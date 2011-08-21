%% -------------------------------------------------------------------
%%
%% Copyright (c) 2011 Andrew Tunnell-Jones. All Rights Reserved.
%%
%% This file is provided to you under the Apache License,
%% Version 2.0 (the "License"); you may not use this file
%% except in compliance with the License.  You may obtain
%% a copy of the License at
%%
%%   http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing,
%% software distributed under the License is distributed on an
%% "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
%% KIND, either express or implied.  See the License for the
%% specific language governing permissions and limitations
%% under the License.
%%
%% -------------------------------------------------------------------
-module(dnsxd_couch_zone).
-include("dnsxd_couch.hrl").

%% API
-export([get/1, get/2, put/1, put/2, update/5, change/2]).

%%%===================================================================
%%% API
%%%===================================================================

get(ZoneName) ->
    case dnsxd_couch_lib:get_db() of
	{ok, DbRef} -> get(DbRef, ZoneName);
	{error, _Reason} = Error -> Error
    end.

get(DbRef, ZoneName) ->
    case couchbeam:open_doc(DbRef, ZoneName) of
	{ok, Doc} ->
	    case decode_doc(Doc) of
		#dnsxd_couch_zone{} = Zone ->
		    case dnsxd_couch_lib:get_conflicts(Doc) of
			[] -> {ok, Zone};
			Revs -> get(DbRef, ZoneName, Zone, Revs)
		    end;
		{error, _Reason} = Error -> Error
	    end;
	{error, _Reason} = Error -> Error
    end.

get(DbRef, ZoneName, Zone, Revs) -> get(DbRef, ZoneName, Zone, Revs, []).

get(DbRef, _ZoneName, Zone, [], DelDocs) ->
    case ?MODULE:put(DbRef, Zone) of
	ok ->
	    case couchbeam:delete_docs(DbRef, DelDocs) of
		{ok, _} -> {ok, Zone};
		{error, _Reason} = Error -> Error
	    end;
	{error, _Reason} = Error -> Error
    end;
get(DbRef, ZoneName, Zone, [Rev|Revs], DelDocs) ->
    case couchbeam:open_doc(DbRef, ZoneName, [{rev, Rev}]) of
	{ok, Doc} ->
	    case decode_doc(Doc) of
		#dnsxd_couch_zone{} = CZone ->
		    NewZone = merge(Zone, CZone),
		    NewDelDocs = [Doc|DelDocs],
		    get(DbRef, ZoneName, NewZone, Revs, NewDelDocs);
		_Other ->
		    NewDelDocs = [Doc|DelDocs],
		    get(DbRef, ZoneName, Zone, Revs, NewDelDocs)
	    end;
	{error, _Reason} = Error -> Error
    end.

put(#dnsxd_couch_zone{} = Zone) ->
    case dnsxd_couch_lib:get_db() of
	{ok, DbRef} -> ?MODULE:put(DbRef, Zone);
	{error, _Reason} = Error -> Error
    end.

put(DbRef, #dnsxd_couch_zone{} = Zone) ->
    Doc = encode(Zone),
    case couchbeam:save_doc(DbRef, Doc) of
	{ok, _} ->
	    ?DNSXD_COUCH_SERVER ! write,
	    ok;
	{error, _Reason} = Error -> Error
    end.

update(_MsgCtx, Key, ZoneName, PreReqs, Updates) ->
    case ?MODULE:get(ZoneName) of
	{ok, #dnsxd_couch_zone{enabled = true} = Zone} ->
	    update(Zone, Key, PreReqs, Updates);
	{ok, #dnsxd_couch_zone{enabled = false}} ->
	    {error, disabled};
	{error, _Reason} = Error -> Error
    end.

update(#dnsxd_couch_zone{rr = RRs, tombstone_period = TombstonePeriod} = Zone,
       Key, PreReqs, Updates) ->
    Now = dns:unix_time(),
    {MutableRRs, ImmutableRRs} = lists:partition(
				   fun(#dnsxd_couch_rr{tombstone = Int})
					 when is_integer(Int) -> false;
				      (#dnsxd_couch_rr{incept = Incept})
					 when is_integer(Incept) andalso
					      Incept > Now -> false;
				      (#dnsxd_couch_rr{expire = Expire})
					 when is_integer(Expire) andalso
					      Expire < Now -> false;
				      (#dnsxd_couch_rr{}) ->
					   true
				   end, RRs),
    case check_update_prereqs(PreReqs, MutableRRs) of
	ok ->
	    NewMutableRRs = update_rr(Key, Updates, MutableRRs),
	    NewImmutableRRs = reap(Now, TombstonePeriod, ImmutableRRs),
	    NewRRs = lists:sort(NewMutableRRs ++ NewImmutableRRs),
	    NewZone = Zone#dnsxd_couch_zone{rr = NewRRs},
	    case put(NewZone) of
		ok ->
		    {ok, noerror};
		{error, _Reason} = Error ->
		    timer:sleep(50),
		    Error
	    end;
	Rcode when is_atom(Rcode) -> {ok, Rcode}
    end.

change(ZoneName, Changes) ->
    {ok, DbRef} = dnsxd_couch_lib:get_db(),
    Create = proplists:get_bool(create_zone, Changes),
    Delete = proplists:get_bool(delete_zone, Changes),
    case ?MODULE:get(DbRef, ZoneName) of
	{ok, #dnsxd_couch_zone{}} when Create -> {error, exists};
	{ok, #dnsxd_couch_zone{name = Id, rev = Rev}} when Delete ->
	    Doc = {[{<<"_id">>, Id},{<<"_rev">>, Rev}]},
	    case couchbeam:delete_doc(DbRef, Doc) of
		{ok, _} -> ok;
		{error, _Reason} = Error -> Error
	    end;
	{ok, #dnsxd_couch_zone{} = Zone} -> change(DbRef, Zone, Changes);
	{error, not_found} when Create ->
	    Mname = <<"ns.", ZoneName/binary>>,
	    Rname = <<"hostmaster.", ZoneName/binary>>,
	    SOAParam = #dnsxd_couch_sp{mname = Mname, rname = Rname,
				       refresh = 3600, retry = 3600,
				       expire = 3600, minimum = 120},
	    NSEC3 = #dnsxd_couch_nsec3param{salt = <<>>, iter = 0, alg = 7},
	    Zone = #dnsxd_couch_zone{name = ZoneName, soa_param = SOAParam,
				     dnssec_nsec3_param = NSEC3},
	    change(DbRef, Zone, Changes);
	{error, _Reason} = Error -> Error
    end.

change(DbRef, #dnsxd_couch_zone{} = Zone, []) -> ?MODULE:put(DbRef, Zone);
change(DbRef, #dnsxd_couch_zone{tsig_keys = Keys} = Zone,
       [{add_tsig_key, #dnsxd_tsig_key{id = Id,
				       name = Name,
				       secret = Secret,
				       enabled = Enabled,
				       dnssd_only = DNSSDOnly
				      }}|Changes]) ->
    Active = [Key || Key <- Keys, is_active(Key)],
    IdInUse = lists:keymember(Id, #dnsxd_couch_tk.name, Keys),
    NameInUse = lists:keymember(Name, #dnsxd_couch_tk.name, Active),
    if IdInUse -> {display_error, {"TSIG ID ~s conflicts", [Id]}};
       NameInUse -> {display_error, {"TSIG name ~s conflicts", [Name]}};
       true ->
	    NewKey = #dnsxd_couch_tk{id = Id,
				     name = Name,
				     secret = base64:encode(Secret),
				     enabled = Enabled,
				     dnssd_only = DNSSDOnly},
	    NewKeys = [NewKey|Keys],
	    NewZone = Zone#dnsxd_couch_zone{tsig_keys = NewKeys},
	    change(DbRef, NewZone, Changes)
    end;
change(DbRef, #dnsxd_couch_zone{tsig_keys = Keys,
				tombstone_period = TombstonePeriod} = Zone,
       [{delete_tsig_key, Name}|Changes]) ->
    {Active, Expired} = lists:partition(fun is_active/1, Keys),
    case lists:keytake(Name, #dnsxd_couch_tk.name, Active) of
	{value, #dnsxd_couch_tk{} = Key, NewActive} ->
	    Tombstone = TombstonePeriod + dns:unix_time(),
	    NewKey = Key#dnsxd_couch_tk{tombstone = Tombstone},
	    NewKeys = Expired ++ [NewKey|NewActive],
	    NewZone = Zone#dnsxd_couch_zone{tsig_keys = NewKeys},
	    change(DbRef, NewZone, Changes);
	false ->
	    {display_error, {"No TSIG named ~s", [Name]}}
    end;
change(DbRef, #dnsxd_couch_zone{tsig_keys = Keys} = Zone,
       [{Action, {Name, Value}}|Changes])
  when Action =:= tsig_key_secret orelse
       Action =:= tsig_key_enabled orelse
       Action =:= tsig_key_dnssdonly ->
    {Active, Expired} = lists:partition(fun is_active/1, Keys),
    case lists:keytake(Name, #dnsxd_couch_tk.name, Active) of
	{value, #dnsxd_couch_tk{} = Key, NewActive} ->
	    NewKey = case Action of
			 tsig_key_secret when is_binary(Value) ->
			     Key#dnsxd_couch_tk{secret = base64:encode(Value)};
			 tsig_key_enabled when is_boolean(Value) ->
			     Key#dnsxd_couch_tk{enabled = Value};
			 tsig_key_dnssdonly when is_boolean(Value) ->
			     Key#dnsxd_couch_tk{dnssd_only = Value};
			 _ -> undefined
		     end,
	    case NewKey =:= undefined of
		true -> {error, {bad_value, Action, Value}};
		false ->
		    NewKeys = Expired ++ [NewKey|NewActive],
		    NewZone = Zone#dnsxd_couch_zone{tsig_keys = NewKeys},
		    change(DbRef, NewZone, Changes)
	    end;
	false -> {display_error, {"No TSIG named ~s", [Name]}}
    end;
change(DbRef, #dnsxd_couch_zone{} = Zone, [{dnssec_enabled, Bool}|Changes])
  when is_boolean(Bool) ->
    NewZone = Zone#dnsxd_couch_zone{dnssec_enabled = Bool,
				    dnssec_enabled_set = dns:unix_time()},
    change(DbRef, NewZone, Changes);
change(DbRef, #dnsxd_couch_zone{dnssec_keys = Keys,
				tombstone_period = TombstonePeriod} = Zone,
       [{delete_dnssec_key, Id}|Changes]) ->
    case lists:keytake(Id, #dnsxd_couch_dk.id, Keys) of
	{value, #dnsxd_couch_dk{} = Key, Keys0} ->
	    Tombstone = TombstonePeriod + dns:unix_time(),
	    NewKey = Key#dnsxd_couch_dk{tombstone = Tombstone},
	    NewKeys = [NewKey|Keys0],
	    NewZone = Zone#dnsxd_couch_zone{dnssec_keys = NewKeys},
	    change(DbRef, NewZone, Changes);
	false ->
	    {display_error, {"No DNSSEC key with ID ~s~n", [Id]}}
    end;
change(DbRef, #dnsxd_couch_zone{
	 dnssec_nsec3_param = #dnsxd_couch_nsec3param{} = NSEC3Param} = Zone,
       [{nsec3salt, Salt}|Changes]) when is_binary(Salt) ->
    NewNSEC3Param = NSEC3Param#dnsxd_couch_nsec3param{salt = Salt},
    NewZone = Zone#dnsxd_couch_zone{dnssec_nsec3_param = NewNSEC3Param,
				    dnssec_nsec3_param_set = dns:unix_time()},
    change(DbRef, NewZone, Changes);
change(DbRef, #dnsxd_couch_zone{
	 dnssec_nsec3_param = #dnsxd_couch_nsec3param{} = NSEC3Param} = Zone,
       [{nsec3salt, Iter}|Changes]) when is_integer(Iter) ->
    NewNSEC3Param = NSEC3Param#dnsxd_couch_nsec3param{iter = Iter},
    NewZone = Zone#dnsxd_couch_zone{dnssec_nsec3_param = NewNSEC3Param,
				    dnssec_nsec3_param_set = dns:unix_time()},
    change(DbRef, NewZone, Changes);
change(DbRef, #dnsxd_couch_zone{} = Zone, [{dnssec_siglife, SigLife}|Changes])
  when is_integer(SigLife) ->
    NewZone = Zone#dnsxd_couch_zone{dnssec_siglife = SigLife,
				    dnssec_siglife_set = dns:unix_time()},
    change(DbRef, NewZone, Changes);
change(DbRef, #dnsxd_couch_zone{dnssec_keys = Keys} = Zone,
       [{add_dnssec_key, #dnsxd_dnssec_key{id = Id,
					   incept = Incept,
					   expire = Expire,
					   alg = ?DNS_ALG_NSEC3RSASHA1 = Alg,
					   ksk = KSK,
					   key = [<<_:32, E/binary>>,
						  <<_:32, N/binary>>,
						  <<_:32, D/binary>>]
					  }}|Changes]) ->
    case lists:keymember(Id, #dnsxd_couch_dk.id, Keys) of
	true ->
	    {display_error, {"Key ID ~s conflicts with existing key~n", [Id]}};
	false ->
	    Data = #dnsxd_couch_dk_rsa{e = base64:encode(E),
				       n = base64:encode(N),
				       d = base64:encode(D)},
	    NewKey = #dnsxd_couch_dk{id = Id,
				     incept = Incept,
				     expire = Expire,
				     alg = Alg,
				     ksk = KSK,
				     data = Data},
	    NewKeys = [NewKey|Keys],
	    NewZone = Zone#dnsxd_couch_zone{dnssec_keys = NewKeys},
	    change(DbRef, NewZone, Changes)
    end;
change(DbRef, #dnsxd_couch_zone{soa_param = SOAP} = Zone,
       [{Field, Value}|Changes])
  when Field =:= mname orelse Field =:= rname orelse Field =:= refresh orelse
       Field =:= retry orelse Field =:= expire orelse Field =:= minimum ->
    NewSOAP = case Field of
		  mname -> SOAP#dnsxd_couch_sp{mname = Value};
		  rname -> SOAP#dnsxd_couch_sp{rname = Value};
		  refresh -> SOAP#dnsxd_couch_sp{refresh = Value};
		  retry -> SOAP#dnsxd_couch_sp{retry = Value};
		  expire -> SOAP#dnsxd_couch_sp{expire = Value};
		  minimum -> SOAP#dnsxd_couch_sp{minimum = Value}
	      end,
    NewZone = Zone#dnsxd_couch_zone{soa_param = NewSOAP,
				    soa_param_set = dns:unix_time()},
    change(DbRef, NewZone, Changes);
change(DbRef, #dnsxd_couch_zone{} = Zone, [{zone_enabled, Bool}|Changes])
  when is_boolean(Bool) ->
    NewZone = Zone#dnsxd_couch_zone{enabled = Bool},
    change(DbRef, NewZone, Changes);
change(DbRef, #dnsxd_couch_zone{} = Zone, [create_zone|Changes]) ->
    change(DbRef, Zone, Changes);
change(_DbRef, _Zone, [Change|_]) -> {error, {unknown_change, Change}}.

%% is_active = whether term is live as far as dnsxd is concerned
%% is_current = whether term is live as far as dnsxd_couch is concerned
%% the difference? dnsxd_couch keeps dead items around a little while to
%% prevent zombies from showing up
is_active(#dnsxd_couch_tk{tombstone = Tombstone}) -> not is_integer(Tombstone).

%%%===================================================================
%%% Internal functions
%%%===================================================================

check_update_prereqs([], _RRs) -> ok;
check_update_prereqs([{exist, NameM}|PreReqs], RRs) ->
    Name = dns:dname_to_lower(NameM),
    Exists = lists:keymember(Name, #dnsxd_couch_rr.name, RRs),
    if Exists -> check_update_prereqs(PreReqs, RRs);
       true -> nxdomain end;
check_update_prereqs([{exist, NameM, Type}|PreReqs], RRs) ->
    Name = dns:dname_to_lower(NameM),
    Exists = lists:any(fun(#dnsxd_couch_rr{name = SN, type = ST}) ->
		       Name =:= SN andalso Type =:= ST end, RRs),
    if Exists -> check_update_prereqs(PreReqs, RRs);
       true -> nxrrset end;
check_update_prereqs([{exist, NameM, Type, Data}|PreReqs], RRs) ->
    Name = dns:dname_to_lower(NameM),
    Exists = lists:any(fun(#dnsxd_couch_rr{name = SN, type = ST, data = SD}) ->
			       (Name =:= SN andalso Type =:= ST andalso
				Data =:= SD) %% parenthesis for emacs' benefit
		       end, RRs),
    if Exists -> check_update_prereqs(PreReqs, RRs);
       true -> nxrrset end;
check_update_prereqs([{not_exist, NameM}|PreReqs], RRs) ->
    Name = dns:dname_to_lower(NameM),
    Exists = lists:keymember(Name, #dnsxd_couch_rr.name, RRs),
    if Exists -> yxdomain;
       true -> check_update_prereqs(PreReqs, RRs) end;
check_update_prereqs([{not_exist, NameM, Type}|PreReqs], RRs) ->
    Name = dns:dname_to_lower(NameM),
    Exists = lists:any(fun(#dnsxd_couch_rr{name = SN, type = ST}) ->
		       Name =:= SN andalso Type =:= ST end, RRs),
    if Exists -> yxrrset;
       true -> check_update_prereqs(PreReqs, RRs) end.

update_rr(_Key, [], RRs) -> RRs;
update_rr(Key, [{delete, Name}|Updates], RRs) ->
    Now = dns:unix_time(),
    {Match, Diff} = lists:partition(
		      fun(#dnsxd_couch_rr{name = SN}) ->
			      dns:dname_to_lower(SN) =:= Name end, RRs),
    NewMatch = [ RR#dnsxd_couch_rr{expire = Now - 1} || RR <- Match ],
    NewRRs = NewMatch ++ Diff,
    update_rr(Key, Updates, NewRRs);
update_rr(Key, [{delete, Name, Type}|Updates], RRs) ->
    Now = dns:unix_time(),
    Fun = fun(#dnsxd_couch_rr{name = SN, type = ST}) ->
		  dns:dname_to_lower(SN) =:= Name andalso ST =:= Type
	  end,
    {Match, Diff} = lists:partition(Fun, RRs),
    NewMatch = [ RR#dnsxd_couch_rr{expire = Now - 1} || RR <- Match ],
    NewRRs = NewMatch ++ Diff,
    update_rr(Key, Updates, NewRRs);
update_rr(Key, [{delete, Name, Type, Data}|Updates], RRs) ->
    Now = dns:unix_time(),
    Fun = fun(#dnsxd_couch_rr{name = SN, type = ST, data = SD}) ->
		  (dns:dname_to_lower(SN) =:= Name andalso
		   ST =:= Type andalso SD =:= Data)
	  end,
    {Match, Diff} = lists:partition(Fun, RRs),
    NewMatch = [ RR#dnsxd_couch_rr{expire = Now - 1} || RR <- Match ],
    NewRRs = NewMatch ++ Diff,
    update_rr(Key, Updates, NewRRs);
update_rr(Key, [{add, Name, Type, TTL, Data, LeaseLength}|Updates], RRs) ->
    Fun = fun(#dnsxd_couch_rr{name = SN, type = ST, data = SD}) ->
		  (dns:dname_to_lower(SN) =:= Name
		   andalso Type =:= ST andalso SD =:= Data)
	  end,
    {Match, Diff} = lists:partition(Fun, RRs),
    Now = dns:unix_time(),
    Expire = case is_integer(LeaseLength) andalso LeaseLength > 0 of
		 true -> Now + LeaseLength;
		 false -> null
	     end,
    case Match of
	[] ->
	    NewRR = #dnsxd_couch_rr{name = Name, class = ?DNS_CLASS_IN,
				    type = Type, ttl = TTL, data = Data,
				    incept = Now, expire = Expire},
	    NewRRs = [NewRR|RRs],
	    update_rr(Key, Updates, NewRRs);
	[#dnsxd_couch_rr{} = RR] ->
	    NewRR = RR#dnsxd_couch_rr{ttl = TTL, set = Now, expire = Expire},
	    NewRRs = [NewRR|Diff],
	    update_rr(Key, Updates, NewRRs);
	[#dnsxd_couch_rr{} = RR|Dupes] ->
	    NewRR = RR#dnsxd_couch_rr{ttl = TTL, set = Now, expire = Expire},
	    NewDupes = [ Dupe#dnsxd_couch_rr{expire = Now - 1}
			 || Dupe <- Dupes ],
	    NewRRs = NewDupes ++ [NewRR|Diff],
	    update_rr(Key, Updates, NewRRs)
    end.

reap(Now, TombstonePeriod, Recs) when is_list(Recs) ->
    TombstonedRecs = [add_tombstone(Rec, Now, TombstonePeriod) || Rec <- Recs],
    [Rec || Rec <- TombstonedRecs, is_current(Now, Rec)].

add_tombstone(#dnsxd_couch_rr{expire = Expires} = RR, Now, TombstonePeriod)
  when is_integer(Expires) andalso Expires < Now ->
    Tombstone = Expires + TombstonePeriod,
    RR#dnsxd_couch_rr{tombstone = Tombstone};
add_tombstone(Rec, _Now, _TombstonePeriod) -> Rec.

is_current(Now, #dnsxd_couch_rr{tombstone = Tombstone})
  when is_integer(Tombstone) -> is_current(Now, Tombstone);
is_current(Now, #dnsxd_couch_tk{tombstone = Tombstone})
  when is_integer(Tombstone) -> is_current(Now, Tombstone);
is_current(Now, #dnsxd_couch_dk{tombstone = Tombstone})
  when is_integer(Tombstone) -> is_current(Now, Tombstone);
is_current(_Now, Rec) when is_tuple(Rec) -> true;
is_current(Now, Tombstone) when is_integer(Tombstone) -> Now < Tombstone.

decode_doc({DocProps}) -> decode_doc(DocProps);
decode_doc(DocProps) ->
    case proplists:get_bool(<<"_deleted">>, DocProps) of
	true -> {error, deleted};
	false ->
	    case get_value(?DNSXD_COUCH_TAG, DocProps) of
		<<"dnsxd_couch_zone">> ->
		    #dnsxd_couch_zone{} = decode(DocProps);
		_ -> {error, not_zone}
	    end
    end.

decode({List}) when is_list(List) -> decode(List);
decode(List) when is_list(List) ->
    case get_value(?DNSXD_COUCH_TAG, List) of
	undefined -> List;
	TagBin ->
	    Tag = binary_to_existing_atom(TagBin, latin1),
	    Values = [ decode(Tag, Field, List) || Field <- fields(Tag) ],
	    list_to_tuple([Tag|Values])
    end.

decode(dnsxd_couch_zone, name, List) -> get_value(<<"_id">>, List);
decode(dnsxd_couch_zone, rev, List) -> get_value(<<"_rev">>, List);
decode(Tag, Field, List) ->
    Default = get_default(Tag, Field),
    case get_value(atom_to_binary(Field, latin1), List, Default) of
	{MebePL} when is_list(MebePL) ->
	    case get_value(?DNSXD_COUCH_TAG, MebePL) of
		undefined -> MebePL;
		_ -> decode(MebePL)
	    end;
	[{MebePL}|_] = MebePLs when is_list(MebePL) ->
	    case get_value(?DNSXD_COUCH_TAG, MebePL) of
		undefined -> List;
		_ -> [ decode(PL) || PL <- MebePLs ]
	    end;
	MebeBase64 when Tag =:= dnsxd_couch_rr andalso
			Field =:= data andalso
			is_binary(MebeBase64) ->
	    try base64:decode(MebeBase64)
	    catch _:_ -> MebeBase64 end;
	Value -> Value
    end.

-define(FIELDS(Atom), fields(Atom) -> record_info(fields, Atom)).
?FIELDS(dnsxd_couch_zone);
?FIELDS(dnsxd_couch_rr);
?FIELDS(dnsxd_couch_sp);
?FIELDS(dnsxd_couch_tk);
?FIELDS(dnsxd_couch_dk);
?FIELDS(dnsxd_couch_dk_rsa);
?FIELDS(dnsxd_couch_nsec3param);
fields(Tag) -> dns_record_info:fields(Tag).

values(Rec) when is_tuple(Rec) -> tl(tuple_to_list(Rec)).

get_default(Tag, Field)
  when Tag =:= dnsxd_couch_zone orelse
       Tag =:= dnsxd_couch_rr orelse
       Tag =:= dnsxd_couch_sp ->
    Fields = fields(Tag),
    [_|Values] = tuple_to_list(defaults(Tag)),
    DefaultPL = lists:zip(Fields, Values),
    get_value(Field, DefaultPL);
get_default(_, _) -> undefined.

-define(DEFAULTS(Atom), defaults(Atom) -> #Atom{}).
?DEFAULTS(dnsxd_couch_zone);
?DEFAULTS(dnsxd_couch_rr);
?DEFAULTS(dnsxd_couch_sp).

encode(Rec) when is_tuple(Rec) ->
    Tag = element(1, Rec),
    Fun = fun(X, Y) -> encode_zipper(Tag, X, Y) end,
    PL = [ KV || KV <- lists:zipwith(Fun, fields(Tag), values(Rec)),
		 KV =/= undefined ],
    {[{?DNSXD_COUCH_TAG, atom_to_binary(Tag, latin1)}|PL]};
encode(undefined) -> null;
encode(null) -> null.

encode_zipper(dnsxd_couch_zone, name, Name) -> {<<"_id">>, Name};
encode_zipper(dnsxd_couch_zone, rev, undefined) -> undefined;
encode_zipper(dnsxd_couch_zone, rev, Rev) -> {<<"_rev">>, Rev};
encode_zipper(dnsxd_couch_zone, rr, RRs) ->
    {<<"rr">>, [ encode(RR) || RR <- RRs ]};
encode_zipper(dnsxd_couch_zone, soa_param, SOAParam) ->
    {<<"soa_param">>, encode(SOAParam)};
encode_zipper(dnsxd_couch_zone, dnssec_nsec3_param, NSEC3Param) ->
    {<<"dnssec_nsec3_param">>, encode(NSEC3Param)};
encode_zipper(dnsxd_couch_zone, tsig_keys, Keys) ->
    {<<"tsig_keys">>, [ encode(Key) || Key <- Keys ]};
encode_zipper(dnsxd_couch_zone, dnssec_keys, Keys) ->
    {<<"dnssec_keys">>, [ encode(Key) || Key <- Keys ]};
encode_zipper(dnsxd_couch_dk, data, Key) -> {<<"data">>, encode(Key)};
encode_zipper(dnsxd_couch_rr, data, Bin) when is_binary(Bin) ->
    {<<"data">>, base64:encode(Bin)};
encode_zipper(dnsxd_couch_rr, data, Data) when is_tuple(Data) ->
    {<<"data">>, encode(Data)};
encode_zipper(_Tag, Key, undefined) -> {atom_to_binary(Key, latin1), null};
encode_zipper(_Tag, Key, Value) -> {atom_to_binary(Key, latin1), Value}.

get_value(Key, List) -> get_value(Key, List, undefined).

get_value(Key, List, Default) ->
    case lists:keyfind(Key, 1, List) of
	{Key, Value} -> Value;
	false -> Default
    end.

merge(#dnsxd_couch_zone{name = ZoneName} = Winner,
      #dnsxd_couch_zone{name = ZoneName} = Loser) ->
    MergeFuns = [ fun merge_enabled/2,
		  fun merge_rr/2,
		  fun merge_axfr_enabled/2,
		  fun merge_axfr_hosts/2,
		  fun merge_tsig_keys/2,
		  fun merge_soa_param/2,
		  fun merge_dnssec_enabled/2,
		  fun merge_dnssec_keys/2,
		  fun merge_dnssec_nsec3param/2,
		  fun merge_dnssec_siglife/2 ],
    merge(Winner, Loser, MergeFuns).

merge(Winner, _Loser, []) -> Winner;
merge(Winner, Loser, [Fun|Funs]) ->
    NewWinner = Fun(Winner, Loser),
    merge(NewWinner, Loser, Funs).

%% simple merges - just go for whichever was set later
merge_enabled(#dnsxd_couch_zone{enabled_set = TW} = Winner,
	      #dnsxd_couch_zone{enabled = Enabled, enabled_set = TL})
  when TL > TW -> Winner#dnsxd_couch_zone{enabled = Enabled};
merge_enabled(#dnsxd_couch_zone{} = Winner, #dnsxd_couch_zone{}) -> Winner.

merge_axfr_enabled(#dnsxd_couch_zone{axfr_enabled_set = TW} = Winner,
		   #dnsxd_couch_zone{axfr_enabled = Enabled,
				     axfr_enabled_set = TL})
  when TL > TW -> Winner#dnsxd_couch_zone{enabled = Enabled};
merge_axfr_enabled(#dnsxd_couch_zone{} = Winner, #dnsxd_couch_zone{}) -> Winner.

merge_soa_param(#dnsxd_couch_zone{soa_param_set = TW} = Winner,
		#dnsxd_couch_zone{soa_param = SOAParam, soa_param_set = TL})
  when TL > TW -> Winner#dnsxd_couch_zone{soa_param = SOAParam};
merge_soa_param(#dnsxd_couch_zone{} = Winner, #dnsxd_couch_zone{}) -> Winner.

merge_dnssec_enabled(#dnsxd_couch_zone{dnssec_enabled_set = TW} = Winner,
		     #dnsxd_couch_zone{dnssec_enabled = DNSSEC,
				       dnssec_enabled_set = TL})
  when TL > TW -> Winner#dnsxd_couch_zone{dnssec_enabled = DNSSEC};
merge_dnssec_enabled(#dnsxd_couch_zone{} = Winner, #dnsxd_couch_zone{}) ->
    Winner.

merge_dnssec_nsec3param(#dnsxd_couch_zone{dnssec_nsec3_param_set = TW} = Winner,
			#dnsxd_couch_zone{dnssec_nsec3_param = DNSSEC,
					  dnssec_nsec3_param_set = TL})
  when TL > TW -> Winner#dnsxd_couch_zone{dnssec_nsec3_param = DNSSEC};
merge_dnssec_nsec3param(#dnsxd_couch_zone{} = Winner, #dnsxd_couch_zone{}) ->
    Winner.

merge_dnssec_siglife(#dnsxd_couch_zone{dnssec_siglife_set = TW} = Winner,
		     #dnsxd_couch_zone{dnssec_siglife = SigLife,
				       dnssec_siglife_set = TL})
  when TL > TW -> Winner#dnsxd_couch_zone{dnssec_siglife = SigLife};
merge_dnssec_siglife(#dnsxd_couch_zone{} = Winner, #dnsxd_couch_zone{}) ->
    Winner.

%% messier merges

%% rr
merge_rr(#dnsxd_couch_zone{rr = WRRs} = Winner, #dnsxd_couch_zone{rr = LRRs}) ->
    %% todo: check for invalid rrsets (multiple cname at same dname, etc)
    CombinedRRs = lists:usort(WRRs ++ LRRs),
    NewRRs = dedupe_tuples(#dnsxd_couch_rr.id,
			   #dnsxd_couch_rr.set,
			   CombinedRRs),
    Winner#dnsxd_couch_zone{rr = NewRRs}.

%% keeping the common hosts is probably preferable
merge_axfr_hosts(#dnsxd_couch_zone{axfr_hosts = HW} = Winner,
		 #dnsxd_couch_zone{axfr_hosts = HL}) ->
    Hosts = sets:to_list(sets:intersection(sets:from_list(HW),
					   sets:from_list(HL))),
    Winner#dnsxd_couch_zone{axfr_hosts = Hosts}.

%% tsig_keys
merge_tsig_keys(#dnsxd_couch_zone{tsig_keys = WKeys} = Winner,
		#dnsxd_couch_zone{tsig_keys = LKeys}) ->
    CombinedKeys = lists:usort(WKeys ++ LKeys),
    NewKeys = dedupe_tuples(#dnsxd_couch_tk.id,
			    #dnsxd_couch_tk.set,
			    CombinedKeys),
    Winner#dnsxd_couch_zone{tsig_keys = NewKeys}.

%% dnssec_keys
merge_dnssec_keys(#dnsxd_couch_zone{dnssec_keys = WKeys} = Winner,
		  #dnsxd_couch_zone{dnssec_keys = LKeys}) ->
    CombinedKeys = lists:usort(WKeys ++ LKeys),
    NewKeys = dedupe_tuples(#dnsxd_couch_dk.id,
			    #dnsxd_couch_dk.set,
			    CombinedKeys),
    Winner#dnsxd_couch_zone{dnssec_keys = NewKeys}.

%% helpers

dedupe_tuples(TagPos, TimePos, Tuples) ->
    DupeTags = find_dupe_tupletag(TagPos, Tuples),
    Fun = fun(Tuple) ->
		  Tag = element(TagPos, Tuple),
		  lists:member(Tag, DupeTags)
	  end,
    {DupeTuples, SingleTuples} = lists:partition(Fun, Tuples),
    DedupedTuples = pick_tuples(TagPos, TimePos, DupeTuples),
    lists:sort(DedupedTuples ++ SingleTuples).

pick_tuples(TagPos, TimePos, DupeTuples) ->
    pick_tuples(TagPos, TimePos, DupeTuples, []).

pick_tuples(_TagPos, _TimePos, [], Deduped) -> Deduped;
pick_tuples(TagPos, TimePos, [Tuple|Tuples], Deduped) ->
    Tag = element(TagPos, Tuple),
    case lists:keytake(Tag, TagPos, Tuples) of
	{value, DupeTuple, Tuples0} ->
	    NewTuple = pick_tuple(TimePos, Tuple, DupeTuple),
	    NewTuples = [NewTuple|Tuples0],
	    pick_tuples(TagPos, TimePos, NewTuples, Deduped);
	false ->
	    NewDeduped = [Tuple|Deduped],
	    pick_tuples(TagPos, TimePos, Tuples, NewDeduped)
    end.

pick_tuple(TimePos, A, B) ->
    if element(TimePos, A) < element(TimePos, B) -> B;
       true -> A end.

find_dupe_tupletag(TagPos, Tuples) ->
    find_dupe_tupletag(TagPos, Tuples, dict:new()).

find_dupe_tupletag(_TagPos, [], Dict) ->
    [ Tag || {Tag, Count} <- dict:to_list(Dict), Count > 1 ];
find_dupe_tupletag(TagPos, [Tuple|Tuples], Dict) ->
    Tag = element(TagPos, Tuple),
    NewDict = dict:update_counter(Tag, 1, Dict),
    find_dupe_tupletag(TagPos, Tuples, NewDict).
