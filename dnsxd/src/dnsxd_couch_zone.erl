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
	{ok, _} -> ok;
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
	{ok, #dnsxd_couch_zone{} = Zone} -> make_changes(Zone, Changes);
	{error, not_found} when Create ->
	    Mname = <<"ns.", ZoneName/binary>>,
	    Rname = <<"hostmaster.", ZoneName/binary>>,
	    SOAParam = #dnsxd_couch_sp{mname = Mname, rname = Rname,
				       refresh = 3600, retry = 3600,
				       expire = 3600, minimum = 120},
	    NSEC3 = #dnsxd_couch_nsec3param{salt = <<>>, iter = 0, alg = 7},
	    Zone = #dnsxd_couch_zone{name = ZoneName, soa_param = SOAParam,
				     dnssec_nsec3_param = NSEC3},
	    case make_changes(Zone, Changes) of
		#dnsxd_couch_zone{} = NewZone -> ?MODULE:put(DbRef, NewZone);
		{error, _} = Result -> Result
	    end;
	{error, _Reason} = Error -> Error
    end.

make_changes(#dnsxd_couch_zone{} = Zone, []) -> Zone;
make_changes(#dnsxd_couch_zone{tsig_keys = Keys} = Zone,
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
	    make_changes(NewZone, Changes)
    end;
make_changes(#dnsxd_couch_zone{tsig_keys = Keys,
			       tombstone_period = TombstonePeriod} = Zone,
	     [{delete_tsig_key, Name}|Changes]) ->
    {Active, Expired} = lists:partition(fun is_active/1, Keys),
    case lists:keytake(Name, #dnsxd_couch_tk.name, Active) of
	{value, #dnsxd_couch_tk{} = Key, NewActive} ->
	    Tombstone = TombstonePeriod + dns:unix_time(),
	    NewKey = Key#dnsxd_couch_tk{tombstone = Tombstone},
	    NewKeys = Expired ++ [NewKey|NewActive],
	    NewZone = Zone#dnsxd_couch_zone{tsig_keys = NewKeys},
	    make_changes(NewZone, Changes);
	false ->
	    {display_error, {"No TSIG named ~s", [Name]}}
    end;
make_changes(#dnsxd_couch_zone{tsig_keys = Keys} = Zone,
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
		    NewKey2 = NewKey#dnsxd_couch_tk{set = dns:unix_time()},
		    NewKeys = Expired ++ [NewKey2|NewActive],
		    NewZone = Zone#dnsxd_couch_zone{tsig_keys = NewKeys},
		    make_changes(NewZone, Changes)
	    end;
	false -> {display_error, {"No TSIG named ~s", [Name]}}
    end;
make_changes(#dnsxd_couch_zone{} = Zone, [{dnssec_enabled, Bool}|Changes])
  when is_boolean(Bool) ->
    NewZone = Zone#dnsxd_couch_zone{dnssec_enabled = Bool,
				    dnssec_enabled_set = dns:unix_time()},
    make_changes(NewZone, Changes);
make_changes(#dnsxd_couch_zone{dnssec_keys = Keys} = Zone,
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
	    make_changes(NewZone, Changes)
    end;
make_changes(#dnsxd_couch_zone{dnssec_keys = Keys,
				tombstone_period = TombstonePeriod} = Zone,
       [{delete_dnssec_key, Id}|Changes]) ->
    case lists:keytake(Id, #dnsxd_couch_dk.id, Keys) of
	{value, #dnsxd_couch_dk{} = Key, Keys0} ->
	    Tombstone = TombstonePeriod + dns:unix_time(),
	    NewKey = Key#dnsxd_couch_dk{tombstone = Tombstone},
	    NewKeys = [NewKey|Keys0],
	    NewZone = Zone#dnsxd_couch_zone{dnssec_keys = NewKeys},
	    make_changes(NewZone, Changes);
	false ->
	    {display_error, {"No DNSSEC key with ID ~s~n", [Id]}}
    end;
make_changes(#dnsxd_couch_zone{
	 dnssec_nsec3_param = #dnsxd_couch_nsec3param{} = NSEC3Param} = Zone,
       [{nsec3salt, Salt}|Changes]) when is_binary(Salt) ->
    NewNSEC3Param = NSEC3Param#dnsxd_couch_nsec3param{salt = Salt},
    NewZone = Zone#dnsxd_couch_zone{dnssec_nsec3_param = NewNSEC3Param,
				    dnssec_nsec3_param_set = dns:unix_time()},
    make_changes(NewZone, Changes);
make_changes(#dnsxd_couch_zone{
	 dnssec_nsec3_param = #dnsxd_couch_nsec3param{} = NSEC3Param} = Zone,
       [{nsec3iter, Iter}|Changes]) when is_integer(Iter) ->
    NewNSEC3Param = NSEC3Param#dnsxd_couch_nsec3param{iter = Iter},
    NewZone = Zone#dnsxd_couch_zone{dnssec_nsec3_param = NewNSEC3Param,
				    dnssec_nsec3_param_set = dns:unix_time()},
    make_changes(NewZone, Changes);
make_changes(#dnsxd_couch_zone{} = Zone, [{dnssec_siglife, SigLife}|Changes])
  when is_integer(SigLife) ->
    NewZone = Zone#dnsxd_couch_zone{dnssec_siglife = SigLife,
				    dnssec_siglife_set = dns:unix_time()},
    make_changes(NewZone, Changes);
make_changes(#dnsxd_couch_zone{soa_param = SOAP} = Zone,
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
    make_changes(NewZone, Changes);
make_changes(#dnsxd_couch_zone{} = Zone, [{zone_enabled, Bool}|Changes])
  when is_boolean(Bool) ->
    NewZone = Zone#dnsxd_couch_zone{enabled = Bool},
    make_changes(NewZone, Changes);
make_changes(#dnsxd_couch_zone{} = Zone, [create_zone|Changes]) ->
    make_changes(Zone, Changes);
make_changes(_Zone, [Change|_]) -> {error, {unknown_change, Change}}.

-ifdef(TEST).

make_changes_wrapper(A, B) ->
    case make_changes(A, B) of
	{display_error, _} -> display_error;
	X -> X
    end.

make_changes_tsig_1_test_() ->
    Now = dns:unix_time(),
    Id = dnsxd_lib:new_id(),
    Name = <<$a>>,
    Secret = <<$b>>,
    Enabled = false,
    DNSSDOnly = false,
    DTK = #dnsxd_tsig_key{id = Id, name = Name, secret = Secret,
			  enabled = Enabled, dnssd_only = DNSSDOnly},
    CTK = #dnsxd_couch_tk{id = Id, name = Name, secret = base64:encode(Secret),
			  enabled = Enabled, dnssd_only = DNSSDOnly},
    Tombstone = (#dnsxd_couch_zone{})#dnsxd_couch_zone.tombstone_period + Now,
    Cases = [{#dnsxd_couch_zone{tsig_keys = [CTK]},
	      #dnsxd_couch_zone{},
	      [{add_tsig_key, DTK}]},
	     {display_error,
	      #dnsxd_couch_zone{tsig_keys = [CTK]},
	      [{add_tsig_key, DTK}]},
	     {display_error,
	      #dnsxd_couch_zone{tsig_keys = [CTK#dnsxd_couch_tk{id = <<$b>>}]},
	      [{add_tsig_key, DTK}]},
	     {#dnsxd_couch_zone{tsig_keys = [CTK#dnsxd_couch_tk{
					       tombstone = Tombstone}]},
	      #dnsxd_couch_zone{tsig_keys = [CTK]},
	      [{delete_tsig_key, <<$a>>}]},
	     {display_error, #dnsxd_couch_zone{}, [{delete_tsig_key, <<$a>>}]}
	    ],
    [ ?_assertEqual(ZoneOut, make_changes_wrapper(ZoneIn, Changes))
      || {ZoneOut, ZoneIn, Changes} <- Cases ].

make_changes_tsig_2_test_() ->
    Now = dns:unix_time(),
    Name = <<$a>>,
    TKA = #dnsxd_couch_tk{name = Name, secret = <<$b>>, enabled = true,
			  dnssd_only = true},
    TKB = TKA#dnsxd_couch_tk{set = Now},
    Zone = #dnsxd_couch_zone{tsig_keys = [TKA]},
    Cases = [{{tsig_key_secret, {Name, <<$c>>}},
	      TKB#dnsxd_couch_tk{secret = base64:encode(<<$c>>)}},
	     {{tsig_key_enabled, {Name, false}},
	      TKB#dnsxd_couch_tk{enabled = false}},
	     {{tsig_key_dnssdonly, {Name, false}},
	      TKB#dnsxd_couch_tk{dnssd_only = false}}],
    [ ?_assertEqual(Zone#dnsxd_couch_zone{tsig_keys = [NewTK]},
		    make_changes(Zone, [Change])) || {Change, NewTK} <- Cases ].

make_changes_tsig_3_test_() ->
    Action = tsig_key_secret,
    Name = <<$a>>,
    Value = 333,
    Zone = #dnsxd_couch_zone{tsig_keys = [#dnsxd_couch_tk{name = Name}]},
    Cases = [{{error, {bad_value, Action, Value}}, [{Action, {Name, Value}}]},
	     {display_error, [{Action, {<<$b>>, Value}}]}],
    [ ?_assertEqual(Result, make_changes_wrapper(Zone, Changes))
      || {Result, Changes} <- Cases ].

make_changes_dnssec_enabled_test_() ->
    ZoneA = #dnsxd_couch_zone{dnssec_enabled = false},
    ZoneB = #dnsxd_couch_zone{dnssec_enabled = true},
    Cases = [{ZoneB, ZoneA, true}, {ZoneA, ZoneB, false}],
    [ ?_assertEqual(Result, make_changes(Zone, [{dnssec_enabled, Bool}]))
      || {Result, Zone, Bool} <- Cases ].

make_changes_add_dnssec_key_test_() ->
    Id = dnsxd_lib:new_id(),
    Now = dns:unix_time(),
    DKRSA = #dnsxd_couch_dk_rsa{_ = base64:encode(<<42>>)},
    DDKKey = lists:duplicate(3, <<1:32, 42>>),
    KSK = false,
    CDK = #dnsxd_couch_dk{id = Id, ksk = KSK, data = DKRSA,
			  incept = Now, expire = Now, alg = 7},
    DDK = #dnsxd_dnssec_key{id = Id, ksk = KSK, key = DDKKey, incept = Now,
			    expire = Now, alg = 7},
    ZoneA = #dnsxd_couch_zone{dnssec_keys = [CDK]},
    ZoneB = ZoneA#dnsxd_couch_zone{dnssec_keys = []},
    Cases = [{display_error, ZoneA, {add_dnssec_key, DDK}},
	     {ZoneA, ZoneB, {add_dnssec_key, DDK}}],
    [ ?_assertEqual(Result, make_changes_wrapper(Zone, [Change]))
      || {Result, Zone, Change} <- Cases ].

make_changes_delete_dnssec_key_test_() ->
    ZoneA = #dnsxd_couch_zone{},
    TombstonePeriod = ZoneA#dnsxd_couch_zone.tombstone_period,
    DKA = #dnsxd_couch_dk{id = <<$a>>},
    DKB = DKA#dnsxd_couch_dk{tombstone = dns:unix_time() + TombstonePeriod},
    ZoneB = ZoneA#dnsxd_couch_zone{dnssec_keys = [DKA]},
    ZoneC = ZoneA#dnsxd_couch_zone{dnssec_keys = [DKB]},
    Cases = [{ZoneC, ZoneB}, {display_error, ZoneA}],
    Changes = [{delete_dnssec_key, <<$a>>}],
    [ ?_assertEqual(Result, make_changes_wrapper(Input, Changes))
      || {Result, Input} <- Cases ].

make_changes_nsec3_test_() ->
    Now = dns:unix_time(),
    NPA = #dnsxd_couch_nsec3param{salt = <<$s>>, iter = 1},
    NPB = NPA#dnsxd_couch_nsec3param{salt = <<$n>>},
    NPC = NPA#dnsxd_couch_nsec3param{iter = 2},
    Zone = #dnsxd_couch_zone{dnssec_nsec3_param  = NPA},
    Cases = [{{nsec3salt, <<$n>>}, NPB}, {{nsec3iter, 2}, NPC}],
    [ ?_assertEqual(Zone#dnsxd_couch_zone{dnssec_nsec3_param = NP,
					  dnssec_nsec3_param_set = Now},
		    make_changes(Zone, [Change]))
      || {Change, NP} <- Cases ].

make_changes_siglife_test() ->
    ?assertEqual(#dnsxd_couch_zone{dnssec_siglife = 42},
		 make_changes(#dnsxd_couch_zone{}, [{dnssec_siglife, 42}])).

make_changes_soa_test_() ->
    SOAP = #dnsxd_couch_sp{set = dns:unix_time(), mname = <<$a>>,
			   rname = <<$a>>, _ = 7},
    Zone = #dnsxd_couch_zone{soa_param = SOAP},
    MName = <<$m>>,
    MNameChange = {mname, MName},
    MNameSOAP = SOAP#dnsxd_couch_sp{mname = MName},
    RName = <<$r>>,
    RNameChange = {rname, RName},
    RNameSOAP = SOAP#dnsxd_couch_sp{rname = RName},
    N = 42,
    RefreshChange = {refresh, N},
    RefreshSOAP = SOAP#dnsxd_couch_sp{refresh = N},
    RetryChange = {retry, N},
    RetrySOAP = SOAP#dnsxd_couch_sp{retry = N},
    ExpireChange = {expire, N},
    ExpireSOAP = SOAP#dnsxd_couch_sp{expire = N},
    MinimumChange = {minimum, N},
    MinimumSOAP = SOAP#dnsxd_couch_sp{minimum = N},
    Cases = [{MNameSOAP, MNameChange}, {RNameSOAP, RNameChange},
	     {RefreshSOAP, RefreshChange}, {RetrySOAP, RetryChange},
	     {ExpireSOAP, ExpireChange}, {MinimumSOAP, MinimumChange}],
    [ ?_assertEqual(Zone#dnsxd_couch_zone{soa_param = NewSOAP},
		    make_changes(Zone, [Change]))
      || {NewSOAP, Change} <- Cases ].

makes_changes_enabled_test_() ->
    [ ?_assertEqual(#dnsxd_couch_zone{enabled = Bool},
		    make_changes(#dnsxd_couch_zone{}, [{zone_enabled, Bool}]))
	|| Bool <- [ true, false ] ].

make_changes_misc_test_() ->
    Zone = #dnsxd_couch_zone{},
    Cases = [{Zone, create_zone}, {{error, {unknown_change, foo}}, foo}],
    [ ?_assertEqual(Result, make_changes(Zone, [Change]))
      || {Result, Change} <- Cases ].

-endif.

%% is_active = whether term is live as far as dnsxd is concerned
%% is_current = whether term is live as far as dnsxd_couch is concerned
%% the difference? dnsxd_couch keeps dead items around a little while to
%% prevent zombies from showing up
is_active(#dnsxd_couch_tk{tombstone = Tombstone}) -> not is_integer(Tombstone).

-ifdef(TEST).

is_active_test_() ->
    Cases = [{true, #dnsxd_couch_tk{}},
	     {false, #dnsxd_couch_tk{tombstone = 1}}],
    [ ?_assertEqual(Result, is_active(Case)) || {Result, Case} <- Cases ].

-endif.

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

-ifdef(TEST).

check_update_prereqs_test_() ->
    Cases = [{nxdomain, [{exist, <<$a>>}], []},
	     {ok, [{exist, <<$a>>}], [#dnsxd_couch_rr{name = <<$a>>}]},
	     {nxrrset, [{exist, <<$a>>, 1}], [#dnsxd_couch_rr{name = <<$a>>}]},
	     {ok, [{exist, <<$a>>, 1}],
	      [#dnsxd_couch_rr{name = <<$a>>, type = 1}]},
	     {nxrrset, [{exist, <<$a>>, 1, <<$a>>}],
	      [#dnsxd_couch_rr{name = <<$a>>, type = 1}]},
	     {ok, [{exist, <<$a>>, 1, <<$a>>}],
	      [#dnsxd_couch_rr{name = <<$a>>, type = 1, data = <<$a>>}]},
	     {yxdomain, [{not_exist, <<$a>>}],
	      [#dnsxd_couch_rr{name = <<$a>>}]},
	     {ok, [{not_exist, <<$a>>}], []},
	     {yxrrset, [{not_exist, <<$a>>, 1}],
	      [#dnsxd_couch_rr{name = <<$a>>, type = 1}]},
	     {ok, [{not_exist, <<$a>>, 1}], [#dnsxd_couch_rr{name = <<$a>>}]}],
    [ ?_assertEqual(Result, check_update_prereqs(PreReq, RR))
      || {Result, PreReq, RR} <- Cases ].

-endif.

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
		 false -> undefined
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

-ifdef(TEST).

%% all these tests have a race condition - change update_rr to accept a Now

update_rr_delete_1_test() ->
    Key = undefined,
    Update = {delete, <<$a>>},
    RRA = #dnsxd_couch_rr{name = <<$a>>},
    RRB = #dnsxd_couch_rr{name = <<$b>>},
    In = [RRA, RRB],
    Out = [RRA#dnsxd_couch_rr{expire = dns:unix_time() - 1}, RRB],
    ?assertEqual(Out, update_rr(Key, [Update], In)).

update_rr_delete_2_test() ->
    Key = undefined,
    Update = {delete, <<$a>>, 1},
    RRA = #dnsxd_couch_rr{name = <<$a>>, type = 1},
    RRB = #dnsxd_couch_rr{name = <<$b>>, type = 1},
    In = [RRA, RRB],
    Out = [RRA#dnsxd_couch_rr{expire = dns:unix_time() - 1}, RRB],
    ?assertEqual(Out, update_rr(Key, [Update], In)).

update_rr_delete_3_test() ->
    Key = undefined,
    Update = {delete, <<$a>>, 1, <<$a>>},
    RRA = #dnsxd_couch_rr{name = <<$a>>, type = 1, data = <<$a>>},
    RRB = #dnsxd_couch_rr{name = <<$a>>, type = 1, data = <<$b>>},
    In = [RRA, RRB],
    Out = [RRA#dnsxd_couch_rr{expire = dns:unix_time() - 1}, RRB],
    ?assertEqual(Out, update_rr(Key, [Update], In)).

update_rr_add_1_test() ->
    Key = undefined,
    Name = <<$a>>,
    Type = 1,
    TTL = 2,
    Data = <<$a>>,
    LeaseLength = 3,
    Now = dns:unix_time(),
    Update = {add, Name, Type, TTL, Data, LeaseLength},
    Out = [#dnsxd_couch_rr{id = undefined, name = Name, class = ?DNS_CLASS_IN,
			   type = Type, ttl = TTL, data = Data, incept = Now,
			   expire = Now + LeaseLength}],
    Fun = fun() ->
		  [ RR#dnsxd_couch_rr{id = undefined}
		    || RR <- update_rr(Key, [Update], []) ]
	  end,
    ?assertEqual(Out, Fun()).

update_rr_add_2_test() ->
    Key = undefined,
    Name = <<$a>>,
    Type = 1,
    TTL = 2,
    Data = <<$a>>,
    LeaseLength = undefined,
    Now = dns:unix_time(),
    Update = {add, Name, Type, TTL, Data, LeaseLength},
    Out = [#dnsxd_couch_rr{id = undefined, name = Name, class = ?DNS_CLASS_IN,
			   type = Type, ttl = TTL, data = Data, incept = Now,
			   expire = undefined}],
    Fun = fun() ->
		  [ RR#dnsxd_couch_rr{id = undefined}
		    || RR <- update_rr(Key, [Update], []) ]
	  end,
    ?assertEqual(Out, Fun()).

update_rr_add_3_test() ->
    Key = undefined,
    Name = <<$a>>,
    Type = 1,
    TTL = 2,
    Data = <<$a>>,
    LeaseLength = 3,
    Now = dns:unix_time(),
    Update = {add, Name, Type, TTL, Data, LeaseLength},
    RRA = #dnsxd_couch_rr{name = Name, class = ?DNS_CLASS_IN, type = Type,
			  ttl = TTL, data = Data, incept = Now,
			  expire = Now + 3600},
    RRB = RRA#dnsxd_couch_rr{set = Now, expire = Now + LeaseLength},
    Out = [RRB],
    ?assertEqual(Out, update_rr(Key, [Update], [RRA])).

update_rr_add_4_test() ->
    Key = undefined,
    Name = <<$a>>,
    Type = 1,
    TTL = 2,
    Data = <<$a>>,
    LeaseLength = 3,
    Now = dns:unix_time(),
    Update = {add, Name, Type, TTL, Data, LeaseLength},
    RRA1 = #dnsxd_couch_rr{name = Name, class = ?DNS_CLASS_IN, type = Type,
			   ttl = TTL, data = Data, incept = Now,
			   expire = Now + 3600},
    RRA2 = RRA1#dnsxd_couch_rr{set = Now, expire = Now + LeaseLength},
    RRB1 = #dnsxd_couch_rr{name = Name, class = ?DNS_CLASS_IN, type = Type,
			   ttl = TTL, data = Data, incept = Now,
			   expire = Now + 3600},
    RRB2 = RRB1#dnsxd_couch_rr{set = Now, expire = Now - 1},
    In = [RRA1, RRB1],
    Out = [RRB2, RRA2],
    ?assertEqual(Out, update_rr(Key, [Update], In)).

-endif.

reap(Now, TombstonePeriod, Recs) when is_list(Recs) ->
    TombstonedRecs = [add_tombstone(Rec, Now, TombstonePeriod) || Rec <- Recs],
    [Rec || Rec <- TombstonedRecs, is_current(Now, Rec)].

-ifdef(TEST).

reap_test() ->
    Now = 10,
    TombstonePeriod = 5,
    A = #dnsxd_couch_rr{expire = Now},
    B = #dnsxd_couch_rr{expire = Now - 1},
    C = #dnsxd_couch_rr{expire = Now - TombstonePeriod - 1},
    In = [A, B, C],
    Out = [ A, B#dnsxd_couch_rr{tombstone = Now - 1 + TombstonePeriod} ],
    ?assertEqual(Out, reap(Now, TombstonePeriod, In)).

-endif.

add_tombstone(#dnsxd_couch_rr{expire = Expires} = RR, Now, TombstonePeriod)
  when is_integer(Expires) andalso Expires < Now ->
    Tombstone = Expires + TombstonePeriod,
    RR#dnsxd_couch_rr{tombstone = Tombstone};
add_tombstone(Rec, _Now, _TombstonePeriod) -> Rec.

-ifdef(TEST).

add_tombstone_test_() ->
    Now = 10,
    TombstonePeriod = 5,
    Cases = [{#dnsxd_couch_rr{id = <<$a>>, expire = Now},
	      #dnsxd_couch_rr{id = <<$a>>, expire = Now}},
	     {#dnsxd_couch_rr{id = <<$b>>, expire = Now - 1},
	      #dnsxd_couch_rr{id = <<$b>>, expire = Now - 1,
			      tombstone = Now - 1 + TombstonePeriod}}],
    [ ?_assertEqual(Out, add_tombstone(In, Now, TombstonePeriod))
      || {In, Out} <- Cases ].

-endif.

is_current(Now, #dnsxd_couch_rr{tombstone = Tombstone})
  when is_integer(Tombstone) -> is_current(Now, Tombstone);
is_current(Now, #dnsxd_couch_tk{tombstone = Tombstone})
  when is_integer(Tombstone) -> is_current(Now, Tombstone);
is_current(Now, #dnsxd_couch_dk{tombstone = Tombstone})
  when is_integer(Tombstone) -> is_current(Now, Tombstone);
is_current(_Now, Rec) when is_tuple(Rec) -> true;
is_current(Now, Tombstone) when is_integer(Tombstone) -> Now < Tombstone.

-ifdef(TEST).

is_current_test_() ->
    Now = 10,
    Cases = [{#dnsxd_couch_rr{tombstone = 5}, false},
	     {#dnsxd_couch_rr{tombstone = 15}, true},
	     {#dnsxd_couch_tk{tombstone = 5}, false},
	     {#dnsxd_couch_tk{tombstone = 15}, true},
	     {#dnsxd_couch_dk{tombstone = 5}, false},
	     {#dnsxd_couch_dk{tombstone = 15}, true},
	     {#dnsxd_couch_dk{tombstone = undefined}, true}],
    [ ?_assertEqual(Expect, is_current(Now, Input))
      || {Input, Expect} <- Cases ].

-endif.

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

-ifdef(TEST).

decode_doc_1_test() ->
    DeletedDoc = {[{<<"_deleted">>, true}]},
    ?assertEqual({error, deleted}, decode_doc(DeletedDoc)).

decode_doc_2_test() ->
    Zone = #dnsxd_couch_zone{},
    ZoneDoc = {encode(Zone)},
    ?assertEqual(Zone, decode_doc(ZoneDoc)).

-endif.

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
		undefined -> {MebePL};
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
	null -> undefined;
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

-ifdef(TEST).

encodecode_test_() ->
    Zone1 = #dnsxd_couch_zone{},
    Zone2 = #dnsxd_couch_zone{rev = <<$a>>},
    Zone3 = #dnsxd_couch_zone{meta = {[]}},
    SOAParam = #dnsxd_couch_sp{mname = <<$m>>, rname = <<$r>>, _ = $r},
    Zone4 = #dnsxd_couch_zone{soa_param = SOAParam},
    RR = [#dnsxd_couch_rr{id = <<$a>>, incept = $a, name = <<$a>>, class = $a,
			  type = 97, ttl = $a, data = <<$a>>},
	  #dnsxd_couch_rr{id = <<$b>>, incept = $b, name = <<$b>>,
			  class = ?DNS_CLASS_IN, type = ?DNS_TYPE_A, ttl = $b,
			  data = #dns_rrdata_a{ip = <<"127.0.0.1">>}}],
    Zone5 = #dnsxd_couch_zone{rr = RR},
    TK = #dnsxd_couch_tk{name = <<$t>>, secret = <<$s>>},
    Zone6 = #dnsxd_couch_zone{tsig_keys = [TK]},
    Data = #dnsxd_couch_dk_rsa{e = <<$e>>, n = <<$n>>, d = <<$d>>},
    DK = #dnsxd_couch_dk{id = <<$a>>, alg = ?DNS_ALG_NSEC3RSASHA1, data = Data},
    Zone7 = #dnsxd_couch_zone{dnssec_keys = [DK]},
    NSEC3Param = #dnsxd_couch_nsec3param{salt = <<$s>>, iter = $s, alg = $s},
    Zone8 = #dnsxd_couch_zone{dnssec_nsec3_param = NSEC3Param},
    Zones = [Zone1, Zone2, Zone3, Zone4, Zone5, Zone6, Zone7, Zone8],
    [ ?_assertEqual(Zone, decode(encode(Zone))) || Zone <- Zones ].

-endif.

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

-ifdef(TEST).

merge_test() ->
    Zone = #dnsxd_couch_zone{},
    ?assertEqual(Zone, merge(Zone, Zone)).

-endif.

%% simple merges - just go for whichever was set later
merge_enabled(#dnsxd_couch_zone{enabled_set = TW} = Winner,
	      #dnsxd_couch_zone{enabled = Enabled, enabled_set = TL})
  when TL > TW -> Winner#dnsxd_couch_zone{enabled = Enabled, enabled_set = TL};
merge_enabled(#dnsxd_couch_zone{} = Winner, #dnsxd_couch_zone{}) -> Winner.

-ifdef(TEST).

merge_enabled1_test() ->
    A = #dnsxd_couch_zone{rev = a, enabled_set = 1, enabled = 1},
    B = #dnsxd_couch_zone{rev = b, enabled_set = 2, enabled = 2},
    O = #dnsxd_couch_zone{rev = a, enabled_set = 2, enabled = 2},
    ?assertEqual(O, merge_enabled(A, B)).

merge_enabled2_test() ->
    A = #dnsxd_couch_zone{rev = a, axfr_enabled_set = 2, axfr_enabled = 2},
    B = #dnsxd_couch_zone{rev = b, axfr_enabled_set = 2, axfr_enabled = 2},
    O = A,
    ?assertEqual(O, merge_enabled(A, B)).

-endif.

merge_axfr_enabled(#dnsxd_couch_zone{axfr_enabled_set = TW} = Winner,
		   #dnsxd_couch_zone{axfr_enabled = Enabled,
				     axfr_enabled_set = TL}) when TL > TW ->
    Winner#dnsxd_couch_zone{axfr_enabled = Enabled, axfr_enabled_set = TL};
merge_axfr_enabled(#dnsxd_couch_zone{} = Winner, #dnsxd_couch_zone{}) -> Winner.

-ifdef(TEST).

merge_axfr_enabled_1_test() ->
    A = #dnsxd_couch_zone{rev = a, axfr_enabled_set = 1, axfr_enabled = 1},
    B = #dnsxd_couch_zone{rev = b, axfr_enabled_set = 2, axfr_enabled = 2},
    O = #dnsxd_couch_zone{rev = a, axfr_enabled_set = 2, axfr_enabled = 2},
    ?assertEqual(O, merge_axfr_enabled(A, B)).

merge_axfr_enabled_2_test() ->
    A = #dnsxd_couch_zone{rev = a, axfr_enabled_set = 2, axfr_enabled = 2},
    B = #dnsxd_couch_zone{rev = b, axfr_enabled_set = 2, axfr_enabled = 2},
    O = A,
    ?assertEqual(O, merge_axfr_enabled(A, B)).

-endif.

merge_soa_param(#dnsxd_couch_zone{soa_param_set = TW} = Winner,
		#dnsxd_couch_zone{soa_param = SOAParam, soa_param_set = TL})
  when TL > TW ->
    Winner#dnsxd_couch_zone{soa_param = SOAParam, soa_param_set = TL};
merge_soa_param(#dnsxd_couch_zone{} = Winner, #dnsxd_couch_zone{}) -> Winner.

-ifdef(TEST).

merge_soa_param_1_test() ->
    A = #dnsxd_couch_zone{rev = a, soa_param_set = 1, soa_param = 1},
    B = #dnsxd_couch_zone{rev = b, soa_param_set = 2, soa_param = 2},
    O = #dnsxd_couch_zone{rev = a, soa_param_set = 2, soa_param = 2},
    ?assertEqual(O, merge_soa_param(A, B)).

merge_soa_param_2_test() ->
    A = #dnsxd_couch_zone{rev = a, soa_param_set = 2, soa_param = 2},
    B = #dnsxd_couch_zone{rev = b, soa_param_set = 2, soa_param = 2},
    O = A,
    ?assertEqual(O, merge_soa_param(A, B)).

-endif.

merge_dnssec_enabled(#dnsxd_couch_zone{dnssec_enabled_set = TW} = Winner,
		     #dnsxd_couch_zone{dnssec_enabled = DNSSEC,
				       dnssec_enabled_set = TL}) when TL > TW ->
    Winner#dnsxd_couch_zone{dnssec_enabled = DNSSEC, dnssec_enabled_set = TL};
merge_dnssec_enabled(#dnsxd_couch_zone{} = Winner, #dnsxd_couch_zone{}) ->
    Winner.

-ifdef(TEST).

merge_dnssec_enabled_1_test() ->
    A = #dnsxd_couch_zone{rev = a, dnssec_enabled_set = 1, dnssec_enabled = 1},
    B = #dnsxd_couch_zone{rev = b, dnssec_enabled_set = 2, dnssec_enabled = 2},
    O = #dnsxd_couch_zone{rev = a, dnssec_enabled_set = 2, dnssec_enabled = 2},
    ?assertEqual(O, merge_dnssec_enabled(A, B)).

merge_dnssec_enabled_2_test() ->
    A = #dnsxd_couch_zone{rev = a, dnssec_enabled_set = 3, dnssec_enabled = 3},
    B = #dnsxd_couch_zone{rev = b, dnssec_enabled_set = 2, dnssec_enabled = 2},
    O = A,
    ?assertEqual(O, merge_dnssec_enabled(A, B)).

-endif.

merge_dnssec_nsec3param(#dnsxd_couch_zone{dnssec_nsec3_param_set = TW} = Winner,
			#dnsxd_couch_zone{dnssec_nsec3_param = DNSSEC,
					  dnssec_nsec3_param_set = TL})
  when TL > TW ->
    Winner#dnsxd_couch_zone{dnssec_nsec3_param = DNSSEC,
			    dnssec_nsec3_param_set = TL};
merge_dnssec_nsec3param(#dnsxd_couch_zone{} = Winner, #dnsxd_couch_zone{}) ->
    Winner.

-ifdef(TEST).

merge_dnssec_nsec3param_1_test() ->
    A = #dnsxd_couch_zone{rev = a,
			  dnssec_nsec3_param_set = 1,
			  dnssec_nsec3_param = 1},
    B = #dnsxd_couch_zone{rev = b,
			  dnssec_nsec3_param_set = 2,
			  dnssec_nsec3_param = 2},
    O = #dnsxd_couch_zone{rev = a,
			  dnssec_nsec3_param_set = 2,
			  dnssec_nsec3_param = 2},
    ?assertEqual(O, merge_dnssec_nsec3param(A, B)).

merge_dnssec_nsec3param_2_test() ->
    A = #dnsxd_couch_zone{rev = a,
			  dnssec_nsec3_param_set = 3,
			  dnssec_nsec3_param = 3},
    B = #dnsxd_couch_zone{rev = b,
			  dnssec_nsec3_param_set = 2,
			  dnssec_nsec3_param = 2},
    O = A,
    ?assertEqual(O, merge_dnssec_nsec3param(A, B)).

-endif.

merge_dnssec_siglife(#dnsxd_couch_zone{dnssec_siglife_set = TW} = Winner,
		     #dnsxd_couch_zone{dnssec_siglife = SigLife,
				       dnssec_siglife_set = TL}) when TL > TW ->
    Winner#dnsxd_couch_zone{dnssec_siglife = SigLife, dnssec_siglife_set = TL};
merge_dnssec_siglife(#dnsxd_couch_zone{} = Winner, #dnsxd_couch_zone{}) ->
    Winner.

-ifdef(TEST).

merge_dnssec_siglife_1_test() ->
    A = #dnsxd_couch_zone{rev = a, dnssec_siglife_set = 1, dnssec_siglife = 1},
    B = #dnsxd_couch_zone{rev = b, dnssec_siglife_set = 2, dnssec_siglife = 2},
    O = #dnsxd_couch_zone{rev = a, dnssec_siglife_set = 2, dnssec_siglife = 2},
    ?assertEqual(O, merge_dnssec_siglife(A, B)).

merge_dnssec_siglife_2_test() ->
    A = #dnsxd_couch_zone{rev = a, dnssec_siglife_set = 3, dnssec_siglife = 3},
    B = #dnsxd_couch_zone{rev = b, dnssec_siglife_set = 2, dnssec_siglife = 2},
    O = A,
    ?assertEqual(O, merge_dnssec_siglife(A, B)).

-endif.

%% messier merges

%% rr
merge_rr(#dnsxd_couch_zone{rr = WRRs} = Winner, #dnsxd_couch_zone{rr = LRRs}) ->
    %% todo: check for invalid rrsets (multiple cname at same dname, etc)
    CombinedRRs = lists:usort(WRRs ++ LRRs),
    NewRRs = dedupe_tuples(#dnsxd_couch_rr.id,
			   #dnsxd_couch_rr.set,
			   CombinedRRs),
    Winner#dnsxd_couch_zone{rr = NewRRs}.

-ifdef(TEST).

merge_rr_test() ->
    RRA = [#dnsxd_couch_rr{id = 1, set = 1, _ = 1},
	   #dnsxd_couch_rr{id = 2, set = 2, _ = 2},
	   #dnsxd_couch_rr{id = 3, set = 3, _ = 3}],
    RRB = [#dnsxd_couch_rr{id = 1, set = 1, _ = 1},
	   #dnsxd_couch_rr{id = 2, set = 3, _ = 3},
	   #dnsxd_couch_rr{id = 5, set = 5, _ = 5}],
    OutRR = [#dnsxd_couch_rr{id = 1, set = 1, _ = 1},
	     #dnsxd_couch_rr{id = 2, set = 3, _ = 3},
	     #dnsxd_couch_rr{id = 3, set = 3, _ = 3},
	     #dnsxd_couch_rr{id = 5, set = 5, _ = 5}],
    InA = #dnsxd_couch_zone{rr = RRA},
    InB = #dnsxd_couch_zone{rr = RRB},
    Out = #dnsxd_couch_zone{rr = OutRR},
    ?assertEqual(Out, merge_rr(InA, InB)).

-endif.

%% keeping the common hosts is probably preferable
merge_axfr_hosts(#dnsxd_couch_zone{axfr_hosts = HW} = Winner,
		 #dnsxd_couch_zone{axfr_hosts = HL}) ->
    Hosts = sets:to_list(sets:intersection(sets:from_list(HW),
					   sets:from_list(HL))),
    Winner#dnsxd_couch_zone{axfr_hosts = Hosts}.

-ifdef(TEST).

merge_axfr_hosts_test() ->
    InA = #dnsxd_couch_zone{axfr_hosts = [<<"127.0.0.1">>, <<"127.0.0.2">>]},
    InB = #dnsxd_couch_zone{axfr_hosts = [<<"127.0.0.2">>, <<"127.0.0.3">>]},
    Out = #dnsxd_couch_zone{axfr_hosts = [<<"127.0.0.2">>]},
    ?assertEqual(Out, merge_axfr_hosts(InA, InB)).

-endif.


%% tsig_keys
merge_tsig_keys(#dnsxd_couch_zone{tsig_keys = WKeys} = Winner,
		#dnsxd_couch_zone{tsig_keys = LKeys}) ->
    CombinedKeys = lists:usort(WKeys ++ LKeys),
    NewKeys = dedupe_tuples(#dnsxd_couch_tk.id,
			    #dnsxd_couch_tk.set,
			    CombinedKeys),
    Winner#dnsxd_couch_zone{tsig_keys = NewKeys}.

-ifdef(TEST).

merge_tsig_keys_test() ->
    TKA = #dnsxd_couch_tk{id = a, set = 2, _ = 2},
    TKB = #dnsxd_couch_tk{id = a, set = 3, _ = 3},
    InA = #dnsxd_couch_zone{tsig_keys = [TKA]},
    InB = #dnsxd_couch_zone{tsig_keys = [TKB]},
    Out = #dnsxd_couch_zone{tsig_keys = [TKB]},
    ?assertEqual(Out, merge_tsig_keys(InA, InB)).

-endif.

%% dnssec_keys
merge_dnssec_keys(#dnsxd_couch_zone{dnssec_keys = WKeys} = Winner,
		  #dnsxd_couch_zone{dnssec_keys = LKeys}) ->
    CombinedKeys = lists:usort(WKeys ++ LKeys),
    NewKeys = dedupe_tuples(#dnsxd_couch_dk.id,
			    #dnsxd_couch_dk.set,
			    CombinedKeys),
    Winner#dnsxd_couch_zone{dnssec_keys = NewKeys}.

-ifdef(TEST).

merge_dnssec_keys_test() ->
    DKA = #dnsxd_couch_dk{id = a, set = 2, _ = 2},
    DKB = #dnsxd_couch_dk{id = a, set = 3, _ = 3},
    InA = #dnsxd_couch_zone{dnssec_keys = [DKA]},
    InB = #dnsxd_couch_zone{dnssec_keys = [DKB]},
    Out = #dnsxd_couch_zone{dnssec_keys = [DKB]},
    ?assertEqual(Out, merge_dnssec_keys(InA, InB)).

-endif.

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

-ifdef(TEST).

dedupe_tuples_test() ->
    In = [ {a, 2, 2}, {a, 1, 1}, {a, 3, 3} ],
    Out = [ {a, 3, 3}] ,
    ?assertEqual(Out, dedupe_tuples(1, 2, In)).

-endif.
