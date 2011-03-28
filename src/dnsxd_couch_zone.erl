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
-export([get/2, get/3, put/1, prepare/1, update/5]).


%%%===================================================================
%%% API
%%%===================================================================

get(DbAtom, ZoneName) ->
    case dnsxd_couch_lib:get_db(DbAtom) of
	{ok, DbRef} -> get(DbAtom, DbRef, ZoneName);
	{error, Error} -> {error, Error}
    end.

get(DbAtom, DbRef, ZoneName) ->
    case couchbeam:open_doc(DbRef, ZoneName) of
	{ok, {DocProps}} ->
	    case proplists:get_bool(<<"_deleted">>, DocProps) of
		true -> {error, deleted};
		false when DbAtom =:= local ->
		    #dnsxd_couch_lz{} = Zone = dnsxd_couch_doc:decode(DocProps),
		    case proplists:get_value(<<"_conflicts">>, DocProps, []) of
			[] -> {ok, Zone};
			Revs -> get(DbRef, ZoneName, Zone, Revs)
		    end;
		false ->
		    case dnsxd_couch_doc:decode(DocProps) of
			#dnsxd_couch_ez{} = Zone ->
			    {ok, Zone};
			_ ->
			    {error, not_zone}
		    end
	    end;
	{error, Error} -> {error, Error}
    end.

get(DbRef, ZoneName, Zone, Revs) ->
    get(DbRef, ZoneName, Zone, Revs, []).

get(DbRef, _ZoneName, Zone, [], DelDocs) ->
    case put(DbRef, Zone) of
	ok ->
	    case couchbeam:delete_docs(DbRef, DelDocs) of
		{ok, _} -> {ok, Zone};
		{error, Error} -> {error, Error}
	    end;
	{error, Error} -> {error, Error}
    end;
get(DbRef, ZoneName, Zone, [Rev|Revs], DelDocs) ->
    case couchbeam:open_doc(DbRef, ZoneName, [{rev, Rev}]) of
	{ok, Doc} ->
	    CZone = dnsxd_couch_doc:decode(Doc),
	    NewZone = dnsxd_couch_doc:merge(Zone, CZone),
	    NewDelDocs = [Doc|DelDocs],
	    get(DbRef, ZoneName, NewZone, Revs, NewDelDocs);
	{error, Error} ->
	    {error, Error}
    end.

put(Zone)
  when is_record(Zone, dnsxd_couch_lz) orelse is_record(Zone, dnsxd_couch_ez) ->
    Db = case Zone of
	     #dnsxd_couch_lz{} -> local;
	     #dnsxd_couch_ez{} -> export
	 end,
    case dnsxd_couch_lib:get_db(Db) of
	{ok, DbRef} ->
	    Doc = dnsxd_couch_doc:encode(Zone),
	    case couchbeam:save_doc(DbRef, Doc) of
		{ok, _} ->
		    ?DNSXD_COUCH_SERVER ! wrote_zone,
		    ok;
		{error, conflict} when Db =:= export ->
		    ZoneName = Zone#dnsxd_couch_ez.name,
		    case couchbeam:open_doc(DbRef, ZoneName) of
			{ok, CurDoc} ->
			    Rev = couchbeam_doc:get_rev(CurDoc),
			    Zone0 = Zone#dnsxd_couch_ez{rev = Rev},
			    Doc0 = dnsxd_couch_doc:encode(Zone0),
			    case couchbeam:save_doc(DbRef, Doc0) of
				{ok, _} ->
				    ?DNSXD_COUCH_SERVER ! wrote_zone,
				    ok;
				{error, Error} ->
				    {error, Error}
			    end;
			{error, Error} ->
			    {error, Error}
		    end;
		{error, Error} -> {error, Error}
	    end;
	{error, Error} -> {error, Error}
    end.

prepare(#dnsxd_couch_lz{} = Zone) ->
    {ok, Zone1} = pad_rr(Zone),
    {ok, _Zone2} = add_soa(Zone1);
prepare(#dnsxd_couch_ez{} = Zone) -> {ok, Zone}.

update(_MsgCtx, Key, ZoneName, PreReqs, Updates) ->
    Now = dns:unix_time(),
    {ok, #dnsxd_couch_lz{rr = RRs} = Zone} = get(local, ZoneName),
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
	    NewMutableRRs = update_rr(Key, true, Updates, MutableRRs),
	    NewImmutableRRs = reap(Now, ImmutableRRs),
	    NewRRs = lists:sort(NewMutableRRs ++ NewImmutableRRs),
	    NewZone = Zone#dnsxd_couch_lz{rr = NewRRs},
	    case put(NewZone) of
		ok ->
		    {ok, noerror};
		{error, Error} ->
		    timer:sleep(50),
		    {error, Error}
	    end;
	Rcode when is_atom(Rcode) -> {ok, Rcode}
    end.

%%%===================================================================
%%% Internal functions
%%%===================================================================

add_soa(#dnsxd_couch_lz{rr = RR,
			soa_param = #dnsxd_couch_sp{mname = MName,
						    rname = RName,
						    refresh = Ref,
						    retry = Ret,
						    expire = Exp,
						    minimum = Min}} = Zone) ->
    Data = #dns_rrdata_soa{mname = MName,
			   rname = RName,
			   refresh = Ref,
			   retry = Ret,
			   expire = Exp,
			   minimum = Min},
    Serials = dnsxd_couch_lib:get_serials(RR),
    add_soa(Zone, Serials, Data).

add_soa(#dnsxd_couch_lz{name = Name, rr = RRs} = Zone,
	[Serial], #dns_rrdata_soa{minimum = TTL} = Data) ->
    RR = #dnsxd_couch_rr{incept = Serial,
			 expire = undefined,
			 name = Name,
			 class = ?DNS_CLASS_IN,
			 type = ?DNS_TYPE_SOA,
			 ttl = TTL,
			 data = Data#dns_rrdata_soa{serial = Serial}
			},
    NewRRs = [RR|RRs],
    {ok, Zone#dnsxd_couch_lz{rr = NewRRs}};
add_soa(#dnsxd_couch_lz{name = Name, rr = RRs} = Zone,
	[Serial|[Next|_] = Serials], #dns_rrdata_soa{minimum = TTL} = Data) ->
    RR = #dnsxd_couch_rr{incept = Serial,
			 expire = Next,
			 name = Name,
			 class = ?DNS_CLASS_IN,
			 type = ?DNS_TYPE_SOA,
			 ttl = TTL,
			 data = Data#dns_rrdata_soa{serial = Serial}
			},
    NewRRs = [RR|RRs],
    NewZone = Zone#dnsxd_couch_lz{rr = NewRRs},
    add_soa(NewZone, Serials, Data).

pad_rr(#dnsxd_couch_lz{rr = RRs} = Zone) ->
    RRSets = to_rrsets(RRs),
    NewRRs = dict:fold(fun({_Name, _Class, _Type}, RRSetRRs, Acc) ->
			       Serials = get_active_serials(RRSetRRs),
			       pad_rr(Serials, RRSetRRs, Acc)
		       end, [], RRSets),
    {ok, Zone#dnsxd_couch_lz{rr = NewRRs}}.

pad_rr(_Serials, [], PaddedRRs) -> PaddedRRs;
pad_rr(Serials, [RR|RRs], PaddedRRs) ->
    NewPaddedRRs = pad_rr(Serials, RR, PaddedRRs),
    pad_rr(Serials, RRs, NewPaddedRRs);
pad_rr([], #dnsxd_couch_rr{}, PaddedRRs) -> PaddedRRs;
pad_rr([Serial|Serials], #dnsxd_couch_rr{incept = Incept, expire = Expire} = RR,
       PaddedRRs) ->
    if is_integer(Expire) andalso Serial >= Expire ->
	    pad_rr(Serials, RR, PaddedRRs);
       is_integer(Incept) andalso Serial >= Incept ->
	    SIncept = Serial,
	    SExpire = case Serials of
			  [NextSerial|_] -> NextSerial;
			  _ -> undefined
		      end,
	    NewRR = RR#dnsxd_couch_rr{incept = SIncept, expire = SExpire},
	    NewPaddedRRs = [NewRR|PaddedRRs],
	    pad_rr(Serials, RR, NewPaddedRRs);
       true ->
	    pad_rr(Serials, RR, PaddedRRs)
    end.

to_rrsets(RRs) -> to_rrsets(RRs, dict:new()).

to_rrsets([], Dict) -> Dict;
to_rrsets([#dnsxd_couch_rr{name = Name,
			      class = Class,
			      type = Type} = RR|RRs], Acc) ->
    NewAcc = dict:append({Name, Class, Type}, RR, Acc),
    to_rrsets(RRs, NewAcc).

get_active_serials([]) -> [];
get_active_serials(RR) ->
    Serials = dnsxd_couch_lib:get_serials(RR),
    Now = dns:unix_time(),
    get_active_serials(Now, Serials).

get_active_serials(_Now, [_] = Serials) -> Serials;
get_active_serials(Now, [_, Serial|_] = Serials) when Now < Serial -> Serials;
get_active_serials(Now, [_|Serials]) -> get_active_serials(Now, Serials).


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

update_rr(_Key, _Private, [], RRs) -> RRs;
update_rr(Key, Private, [{delete, Name}|Updates], RRs) ->
    Now = dns:unix_time(),
    {Match, Diff} = lists:partition(
		      fun(#dnsxd_couch_rr{name = SN}) ->
			      dns:dname_to_lower(SN) =:= Name end, RRs),
    NewMatch = [ RR#dnsxd_couch_rr{expire = Now - 1} || RR <- Match ],
    NewRRs = NewMatch ++ Diff,
    update_rr(Key, Private, Updates, NewRRs);
update_rr(Key, Private, [{delete, Name, Type}|Updates], RRs) ->
    Now = dns:unix_time(),
    Fun = fun(#dnsxd_couch_rr{name = SN, type = ST}) ->
		  dns:dname_to_lower(SN) =:= Name andalso ST =:= Type
	  end,
    {Match, Diff} = lists:partition(Fun, RRs),
    NewMatch = [ RR#dnsxd_couch_rr{expire = Now - 1} || RR <- Match ],
    NewRRs = NewMatch ++ Diff,
    update_rr(Key, Private, Updates, NewRRs);
update_rr(Key, Private, [{delete, Name, Type, Data}|Updates], RRs) ->
    Now = dns:unix_time(),
    Fun = fun(#dnsxd_couch_rr{name = SN, type = ST, data = SD}) ->
		  (dns:dname_to_lower(SN) =:= Name andalso
		   ST =:= Type andalso SD =:= Data)
	  end,
    {Match, Diff} = lists:partition(Fun, RRs),
    NewMatch = [ RR#dnsxd_couch_rr{expire = Now - 1} || RR <- Match ],
    NewRRs = NewMatch ++ Diff,
    update_rr(Key, Private, Updates, NewRRs);
update_rr(Key, Private, [{add, Name, Type, TTL, Data, LeaseLength}|Updates],
	  RRs) ->
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
	    update_rr(Key, Private, Updates, NewRRs);
	[#dnsxd_couch_rr{} = RR] ->
	    NewRR = RR#dnsxd_couch_rr{ttl = TTL, set = Now, expire = Expire},
	    NewRRs = [NewRR|Diff],
	    update_rr(Key, Private, Updates, NewRRs);
	[#dnsxd_couch_rr{} = RR|Dupes] ->
	    NewRR = RR#dnsxd_couch_rr{ttl = TTL, set = Now, expire = Expire},
	    NewDupes = [ Dupe#dnsxd_couch_rr{expire = Now - 1}
			 || Dupe <- Dupes ],
	    NewRRs = NewDupes ++ [NewRR|Diff],
	    update_rr(Key, Private, Updates, NewRRs)
    end.

reap(Now, RRs) when is_list(RRs) ->
    %% todo: should be configurable
    TombstonePeriod = 48 * 60 * 60,
    TombstonedRRs = [fun(#dnsxd_couch_rr{expire = Expires} = RR)
			   when is_integer(Expires) andalso Expires < Now ->
			     Tombstone = Expires + TombstonePeriod,
			     RR#dnsxd_couch_rr{tombstone = Tombstone};
			(#dnsxd_couch_rr{} = RR) -> RR
		     end(CouchRR) || CouchRR <- RRs],
    [RR || RR <- TombstonedRRs, reap(Now, RR)];
reap(Now, #dnsxd_couch_rr{tombstone = Tombstone})
  when is_integer(Tombstone) andalso Tombstone < Now -> false;
reap(_Now, #dnsxd_couch_rr{}) -> true.
