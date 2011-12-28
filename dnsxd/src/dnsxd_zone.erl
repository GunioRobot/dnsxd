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
-module(dnsxd_zone).
-include("dnsxd_internal.hrl").

-define(PREP_SERIALS_MAX, 10).
-define(PREP_SERIALS_MIN, 60).

-define(DAY_SECONDS, 86400).
-define(YEAR_SECONDS, 31556926).

-export([prepare/3]).

prepare(TempTab, Ref, #dnsxd_zone{} = Zone) ->
    false = process_flag(trap_exit, true),
    Self = self(),
    Pid = spawn_link(fun() -> main(Self, TempTab, Ref, Zone) end),
    Result = receive_result(Pid, Ref),
    true = process_flag(trap_exit, false),
    Result.

receive_result(Pid, Ref) ->
    receive
	{Pid, Ref, Serials, AXFR} ->
	    receive
		{'EXIT', Pid, 'normal'} -> {ok, Serials, AXFR};
		{'EXIT', Pid, Reason} -> {error, Reason}
	    end;
	{'EXIT', Pid, Reason} -> {error, Reason}
    end.

main(Parent, TempTab, Ref, #dnsxd_zone{name = ZoneName} = Zone) ->
    WorkerLimit = worker_limit(),
    Funs = [ fun prep_tsigkey/1,
	     fun prep_rr/1,
	     fun prep_nsec3param/1,
	     fun prep_dnsseckey/1,
	     fun prep_serials/1 ],
    Zone0 = lists:foldl(fun(Fun, #dnsxd_zone{} = T) -> Fun(T) end, Zone, Funs),
    ZoneRef = #zone_ref{name = ZoneName, ref = Ref},
    TSIG = #tsig{zone_ref = ZoneRef, keys = Zone0#dnsxd_zone.tsig_keys},
    ets:insert(TempTab, TSIG),
    Serials = get_serials_to_prep(Zone0),
    AXFR = axfr_settings(Zone0),
    ok = main(TempTab, [], WorkerLimit, Serials, Ref, Zone0),
    RealSerials = lists:reverse(tl(lists:reverse(Serials))),
    Parent ! {self(), Ref, RealSerials, AXFR}.

main(TempTab, Workers, Limit, [Serial|[NextSerial|_] = Serials], Ref, Zone)
  when length(Workers) < Limit ->
    Self = self(),
    Fun = fun() -> prep_zone(Self, TempTab, Serial, NextSerial, Ref, Zone) end,
    Workers0 = [spawn_link(Fun)|Workers],
    main(TempTab, Workers0, Limit, Serials, Ref, Zone);
main(TempTab, Workers, Limit, Serials, Ref, Zone) ->
    MoreToDo = 1 < length(Serials),
    AllWorkersAlive = lists:all(fun erlang:is_process_alive/1, Workers),
    Workers0 = receive {Pid, Ref} -> lists:delete(Pid, Workers)
	       after 1000 -> Workers end,
    false = (not AllWorkersAlive) andalso Workers0 =:= Workers,
    WaitForWorker = [] =/= Workers0,
    case MoreToDo orelse WaitForWorker of
	true -> main(TempTab, Workers0, Limit, Serials, Ref, Zone);
	false -> ok
    end.

worker_limit() ->
    case application:get_env(dnsxd, insert_workers) of
	{ok, Int} when is_integer(Int) andalso Int > 0 -> Int;
	_ ->
	    Limit0 = case erlang:system_info(logical_processors_available) of
			Int when is_integer(Int) -> Int - 1;
			_ ->
			    case erlang:system_info(logical_processors) of
				Int when is_integer(Int) -> Int - 1;
				_ -> 2
			    end
		    end,
	    Limit1 = max(1, Limit0),
	    application:set_env(dnsxd, insert_workers, Limit1),
	    Limit1
    end.

prep_tsigkey(#dnsxd_zone{tsig_keys = Keys} = Zone) ->
    NewKeys = [Key || #dnsxd_tsig_key{enabled = true} = Key <- Keys ],
    Zone#dnsxd_zone{tsig_keys = NewKeys}.

prep_rr(#dnsxd_zone{rr = RRs} = Zone) ->
    NewRRs = [ RR#dnsxd_rr{name = dns:dname_to_lower(Name)}
	       || #dnsxd_rr{name = Name, class = ?DNS_CLASS_IN} = RR <- RRs ],
    Zone#dnsxd_zone{rr = NewRRs}.

prep_nsec3param(#dnsxd_zone{dnssec_enabled = true,
			    nsec3 = #dnsxd_nsec3_param{salt = SaltTxt
						     } = NSEC3Param} = Zone) ->
    Salt = binary:encode_unsigned(list_to_integer(binary_to_list(SaltTxt), 16)),
    NSEC3Param0 = NSEC3Param#dnsxd_nsec3_param{salt = Salt},
    Zone#dnsxd_zone{nsec3 = NSEC3Param0};
prep_nsec3param(#dnsxd_zone{} = Zone) -> Zone.

prep_dnsseckey(#dnsxd_zone{dnssec_enabled = false} = Zone) -> Zone;
prep_dnsseckey(#dnsxd_zone{dnssec_enabled = true, dnssec_keys = Keys} = Zone) ->
    lists:foldl(fun prep_dnsseckey/2, Zone#dnsxd_zone{dnssec_keys = []}, Keys).

prep_dnsseckey(#dnsxd_dnssec_key{alg = ?DNS_ALG_NSEC3RSASHA1 = Alg,
				 id = Id,
				 ksk = KSK,
				 incept = Incept,
				 expire = Expire,
				 key = [ <<ESize:32, E/binary>>,
					 <<_NSize:32, N/binary>>,
					 <<_DSize:32, _D/binary>>] } = Key,
	       #dnsxd_zone{name = ZoneName,
			   rr = RRs,
			   soa_param = #dnsxd_soa_param{expire = TTL},
			   dnssec_keys = Keys} = Zone) ->
    Flags = if KSK -> 257;
	       true -> 256 end,
    PKBin = if ESize > 255 -> <<0, ESize:16, E/binary, N/binary>>;
	       true -> <<ESize:8, E/binary, N/binary>> end,
    DKDataBin = dns:encode_rrdata(?DNS_CLASS_IN,
				  #dns_rrdata_dnskey{flags = Flags,
						     protocol = 3,
						     alg = Alg,
						     public_key = PKBin}),
    DKData = dns:decode_rrdata(?DNS_CLASS_IN, ?DNS_TYPE_DNSKEY, DKDataBin),
    DKRR = #dnsxd_rr{name = ZoneName,
		     class = ?DNS_CLASS_IN,
		     type = ?DNS_TYPE_DNSKEY,
		     ttl = TTL,
		     data = DKData,
		     incept = Incept,
		     expire = Expire},
    DSKeyDigest = crypto:sha([dns:encode_dname(ZoneName), DKDataBin]),
    KeyTag = DKData#dns_rrdata_dnskey.key_tag,
    DSKeyData = #dns_rrdata_ds{keytag = KeyTag,
			       alg = Alg,
			       digest_type = 1,
			       digest = DSKeyDigest},
    DSRRName = <<Id/binary, "._dnsxd-ds.", ZoneName/binary>>,
    DSRR = #dnsxd_rr{name = DSRRName,
		     class = ?DNS_CLASS_IN,
		     type = ?DNS_TYPE_DS,
		     ttl = TTL,
		     data = DSKeyData,
		     incept = Incept,
		     expire = Expire},
    PTRRR = #dnsxd_rr{name = <<"_dnsxd-ds.", ZoneName/binary>>,
		      class = ?DNS_CLASS_IN,
		      type = ?DNS_TYPE_PTR,
		      ttl = TTL,
		      data = #dns_rrdata_ptr{dname = DSRRName},
		      incept = Incept,
		      expire = Expire},
    NewRRs = case KSK of
		 true -> [PTRRR, DSRR, DKRR|RRs];
		 false -> [DKRR|RRs]
	     end,
    NewKeys = [Key#dnsxd_dnssec_key{keytag = KeyTag}|Keys],
    Zone#dnsxd_zone{rr = NewRRs, dnssec_keys = NewKeys}.

prep_serials(#dnsxd_zone{dnssec_enabled = false, rr = RRs} = Zone) ->
    Zone#dnsxd_zone{serials = build_serials_dict(RRs)};
prep_serials(#dnsxd_zone{dnssec_enabled = true, dnssec_siglife = SigLife,
			 rr = RRs} = Zone) ->
    Serials0 = build_serials_dict(RRs),
    Serials1 = pad_serials_dict_to_siglife(Serials0, SigLife),
    Zone#dnsxd_zone{serials = Serials1}.

build_serials_dict(RRs) -> build_serials_dict(RRs, dict:new()).

build_serials_dict([#dnsxd_rr{name = Name,
			      type = Type,
			      incept = Incept,
			      expire = Expire}|RRs], Dict) ->
    Key = {Name, Type},
    Serials = case is_integer(Expire) of
		  true -> [Incept, Expire];
		  false -> [Incept, Incept + 315569260]
	      end,
    NewDict0 = add_to_serials_dict(Key, Serials, Dict),
    NewDict1 = add_to_serials_dict(all, Serials, NewDict0),
    build_serials_dict(RRs, NewDict1);
build_serials_dict([], Dict) -> Dict.

add_to_serials_dict(Key, Values, Dict) ->
    case dict:is_key(Key, Dict) of
	true ->
	    MergedValues = lists:umerge(lists:usort(Values),
					dict:fetch(Key, Dict)),
	    dict:store(Key, MergedValues, Dict);
	false ->
	    dict:store(Key, lists:usort(Values), Dict)
    end.

pad_serials_dict_to_siglife(Dict, SigLife) ->
    dict:fold(fun(all, _, Acc) -> Acc;
		 (RRSetKey, Serials, Acc) ->
		      NewValues = pad_serial_list_to_siglife(Serials, SigLife),
		      Acc0 = dict:store(RRSetKey, NewValues, Acc),
		      add_to_serials_dict(all, NewValues, Acc0)
	      end, dict:new(), Dict).

pad_serial_list_to_siglife([First|Serials], SigLife) ->
    Limit = dns:unix_time() + (2 * SigLife),
    pad_serial_list_to_siglife(Limit, [First], Serials, SigLife).

pad_serial_list_to_siglife(Limit, [Last|_] = Seen, [Cur|NewUnseen] = Unseen,
			   SigLife) when Last < Limit ->
    if (Cur - Last) =< SigLife ->
	    pad_serial_list_to_siglife(Limit, [Cur|Seen], NewUnseen, SigLife);
	true ->
	    NewSerial = Last + SigLife,
	    pad_serial_list_to_siglife(Limit, [NewSerial|Seen], Unseen, SigLife)
    end;
pad_serial_list_to_siglife(_Limit, [_,_,_|_] = Seen, _Unseen, _SigLife) ->
    lists:reverse(Seen);
pad_serial_list_to_siglife(_Limit, [Last|_] = Seen, _Unseen, SigLife) ->
    NewSeen = case length(Seen) of
		  2 -> [Last + SigLife|Seen];
		  1 -> [Last + (SigLife * 2), Last + SigLife|Seen]
	      end,
    lists:reverse(NewSeen).

get_serials_to_prep(#dnsxd_zone{serials = Serials}) ->
    Now = dns:unix_time(),
    AllSerials = case dict:is_key(all, Serials) of
		     true -> dict:fetch(all, Serials);
		     false -> []
		 end,
    get_serials_to_prep(AllSerials, Now, ?PREP_SERIALS_MAX, ?PREP_SERIALS_MIN).

%% get the next N serials or the serials covering Now + MinTime
get_serials_to_prep([_|[Next|_] = NewSerials], Now, MaxSerials, MinTime)
  when Next < Now -> get_serials_to_prep(NewSerials, Now, MaxSerials, MinTime);
get_serials_to_prep(Serials, Now, MaxSerials, MinTime) ->
    get_serials_to_prep(Serials, Now, MaxSerials, MinTime, []).

get_serials_to_prep([Serial|[_|_] = Serials], Now, Max, MinTime, Collected)
  when (Serial < (Now + MinTime)) orelse (length(Collected) < Max) ->
    get_serials_to_prep(Serials, Now, Max, MinTime, [Serial|Collected]);
get_serials_to_prep(_Serials, _Now, _Max, _MinTime, []) -> [0, 1];
get_serials_to_prep(_Serials, Now, _Max, _MinTime, [Serial]) ->
    [Serial, Now + ?YEAR_SECONDS];
get_serials_to_prep(_Serials, _Now, _Max, _MinTime, Collected) ->
    lists:reverse(Collected).

axfr_settings(#dnsxd_zone{axfr_enabled = false}) -> false;
axfr_settings(#dnsxd_zone{axfr_enabled = true, axfr_hosts = []}) -> true;
axfr_settings(#dnsxd_zone{axfr_enabled = true, axfr_hosts = Hosts}) -> Hosts.

prep_zone(Parent, TempTab, Serial, NextSerial, Ref,
	  #dnsxd_zone{name = ZoneName,
		      dnssec_enabled = true,
		      dnssec_keys = DNSSECKeys,
		      rr = AllRRs,
		      serials = SerialsDict
		     } = Zone) ->
    ZoneRef = #zone_ref{name = ZoneName, ref = Ref},
    SerialRef = #serial_ref{zone_ref = ZoneRef, serial = Serial},
    SOARR = gen_soa_rr(Serial, NextSerial, Zone),
    NSEC3ParamRR = gen_nsec3param_rr(Serial, NextSerial, Zone),
    RRforSerial = rr_for_serial(Serial, SerialsDict, AllRRs),
    RRs = [SOARR,NSEC3ParamRR|RRforSerial],
    Cuts = gen_cuts(ZoneName, RRs),
    RRSetDict = gen_rrsetdict(ZoneName, Cuts, RRs),
    {NSEC3Names, NSEC3RRSets} = gen_nsec3(Zone, Serial, NextSerial, RRSetDict),
    RRSetDict0 = gen_rrsetdict(ZoneName, Cuts, NSEC3RRSets, RRSetDict),
    Context = orddict:from_list([{serial_ref, SerialRef},
				 {nsec3_names, NSEC3Names},
				 {zonename, ZoneName},
				 {cuts, Cuts},
				 {dnssec_keys, DNSSECKeys},
				 {temp_tab, TempTab}]),
    RRNameRecs = gen_rrname_recs(RRSetDict0, Context),
    ets:insert(TempTab, RRNameRecs),
    NameTree = gen_nametree(ZoneName, RRSetDict0),
    Names = dict:fetch_keys(RRSetDict0),
    NameType = [ {Name, [Type || #rrset{type = Type} <- Sets]}
		 || {Name, Sets} <- dict:to_list(RRSetDict0) ],
    ets:insert(TempTab, #rrmap{serial_ref = SerialRef,
			       names = Names,
			       tree = NameTree,
			       sets = NameType,
			       nsec3 = NSEC3Names}),
    Parent ! {self(), Ref};
prep_zone(Parent, TempTab, Serial, NextSerial, Ref,
	  #dnsxd_zone{name = ZoneName,
		      rr = AllRRs,
		      serials = SerialsDict} = Zone) ->
    ZoneRef = #zone_ref{name = ZoneName, ref = Ref},
    SerialRef = #serial_ref{zone_ref = ZoneRef, serial = Serial},
    SOARR = gen_soa_rr(Serial, NextSerial, Zone),
    RRforSerial = rr_for_serial(Serial, SerialsDict, AllRRs),
    RRs = [SOARR|RRforSerial],
    Cuts = gen_cuts(ZoneName, RRs),
    RRSetDict = gen_rrsetdict(ZoneName, Cuts, RRs),
    Context = orddict:from_list([{serial_ref, SerialRef},
				 {zonename, ZoneName},
				 {cuts, Cuts},
				 {temp_tab, TempTab}]),
    RRNameRecs = gen_rrname_recs(RRSetDict, Context),
    ets:insert(TempTab, RRNameRecs),
    NameTree = gen_nametree(ZoneName, RRSetDict),
    Names = dict:fetch_keys(RRSetDict),
    NameType = [ {Name, [Type || #rrset{type = Type} <- Sets]}
		 || {Name, Sets} <- dict:to_list(RRSetDict) ],
    ets:insert(TempTab, #rrmap{serial_ref = SerialRef,
			       names = Names,
			       tree = NameTree,
			       sets = NameType}),
    Parent ! {self(), Ref}.

gen_soa_rr(Serial, NextSerial,
	   #dnsxd_zone{name = ZoneName,
		       soa_param = #dnsxd_soa_param{mname = Mname,
						    rname = Rname,
						    refresh = Refresh,
						    retry = Retry,
						    expire = Expire,
						    minimum = Minimum}}) ->
    #dnsxd_rr{name = ZoneName,
	      incept = Serial,
	      expire = NextSerial,
	      class = ?DNS_CLASS_IN,
	      type = ?DNS_TYPE_SOA,
	      ttl = Minimum,
	      data = #dns_rrdata_soa{mname = Mname,
				     rname = Rname,
				     serial = Serial,
				     refresh = Refresh,
				     retry = Retry,
				     expire = Expire,
				     minimum = Minimum}}.

gen_nsec3param_rr(Serial, NextSerial,
		  #dnsxd_zone{name = ZoneName,
			      nsec3 = #dnsxd_nsec3_param{hash = Hash,
							 salt = Salt,
							 iter = Iter}}) ->
    #dnsxd_rr{name = ZoneName,
	      incept = Serial,
	      expire = NextSerial,
	      class = ?DNS_CLASS_IN,
	      type = ?DNS_TYPE_NSEC3PARAM,
	      ttl = NextSerial - Serial,
	      data = #dns_rrdata_nsec3param{hash_alg = Hash,
					    flags = 0,
					    salt = Salt,
					    iterations = Iter}}.

rr_for_serial(Serial, SerialsDict, RRs) ->
    [ RR#dnsxd_rr{incept = incept(Serial, SerialsDict, RR),
		  expire = expire(Serial, SerialsDict, RR)}
      || #dnsxd_rr{incept = Incept, expire = Expire} = RR <- RRs,
	 Incept =< Serial, (not is_integer(Expire) orelse Serial < Expire) ].

incept(Serial, SerialsDict, #dnsxd_rr{type = ?DNS_TYPE_SOA} = RR) ->
    incept(Serial, SerialsDict, RR#dnsxd_rr{type = all});
incept(Serial, SerialsDict, #dnsxd_rr{name = Name, type = Type}) ->
    SetSerials = dict:fetch({Name, Type}, SerialsDict),
    case lists:member(Serial, SetSerials) of
	true -> Serial;
	false -> incept(Serial, SetSerials)
    end.

incept(CurrentSerial, [SetSerial, NextSetSerial|_])
  when NextSetSerial > CurrentSerial -> SetSerial;
incept(_CurrentSerial, [Serial]) -> Serial;
incept(CurrentSerial, [_|SetSerials]) -> incept(CurrentSerial, SetSerials).

expire(CurrentSerial, SerialsDict, #dnsxd_rr{type = ?DNS_TYPE_SOA} = RR) ->
    expire(CurrentSerial, SerialsDict, RR#dnsxd_rr{type = all});
expire(CurrentSerial, SerialsDict, #dnsxd_rr{name = Name, type = Type}) ->
    SetSerials = dict:fetch({Name, Type}, SerialsDict),
    Fun = fun(Serial) -> Serial =< CurrentSerial end,
    case lists:dropwhile(Fun, SetSerials) of
	[Expire|_] -> Expire;
	[] -> undefined
    end.

gen_cuts(ZoneName, RRs) -> gen_cuts(ZoneName, RRs, []).

gen_cuts(ZoneName, [#dnsxd_rr{name = ZoneName}|RRs], Cuts) ->
    gen_cuts(ZoneName, RRs, Cuts);
gen_cuts(ZoneName, [#dnsxd_rr{type = ?DNS_TYPE_NS, name = Name}|RRs], Cuts) ->
    case lists:member(Name, Cuts) of
	false -> gen_cuts(ZoneName, RRs, lists:usort([Name|Cuts]));
	true -> gen_cuts(ZoneName, RRs, Cuts)
    end;
gen_cuts(ZoneName, [#dnsxd_rr{}|RRs], Cuts) -> gen_cuts(ZoneName, RRs, Cuts);
gen_cuts(_ZoneName, [], Cuts) -> Cuts.

gen_rrsetdict(ZoneName, Cuts, RRs) ->
    gen_rrsetdict(ZoneName, Cuts, RRs, dict:new()).

gen_rrsetdict(ZoneName, Cuts, [#dnsxd_rr{incept = Incept,
					 expire = Expire,
					 name = Name,
					 type = Type,
					 ttl = TTL,
					 data = Data}|RRs], Dict) ->
    Dict0 = gen_rrsetdict_names(ZoneName, Name, Dict),
    CurSets = dict:fetch(Name, Dict0),
    NewSets = case lists:keytake(Type, #rrset.type, CurSets) of
		  {value,
		   #rrset{ttl = CurTTL, data = CurDatas} = CurSet, CurSets0} ->
		      NewTTL = case CurTTL < TTL of
				   true -> CurTTL;
				   false -> TTL
			       end,
		      NewDatas = [Data|CurDatas],
		      NewRRSet = CurSet#rrset{ttl = NewTTL, data = NewDatas},
		      [NewRRSet|CurSets0];
		  false ->
		      CutBy = find_cut(ZoneName, Name, Cuts),
		      NewRRSet = #rrset{name = Name,
					cutby = CutBy,
					type = Type,
					incept = Incept,
					expire = Expire,
					ttl = TTL,
					data = [Data]},
		      [NewRRSet|CurSets]
	      end,
    Dict1 = dict:store(Name, NewSets, Dict0),
    gen_rrsetdict(ZoneName, Cuts, RRs, Dict1);
gen_rrsetdict(_ZoneName, _Cuts, [], Dict) -> Dict.

gen_rrsetdict_names(ZoneName, Name, Dict) ->
    case dict:is_key(Name, Dict) of
	true -> Dict;
	false when Name =:= ZoneName -> dict:store(Name, [], Dict);
	false ->
	    NewDict = dict:store(Name, [], Dict),
	    [_|AscLabels] = dns:dname_to_labels(Name),
	    NewName = dns:labels_to_dname(AscLabels),
	    gen_rrsetdict_names(ZoneName, NewName, NewDict)
    end.

find_cut(ZoneName, ZoneName, _Cuts) -> undefined; % <- necessary?
find_cut(_ZoneName, Name, Cuts) -> find_cut(Name, Cuts).

find_cut(Name, [Name|_]) -> Name;
find_cut(Name, [Cut|Cuts]) when (byte_size(Cut) + 1) < byte_size(Name) ->
    Pre = byte_size(Name) - byte_size(Cut) - 1,
    case Name of
	<<_:Pre/binary, $., Cut/binary>> -> Cut;
	_ -> find_cut(Name, Cuts)
    end;
find_cut(Name, [_|Cuts]) -> find_cut(Name, Cuts);
find_cut(_Name, []) -> undefined.

gen_nsec3(#dnsxd_zone{name = ZoneName,
		      soa_param = #dnsxd_soa_param{minimum = TTL},
		      nsec3 = #dnsxd_nsec3_param{hash = HashAlgNo,
						 salt = Salt,
						 iter = Iter}},
	  Serial, NextSerial, RRSetDict) ->
    Fun = fun(Name, Sets, Acc) ->
		  Types = [ Type || #rrset{type = Type} <- Sets ],
		  Types0 = if Types =:= [] -> [];
			      true -> lists:usort([?DNS_TYPE_RRSIG|Types]) end,
		  CutBy = case Sets of
			      [#rrset{cutby = CutByTmp}|_] -> CutByTmp;
			      _ -> undefined
			  end,
		  NotCut = CutBy =:= undefined,
		  DSExists = lists:member(?DNS_TYPE_DS, Types),
		  case NotCut orelse DSExists of
		      true ->
			  DName = dns:encode_dname(Name),
			  HashedDN = dnssec:ih(HashAlgNo, Salt, DName, Iter),
			  HashedDNHex = dnssec:base32hex_encode(HashedDN),
			  NewName = <<HashedDNHex/binary, $.,
				      ZoneName/binary>>,
			  Data = #dns_rrdata_nsec3{hash_alg = 1,
						   opt_out = false,
						   iterations = Iter,
						   salt = Salt,
						   hash = HashedDNHex,
						   types = Types0},
			  RR = #dnsxd_rr{name = NewName,
					 incept = Serial,
					 expire = NextSerial,
					 class = ?DNS_CLASS_IN,
					 type = ?DNS_TYPE_NSEC3,
					 ttl = TTL,
					 data = Data},
			  NSEC3 = #nsec3{name = Name,
					 hash = HashedDN,
					 hashdn = NewName},
			   [{HashedDN, NSEC3, RR}|Acc];
		      false -> Acc
		  end
	  end,
    Unsorted = dict:fold(Fun, [], RRSetDict),
    Sorted = lists:keysort(1, Unsorted),
    {_SortedHash, SortedNSEC3, SortedRRSet} = lists:unzip3(Sorted),
    RRSetWithNextHash = gen_nsec3_add_next(SortedRRSet),
    {SortedNSEC3, RRSetWithNextHash}.

gen_nsec3_add_next([#dnsxd_rr{data = #dns_rrdata_nsec3{hash = First}
			     }|_] = RRs) ->
    gen_nsec3_add_next(RRs, [], First).

gen_nsec3_add_next([#dnsxd_rr{data = Data} = RR], RRs, FirstHash) ->
    NewRR = RR#dnsxd_rr{data = Data#dns_rrdata_nsec3{hash = FirstHash}},
    lists:reverse([NewRR|RRs]);
gen_nsec3_add_next([#dnsxd_rr{data = Data} = RR|
		    [#dnsxd_rr{data = #dns_rrdata_nsec3{hash = NextHash}
			      }|_] = Hashes], RRs, FirstHash) ->
    NewRR = RR#dnsxd_rr{data = Data#dns_rrdata_nsec3{hash = NextHash}},
    gen_nsec3_add_next(Hashes, [NewRR|RRs], FirstHash).

gen_nametree(ZoneName, RRSetDict) ->
    Names = dict:fetch_keys(RRSetDict),
    Fun = fun(Name) ->
		  UQ = strip_zonename(Name, ZoneName),
		  lists:reverse(dns:dname_to_labels(UQ))
	  end,
    DescLabels = [ Fun(Name) || Name <- Names, Name =/= ZoneName ],
    lists:foldl(fun(Labels, Acc) ->
			gen_nametree(ZoneName, Labels, Acc)
		end, gb_trees:empty(), DescLabels).

gen_nametree(ParentName, [<<$*>> = Label], Tree) ->
    NewName = <<"*.", ParentName/binary>>,
    case gb_trees:lookup(Label, Tree) of
	{value, {NewName, _OldWild, SubTree}} ->
	    gb_trees:update(Label, {NewName, true, SubTree}, Tree);
	none ->
	    gb_trees:insert(Label, {NewName, true, gb_trees:empty()}, Tree)
    end;
gen_nametree(ParentName, [Label|Labels], Tree) ->
    NewName = <<(dns:escape_label(Label))/binary, $., ParentName/binary>>,
    case gb_trees:lookup(Label, Tree) of
	{value, {NewName, Wild, SubTree}} ->
	    NewSubTree = gen_nametree(NewName, Labels, SubTree),
	    gb_trees:update(Label, {NewName, Wild, NewSubTree}, Tree);
	none ->
	    NewSubTree = gen_nametree(NewName, Labels, gb_trees:empty()),
	    gb_trees:insert(Label, {NewName, false, NewSubTree}, Tree)
    end;
gen_nametree(_ParentName, [], Tree) -> Tree.

strip_zonename(Name, ZoneName) ->
    ZoneNameSize = byte_size(ZoneName),
    NameSize = byte_size(Name),
    UQSize = NameSize - ZoneNameSize - 1,
    <<UQ:UQSize/binary, $., ZoneName/binary>> = Name,
    UQ.

gen_rrname_recs(RRSetDict, Context) ->
    Fun = fun(Name, Sets, Acc) -> gen_rrname_recs(Name, Sets, Acc, Context) end,
    dict:fold(Fun, [], RRSetDict).

gen_rrname_recs(Name, Sets, Acc, Context) ->
    ZoneName = orddict:fetch(zonename, Context),
    TempTab = orddict:fetch(temp_tab, Context),
    SerialRef = orddict:fetch(serial_ref, Context),
    NSEC3Names = case orddict:is_key(nsec3_names, Context) of
		     true -> orddict:fetch(nsec3_names, Context);
		     false -> []
		 end,
    Cuts = orddict:fetch(cuts, Context),
    RRNameRef = #rrname_ref{serial_ref = SerialRef, name = Name},
    Types = [ Type || #rrset{type = Type} <- Sets ],
    CoveredBy = case lists:keyfind(Name, #nsec3.name, NSEC3Names) of
		    #nsec3{hashdn = HashDN} -> HashDN;
		    false -> undefined
		end,
    CutBy = find_cut(ZoneName, Name, Cuts),
    NameRec = #rrname{ref = RRNameRef, name = Name, cutby = CutBy,
		      types = Types, coveredby = CoveredBy},
    Context0 = orddict:store(name_ref, RRNameRef, Context),
    Context1 = orddict:store(name, Name, Context0),
    SetRecs = [ gen_set_rec(Set, Context1) || Set <- Sets ],
    true = ets:insert(TempTab, SetRecs),
    [NameRec|Acc].

gen_set_rec(#rrset{type = Type, incept = Incept, expire = Expire,
			 cutby = CutBy, data = Datas} = Set, Context) ->
    DNSSECKeys = case orddict:is_key(dnssec_keys, Context) of
		     true -> orddict:fetch(dnssec_keys, Context);
		     false -> []
		 end,
    HaveKeys = DNSSECKeys =/= [],
    Sign = HaveKeys andalso (CutBy =:= undefined orelse Type =:= ?DNS_TYPE_DS),
    NameRef = orddict:fetch(name_ref, Context),
    ZoneName = orddict:fetch(zonename, Context),
    Name = orddict:fetch(name, Context),
    UseKSK = ?DNS_TYPE_DNSKEY =:= Type,
    Sigs = if Sign -> sign_rr(UseKSK, ZoneName, DNSSECKeys, Incept, Expire,
			      Name, Type, Datas);
	      true -> [] end,
    BinSigs = encode_rrdatas(Sigs),
    BinDatas = encode_rrdatas(Datas),
    SetRef = #rrset_ref{rrname_ref = NameRef, type = Type},
    Set#rrset{ref = SetRef, sig = BinSigs, data = BinDatas}.

sign_rr(UseKSK, ZoneName, DNSSECKeys, Incept, Expire, Name, Type, Datas) ->
    DNSSECKeys0 = [ Key || #dnsxd_dnssec_key{incept = KeyIncept,
					     expire = KeyExpire,
					     alg = ?DNS_ALG_NSEC3RSASHA1,
					     ksk = KeyKSK} = Key <- DNSSECKeys,
			   KeyIncept =< Incept,
			   KeyExpire >= Expire,
			   KeyKSK =:= false orelse UseKSK ],
    RRs = [ #dns_rr{name = Name, type = Type, data = Data} || Data <- Datas ],
    Opts = [{inception, Incept - ?DAY_SECONDS},
	    {expiration, Expire + ?DAY_SECONDS}],
    sign_rr(ZoneName, DNSSECKeys0, Opts, RRs, []).

sign_rr(ZoneName, [#dnsxd_dnssec_key{keytag = KeyTag,
				     alg = Alg,
				     key = Key}|DNSSECKeys], Opts, RRs, Sigs) ->
    #dns_rr{data = Sig} = dnssec:sign_rrset(RRs, ZoneName, KeyTag, Alg, Key,
					    Opts),
    NewSigs = [Sig|Sigs],
    sign_rr(ZoneName, DNSSECKeys, Opts, RRs, NewSigs);
sign_rr(_ZoneName, [], _Opts, _RRs, Sigs) -> Sigs.

encode_rrdatas(Datas) -> [ dns:encode_rrdata(?DNS_CLASS_IN, D) || D <- Datas ].
