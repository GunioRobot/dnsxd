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
-module(dnsxd_query).
-include("dnsxd.hrl").

%% API
-export([answer/3, answer/4]).

-record(ctx, {now, rr, zonename, names, cuts, followed_names = [],
	      soa, dnssec, dnssec_keys, nsec3, cur_serial, next_serial}).

%%%===================================================================
%%% API
%%%===================================================================

answer(#dnsxd_zone{} = Zone, #dns_query{} = Query, DNSSEC)
  when is_boolean(DNSSEC) ->
    Now = dns:unix_time(),
    answer(Zone, Query, DNSSEC, Now).

answer(#dnsxd_zone{name = ZoneName, rr = RR, soa_param = SOA,
		   dnssec_keys = AllKeys, dnssec_enabled = DNSSECEnabled,
		   nsec3 = NSEC3Param, serials = Serials},
       #dns_query{} = Query, DoDNSSEC, Now) when is_integer(Now) ->
    ActiveKeys = [ Key || #dnsxd_dnssec_key{} = Key <- AllKeys,
			  is_record(NSEC3Param, dnsxd_nsec3_param),
			  DNSSECEnabled andalso DoDNSSEC,
			  Key#dnsxd_dnssec_key.alg =:= ?DNS_ALG_NSEC3RSASHA1,
			  Key#dnsxd_dnssec_key.incept =< Now,
			  Key#dnsxd_dnssec_key.expire > Now ],
    FilterFun = dnsxd_lib:active_rr_fun(Now),
    ActiveRR = lists:filter(FilterFun, RR),
    Names = build_names(ZoneName, ActiveRR),
    Cuts = build_cuts(ZoneName, ActiveRR),
    NSEC3 = case ActiveKeys =:= [] of
		true -> undefined;
		false -> NSEC3Param
	    end,
    {CurSerial, NextSerial} = current_serials(Now, Serials),
    Ctx = #ctx{zonename = ZoneName,
	       names = Names,
	       now = Now,
	       rr = ActiveRR,
	       cuts = Cuts,
	       soa = SOA,
	       dnssec = DoDNSSEC,
	       dnssec_keys = ActiveKeys,
	       nsec3 = NSEC3,
	       cur_serial = CurSerial,
	       next_serial = NextSerial},
    {RCODE, An, Au, Ad} = an(Query, Ctx, []),
    {RCODE,
     dnsxd_lib:to_dns_rr(Now, An),
     dnsxd_lib:to_dns_rr(Now, Au),
     dnsxd_lib:to_dns_rr(Now, Ad)}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

current_serials(Now, [Current, Next|_])
  when Now >= Current andalso Now < Next -> {Current, Next};
current_serials(Now, [_|Serials]) -> current_serials(Now, Serials);
current_serials(_Now, _Serials) -> {0, 0}. %% this should never happen

an(#dns_query{name = NameM, type = Type} = Query,
   #ctx{zonename = ZoneName, followed_names = FollowedNames, rr = RRs} = Ctx,
   An) ->
    Name = dns:dname_to_lower(NameM),
    SOA = lists:keyfind(?DNS_TYPE_SOA, #dnsxd_rr.type, RRs),
    case Name of
	ZoneName ->
	    NewRRs = [ RR#dnsxd_rr{name = NameM}
		       || #dnsxd_rr{} = RR <- RRs,
			  match_name(ZoneName, RR),
			  match_qtype(Ctx, Type, RR) ],
	    NewAn = An ++ NewRRs,
	    case NewAn of
		[] ->
		    %% no data
		    FinalAn = sign(Ctx, add_nsec3(false, Ctx, Query, [SOA])),
		    {noerror, [], FinalAn, []};
		_ -> ad(Ctx, NewAn, [])
	    end;
	_ ->
	    NameSize = byte_size(Name),
	    ZoneNameSize = byte_size(ZoneName),
	    QLabelsSize = NameSize - ZoneNameSize - 1,
	    <<QLabelsBin:QLabelsSize/binary, $., ZoneName/binary>> = Name,
	    QLabels = lists:reverse(dns:dname_to_labels(QLabelsBin)),
	    case match_down(Ctx, ZoneName, QLabels) of
		{match, MatchRRs} ->
		    case match_cname(Ctx, MatchRRs) of
			{true, RRs, Next} ->
			    NewRRs = [ RR#dnsxd_rr{name = NameM} || RR <- RRs ],
			    case lists:member(Next, FollowedNames) of
				true -> {servfail, [], [], []};
				false ->
				    NewAn = An ++ NewRRs,
				    NewQuery = Query#dns_query{name = Next},
				    NewFollowed = [Next|FollowedNames],
				    NewCtx = Ctx#ctx{
					       followed_names = NewFollowed},
				    an(NewQuery, NewCtx, NewAn)
			    end;
			false ->
			    NewRRs = [ RR#dnsxd_rr{name = NameM}
				       || #dnsxd_rr{} = RR <- MatchRRs,
					  match_qtype(Ctx, Type, RR) ],
			    NewAn = An ++ NewRRs,
			    case NewAn of
				[] ->
				    FinalAn = sign(Ctx,
						   add_nsec3(false, Ctx, Query,
							     [SOA])),
				    {noerror, [], FinalAn, []};
				_ -> au(Ctx, NewAn)
			    end
		    end;
		{referral, RefRRs} -> ad(Ctx, An, RefRRs);
		nomatch ->
		    case An of
			[] ->
			    %% no name
			    FinalAn = sign(Ctx,
					   add_nsec3(true, Ctx, Query, [SOA])),
			    {nxdomain, [], FinalAn, []};
			_ -> au(Ctx, An)
		    end
	    end
    end.

au(#ctx{zonename = ZoneName, rr = RRs} = Q, An) ->
    Au = [ RR || #dnsxd_rr{name = Name, type = ?DNS_TYPE_NS} = RR <- RRs,
		 Name =:= ZoneName ],
    ad(Q, An, Au).

ad(#ctx{} = Ctx, An, Au) -> ad(Ctx, An, Au, []).
ad(#ctx{rr = RRs} = Ctx, An, Au, Ad) ->
    Fun = fun(#dnsxd_rr{data = #dns_rrdata_ns{dname = DnameM}}, Acc) ->
		  Dname = dns:dname_to_lower(DnameM),
		  NewTargets = [ erlang:phash2({Dname, Type})
				 || Type <- [?DNS_TYPE_A, ?DNS_TYPE_AAAA] ],
		  NewTargets ++ Acc;
	     (#dnsxd_rr{data = #dns_rrdata_srv{target = TargetM}}, Acc) ->
		  Dname = dns:dname_to_lower(TargetM),
		  NewTargets = [ erlang:phash2({Dname, Type})
				 || Type <- [?DNS_TYPE_A, ?DNS_TYPE_AAAA] ],
		  NewTargets ++ Acc;
	     (#dnsxd_rr{data = #dns_rrdata_ptr{dname = DnameM}}, Acc) ->
		  Dname = dns:dname_to_lower(DnameM),
		  NewTargets = [ erlang:phash2({Dname, Type})
				 || Type <- [?DNS_TYPE_SRV, ?DNS_TYPE_TXT,
					     ?DNS_TYPE_A, ?DNS_TYPE_AAAA] ],
		  NewTargets ++ Acc;
	     (_, Acc) -> Acc
	  end,
    AnTargets = lists:foldl(Fun, [], An),
    AuTargets = lists:foldl(Fun, [], Au),
    AdTargets = lists:foldl(Fun, [], Ad),
    Targets = lists:usort(AnTargets ++ AuTargets ++ AdTargets),
    Matches = [ RR || RR <- RRs, ad_filter(RR, Targets) ],
    NewAd = lists:usort(Matches ++ Ad),
    case NewAd of
	Ad -> {noerror, sign(Ctx, An), sign(Ctx, Au), sign(Ctx, Ad)};
	NewAd -> ad(Ctx, An, Au, NewAd)
    end.

ad_filter(#dnsxd_rr{name = Name, type = Type}, Targets) ->
    Hash = erlang:phash2({Name, Type}),
    lists:member(Hash, Targets).

sign(#ctx{dnssec = true, dnssec_keys = Keys} = Ctx, RR) when Keys =/= [] ->
    sign(Ctx, lists:reverse(RR), [], []);
sign(#ctx{}, RR) -> RR.

sign(#ctx{}, [], [], Processed) -> Processed;
sign(#ctx{} = Ctx, [], Set, Processed) ->
    SignedRRSet = sign_rrset(Ctx, Set),
    SignedRRSet ++ Processed;
sign(#ctx{} = Ctx, [#dnsxd_rr{} = RR|RRs], _RRSet = [], Processed) ->
    sign(Ctx, RRs, [RR], Processed);
sign(#ctx{} = Ctx, [#dnsxd_rr{name = N, class = C, type = T} = RR|RRs],
     [#dnsxd_rr{name = N, class = C, type = T}|_] = RRSet, Processed) ->
    sign(Ctx, RRs, [RR|RRSet], Processed);
sign(#ctx{} = Ctx, RRs, RRSet, Processed) ->
    SignedRRSet = sign_rrset(Ctx, RRSet),
    NewProcessed = SignedRRSet ++ Processed,
    sign(Ctx, RRs, [], NewProcessed).

sign_rrset(#ctx{dnssec_keys = Keys, zonename = SignersName}, Set) ->
    RRs = [#dns_rr{name = N, class = C, type = Type, ttl = TTL, data = D}
	   || #dnsxd_rr{name = N, class = C, type = Type, ttl = TTL, data = D}
		  <- Set ],
    UseKSK = (hd(Set))#dnsxd_rr.type =:= ?DNS_TYPE_DNSKEY,
    TTL = (hd(Set))#dnsxd_rr.ttl,
    RevSet = lists:foldl(
	       fun(#dnsxd_dnssec_key{alg = Alg, ksk = KSK, key = Key,
				     keytag = KeyTag}, Acc)
		     when Alg =:= ?DNS_ALG_NSEC3RSASHA1 andalso
			  KeyTag =/= undefined andalso
			  (KSK =:= false orelse KSK =:= UseKSK) ->
		       Opts = [], %% calc incept, expire
		       #dns_rr{name = Name,
			       type = ?DNS_TYPE_RRSIG,
			       class = Class,
			       ttl = TTL,
			       data = Data}
			   = dnssec:sign_rrset(RRs, SignersName, KeyTag, Alg,
					       Key, Opts),
		       RRSIG = #dnsxd_rr{name = Name,
					 type = ?DNS_TYPE_RRSIG,
					 class = Class,
					 ttl = TTL,
					 data = Data},
		       [RRSIG|Acc];
		  (#dnsxd_dnssec_key{}, Acc) ->
		       Acc
	       end, Set, Keys),
    lists:reverse(RevSet).

add_nsec3(NxDom,
	  #ctx{dnssec = true, nsec3 = #dnsxd_nsec3_param{}, rr = CtxRR} = Ctx,
	  #dns_query{name = NameMix}, RR) ->
    Name = dns:dname_to_lower(NameMix),
    DName = dns:encode_dname(Name),
    if NxDom ->
	    Types = lists:seq(1,33,3) ++ [?DNS_TYPE_RRSIG],
	    [_|WildAsc] = dns:dname_to_labels(Name),
	    WDName = dns:encode_dname(join_labels([<<$*>>|WildAsc])),
	    %% closest encloser
	    NSEC3 = make_nsec3(Ctx, false, DName, Types),
	    %% wild closest encloser
	    NSEC3Wild = make_nsec3(Ctx, false, WDName, Types),
	    [NSEC3, NSEC3Wild | RR];
       true -> %% Name exists, but no data
	    Types = [T || #dnsxd_rr{name = N, type = T} <- CtxRR,
			  N =:= Name],
	    NSEC3 = make_nsec3(Ctx, true, DName, Types),
	    [NSEC3 | RR]
    end;
add_nsec3(_NxDom, #ctx{}, #dns_query{}, RR) -> RR.

make_nsec3(#ctx{} = Ctx,  CoverName, Name, Types) ->
    #ctx{zonename = ZoneName, nsec3 = NSEC3, soa = SOA,
	 cur_serial = CurSerial, next_serial = NextSerial} = Ctx,
    #dnsxd_nsec3_param{hash = HashNum, salt = Salt, iter = Iter} = NSEC3,
    MaxTTL = SOA#dnsxd_soa_param.minimum,
    TimeToNextSerial = NextSerial - CurSerial,
    TTL = case TimeToNextSerial > MaxTTL of
	      true -> MaxTTL;
	      false -> TimeToNextSerial
	  end,
    HashFun = case HashNum of
		  1 -> fun crypto:sha/1
	      end,
    Hash = ih(HashFun, Salt, dns:dname_to_lower(Name), Iter),
    HashP = case CoverName of
		true -> base32hex_encode(Hash);
		false -> base32hex_encode(hash_bump(Hash, -1))
	    end,
    NextHash = hash_bump(Hash, +1),
    RRName = <<HashP/binary, $., ZoneName/binary>>,
    Data = #dns_rrdata_nsec3{hash_alg = HashNum,
			     opt_out = false,
			     iterations = Iter,
			     salt = Salt,
			     hash = NextHash,
			     types = Types},
    #dnsxd_rr{name = RRName, class = ?DNS_CLASS_IN, type = ?DNS_TYPE_NSEC3,
	      incept = CurSerial, expire = NextSerial, ttl = TTL, data = Data}.

hash_bump(Hash, Amount) ->
    HashS = byte_size(Hash),
    <<Num:HashS/unit:8>> = Hash,
    <<(Num + Amount):HashS/unit:8>>.

ih(H, Salt, X, 0) -> H([X, Salt]);
ih(H, Salt, X, I) -> ih(H, Salt, H([X, Salt]), I - 1).

base32hex_encode(Bin) when bit_size(Bin) rem 5 =/= 0 ->
    PadBy = byte_size(Bin) rem 5,
    base32hex_encode(<<Bin/bitstring, 0:PadBy>>);
base32hex_encode(Bin) when bit_size(Bin) rem 5 =:= 0 ->
    << <<(base32hex_encode(I))>> || <<I:5>> <= Bin >>;
base32hex_encode(Int)
  when is_integer(Int) andalso Int >= 0 andalso Int =< 9 -> Int + 48;
base32hex_encode(Int)
  when is_integer(Int) andalso Int >= 10 andalso Int =< 31 -> Int + 55.

match_name(Name, #dnsxd_rr{name = Name}) -> true;
match_name(_, _) -> false.

match_qtype(#ctx{}, ?DNS_TYPE_ANY, #dnsxd_rr{}) -> true;
match_qtype(#ctx{}, Type, #dnsxd_rr{type = Type}) -> true;
match_qtype(#ctx{dnssec= true}, Type,
	    #dnsxd_rr{type = ?DNS_TYPE_RRSIG,
		      data = #dns_rrdata_rrsig{type_covered = Type}}) -> true;
match_qtype(#ctx{}, _Type, #dnsxd_rr{}) -> false.

match_down(#ctx{cuts = Cuts, names = Names, rr = RRs} = Q,
	   LastDname, [Label]) ->
    LabelSize = byte_size(Label),
    Name = <<Label:LabelSize/binary, $., LastDname/binary>>,
    WName = <<"*.", LastDname/binary>>,
    NameIsCut = lists:member(Name, Cuts),
    NameExists = lists:member(Name, Names),
    WNameExists = lists:member(WName, Names),
    case NameExists of
	true when NameIsCut ->
	    Result = [ RR || #dnsxd_rr{} = RR <- RRs,
			     match_name(Name, RR),
			     match_qtype(Q, ?DNS_TYPE_NS, RR) ],
	    {referral, Result};
	true ->
	    Result = [ RR || #dnsxd_rr{} = RR <- RRs, match_name(Name, RR) ],
	    {match, Result};
	false when WNameExists ->
	    Result = [ RR || #dnsxd_rr{} = RR <- RRs, match_name(WName, RR) ],
	    {match,  Result};
	false -> nomatch
    end;
match_down(#ctx{cuts = Cuts, names = Names, rr = RRs} = Q, LastDname,
	   [Label|Labels]) ->
    LabelSize = byte_size(Label),
    Name = <<Label:LabelSize/binary, $., LastDname/binary>>,
    NameIsCut = lists:member(Name, Cuts),
    NameExists = lists:member(Name, Names),
    case NameExists of
	true when NameIsCut ->
	    Result = [ RR || #dnsxd_rr{} = RR <- RRs,
			     match_qtype(Q, ?DNS_TYPE_NS, RR) ],
	    {referral, Result};
	true -> match_down(Q, Name, Labels);
	false -> nomatch
    end;
match_down(_, _, _) -> nomatch.

match_cname(#ctx{}, [#dnsxd_rr{type = cname,
			       data = #dns_rrdata_cname{dname = Next}}] = RR) ->
    {true, RR, Next};
match_cname(#ctx{}, _) -> false.

build_names(ZoneName, RRs) -> build_names(ZoneName, [ZoneName], RRs).

build_names(_ZoneName, Names, []) -> lists:usort(Names);
build_names(ZoneName, Names, [#dnsxd_rr{name = Name}|RRs]) ->
    Labels = dns:dname_to_labels(Name),
    AscNames = build_asc_names(ZoneName, Labels),
    NewNames = AscNames ++ Names,
    build_names(ZoneName, NewNames, RRs).

build_asc_names(_ZoneName, []) -> [];
build_asc_names(ZoneName, [_|Asc] = Cur) ->
    case join_labels(Cur) of
	ZoneName -> [];
	Name -> [Name|build_asc_names(ZoneName, Asc)]
    end.

join_labels(Labels) ->
    <<$., Dname/binary>> = << <<$., L/binary>> || L <- Labels >>,
    Dname.

build_cuts(ZoneName, RRs) -> build_cuts(ZoneName, RRs, []).

build_cuts(_ZoneName, [], Cuts) -> lists:usort(Cuts);
build_cuts(ZoneName, [#dnsxd_rr{name = ZoneName}|RRs], Cuts) ->
    build_cuts(ZoneName, RRs, Cuts);
build_cuts(ZoneName, [#dnsxd_rr{type = ?DNS_TYPE_NS, name = Name}|RRs], Cuts) ->
    build_cuts(ZoneName, RRs, [Name|Cuts]);
build_cuts(ZoneName, [_|RRs], Cuts) ->
    build_cuts(ZoneName, RRs, Cuts).
