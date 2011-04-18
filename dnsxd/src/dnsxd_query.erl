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
-export([answer/2, answer/3]).

-record(ctx, {now, rr, zonename, names, cuts, followed_names = []}).

%%%===================================================================
%%% API
%%%===================================================================

answer(#dnsxd_zone{} = Zone, #dns_query{} = Query) ->
    Now = dns:unix_time(),
    answer(Zone, Query, Now).

answer(#dnsxd_zone{name = ZoneName, rr = RR}, #dns_query{} = Query, Now)
  when is_integer(Now) ->
    FilterFun = dnsxd_lib:active_rr_fun(Now),
    ActiveRR = lists:filter(FilterFun, RR),
    Names = build_names(ZoneName, ActiveRR),
    Cuts = build_cuts(ZoneName, ActiveRR),
    Ctx = #ctx{zonename = ZoneName,
	       names = Names,
	       now = Now,
	       rr = ActiveRR,
	       cuts = Cuts},
    an(Query, Ctx, []).

%%%===================================================================
%%% Internal functions
%%%===================================================================

an(#dns_query{name = NameM, type = Type} = Query,
   #ctx{zonename = ZoneName} = Ctx, An) ->
    Name = dns:dname_to_lower(NameM),
    SOA = lists:keyfind(?DNS_TYPE_SOA, #dnsxd_rr.type, Ctx#ctx.rr),
    case Name of
	ZoneName ->
	    NewRRs = [ RR#dnsxd_rr{name = NameM}
		       || #dnsxd_rr{} = RR <- Ctx#ctx.rr,
			  match_name(ZoneName, RR),
			  match_qtype(Ctx, Type, RR) ],
	    NewAn = An ++ NewRRs,
	    case NewAn of
		[] -> {noerror, [], [SOA], []};
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
			    FollowedNames = Ctx#ctx.followed_names,
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
			    au(Ctx, NewAn)
		    end;
		{referral, RefRRs} ->
		    ad(Ctx, An, RefRRs);
		nomatch ->
		    case An of
			[] -> {nxdomain, [], [SOA], []};
			_ -> au(Ctx, An)
		    end
	    end
    end.

au(#ctx{zonename = ZoneName, rr = RRs} = Q, An) ->
    Au = [ RR || #dnsxd_rr{name = Name, type = ?DNS_TYPE_NS} = RR <- RRs,
		 Name =:= ZoneName ],
    ad(Q, An, Au).

ad(#ctx{} = Ctx, An, Au) -> ad(Ctx, An, Au, []).
ad(#ctx{} = Ctx, An, Au, Ad) ->
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
    Matches = lists:filter(fun(#dnsxd_rr{name = Name, type = Type}) ->
				   Hash = erlang:phash2({Name,Type}),
				   lists:member(Hash, Targets)
			   end, Ctx#ctx.rr),
    NewAd = lists:usort(Matches ++ Ad),
    case NewAd of
	Ad -> {noerror, An, Au, Ad};
	NewAd -> ad(Ctx, An, Au, NewAd)
    end.

match_name(Name, #dnsxd_rr{name = Name}) -> true;
match_name(_, _) -> false.

match_qtype(#ctx{}, ?DNS_TYPE_ANY, #dnsxd_rr{}) -> true;
match_qtype(#ctx{}, Type, #dnsxd_rr{type = Type}) -> true;
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
