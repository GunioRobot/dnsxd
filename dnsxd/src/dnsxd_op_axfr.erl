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
-module(dnsxd_op_axfr).
-include("dnsxd.hrl").

%% API
-export([handle/2]).

%%%===================================================================
%%% API
%%%===================================================================

handle(MsgCtx, #dns_message{
	 questions=[#dns_query{name = ZoneNameM}]} = ReqMsg) ->
    case dnsxd_op_ctx:protocol(MsgCtx) of
	udp ->
	    dnsxd_op_ctx:reply(MsgCtx, ReqMsg, [{rc, formerr}]);
	tcp ->
	    ZoneName = dns:dname_to_lower(ZoneNameM),
	    case dnsxd:get_zone(ZoneName) of
		undefined ->
		    dnsxd_op_ctx:reply(MsgCtx, ReqMsg, [{rc, refused}]);
		#dnsxd_zone{axfr_enabled = false} ->
		    ?DNSXD_INFO("Refused AXFR of ~s to ~s",
				[ZoneName, src_as_text(MsgCtx)]),
		    dnsxd_op_ctx:reply(MsgCtx, ReqMsg, [{rc, refused}]);
		#dnsxd_zone{axfr_hosts = Hosts, rr = RRs} ->
		    case allow(MsgCtx, Hosts) of
			true ->
			    ?DNSXD_INFO("Allowed AXFR of ~s to ~s",
					[ZoneName, src_as_text(MsgCtx)]),
			    FilterFun = dnsxd_lib:active_rr_fun(),
			    ActiveRRs = [ dnsxd_lib:to_dns_rr(RR)
					  || RR <- RRs, FilterFun(RR) ],
			    {value, SOA, RRBody} = lists:keytake(?DNS_TYPE_SOA,
								 #dns_rr.type,
								 ActiveRRs),
			    Answers = [SOA|RRBody] ++ [SOA],
			    dnsxd_op_ctx:reply(MsgCtx, ReqMsg, [{an, Answers}]);
			false ->
			    ?DNSXD_INFO("Refused AXFR of ~s to ~s",
					[ZoneName, src_as_text(MsgCtx)]),
			    dnsxd_op_ctx:reply(MsgCtx, ReqMsg, [{rc, formerr}])
		    end
	    end
    end.

%%%===================================================================
%%% Internal functions
%%%===================================================================

allow(_MsgCtx, []) -> true;
allow(MsgCtx, Hosts) when is_list(Hosts) ->
    SrcIP = srcip_as_text(MsgCtx),
    lists:member(SrcIP, Hosts).

srcip_as_text(MsgCtx) ->
    SrcIP = dnsxd_op_ctx:src_ip(MsgCtx),
    list_to_binary(inet_parse:ntoa(SrcIP)).

src_as_text(MsgCtx) ->
    {SrcIPTuple, SrcPortInt} = dnsxd_op_ctx:src(MsgCtx),
    SrcIPList = inet_parse:ntoa(SrcIPTuple),
    SrcPortList = integer_to_list(SrcPortInt),
    iolist_to_binary([SrcIPList, $:, SrcPortList]).
