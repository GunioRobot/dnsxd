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
-include("dnsxd_internal.hrl").

%% API
-export([handle/2]).

%%%===================================================================
%%% API
%%%===================================================================

handle(MsgCtx, #dns_message{
	 questions=[#dns_query{name = ZoneName}]} = ReqMsg) ->
    ZoneRef = dnsxd_ds_server:get_zone(ZoneName),
    Protocol = dnsxd_op_ctx:protocol(MsgCtx),
    {SrcIPTuple, SrcPort} = dnsxd_op_ctx:src(MsgCtx),
    SrcIP = dnsxd_lib:ip_to_txt(SrcIPTuple),
    Refuse = if Protocol =:= udp -> true;
		ZoneRef =:= undefined -> true;
		true -> not allow(ZoneRef, SrcIP) end,
    MsgArgs = [ZoneName, SrcIP, SrcPort],
    Props = case Refuse of
		true ->
		    ?DNSXD_INFO("Refusing AXFR of ~s to ~s:~p", MsgArgs),
		    [{rc, ?DNS_RCODE_REFUSED}];
		false ->
		    ?DNSXD_INFO("Allowing AXFR of ~s to ~s:~p", MsgArgs),
		    Sets = dnsxd_ds_server:get_set_list(ZoneRef),
		    [{an, collect_sets(ZoneRef, Sets)}, {dnssec, true}]
	    end,
    dnsxd_op_ctx:reply(MsgCtx, ReqMsg, Props).

%%%===================================================================
%%% Internal functions
%%%===================================================================

allow(Zone, SrcIP) ->
    case dnsxd_ds_server:axfr_hosts(Zone) of
	Bool when is_boolean(Bool) -> Bool;
	Hosts when is_list(Hosts) -> lists:member(SrcIP, Hosts)
    end.

collect_sets(ZoneRef, Sets) -> collect_sets(ZoneRef, Sets, []).

collect_sets(ZoneRef, [{Name, Types}|Sets], RR) ->
    RR0 = collect_sets(ZoneRef, Name, Types, RR),
    collect_sets(ZoneRef, Sets, RR0);
collect_sets(ZoneRef, [], RR) ->
    Name = dnsxd_ds_server:zonename_from_ref(ZoneRef),
    Set = dnsxd_ds_server:get_set(ZoneRef, Name, ?DNS_TYPE_SOA),
    SetNoSig = Set#rrset{sig = []},
    [Set|lists:reverse([SetNoSig|RR])].

collect_sets(ZoneRef, Name, [?DNS_TYPE_DS|Types], RR) ->
    collect_sets(ZoneRef, Name, Types, RR);
collect_sets(ZoneRef, Name, [?DNS_TYPE_SOA|Types], RR) ->
    collect_sets(ZoneRef, Name, Types, RR);
collect_sets(ZoneRef, Name, [Type|Types], RR) ->
    Set = dnsxd_ds_server:get_set(ZoneRef, Name, Type),
    collect_sets(ZoneRef, Name, Types, [Set|RR]);
collect_sets(_ZoneRef, _Name, [], RR) -> RR.
