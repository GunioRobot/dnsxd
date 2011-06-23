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
-module(dnsxd_soc_udp_req).
-include("dnsxd.hrl").
-export([start_link/1, init/1]).

start_link(#dnsxd_if_spec{protocol = udp} = IfSpec) ->
    Pid = spawn_link(?MODULE, init, [IfSpec]),
    {ok, Pid}.

init(#dnsxd_if_spec{protocol = udp, ip = DstIP, port = DstPort}) ->
    receive
	{udp, Socket, SrcIP, SrcPort, MsgBin} ->
	    Ctx = dnsxd_op_ctx:new_udp(Socket, SrcIP, SrcPort, DstIP, DstPort),
	    ok = dnsxd_op:dispatch(Ctx, MsgBin);
	Other ->
	    ?DNSXD_ERR("Stray message:~n~p~n", [Other])
    after 5000 ->
	    ?DNSXD_ERR("Timed out waiting for datagram")
    end.
