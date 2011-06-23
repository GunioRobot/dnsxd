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
-module(dnsxd_soc_tcp_req).
-include("dnsxd.hrl").
-export([start_link/1, init/1, loop/1]).

-define(DEFAULT_TIMEOUT, 60).

-record(state, {ifspec, socket, ctx, timeout}).

start_link(#dnsxd_if_spec{protocol = tcp} = IfSpec) ->
    Pid = spawn_link(?MODULE, init, [IfSpec]),
    {ok, Pid}.

init(#dnsxd_if_spec{protocol = tcp, ip = DstIP, port = DstPort} = IfSpec) ->
    Timeout = timeout(),
    receive
	{start, Socket} ->
	    Ctx = dnsxd_op_ctx:new_tcp(Socket, DstIP, DstPort),
	    State = #state{ifspec = IfSpec, socket = Socket, ctx = Ctx,
			   timeout = Timeout},
	    ?MODULE:loop(State);
	Other ->
	    ?DNSXD_ERR("Stray message:~n~p~n", [Other])
    after Timeout ->
	    ?DNSXD_ERR(?MODULE_STRING " timed out waiting for socket")
    end.

loop(#state{socket = Socket, ctx = Ctx, timeout = Timeout} = State) ->
    ok = inet:setopts(Socket, [{active, once}]),
    receive
	{tcp, Socket, MsgBin} ->
	    ok = dnsxd_op:dispatch(Ctx, MsgBin),
	    ?MODULE:loop(State);
	{tcp_closed, Socket} -> ok;
	Other ->
	    ?DNSXD_ERR("Stray message:~n~p~n", [Other]),
	    ok = gen_tcp:close(Socket)
    after Timeout ->
	    ok = gen_tcp:close(Socket)
    end.

timeout() ->
    case dnsxd:get_env(tcp_timeout) of
	{ok, TimeoutSecs}
	  when is_integer(TimeoutSecs) andalso TimeoutSecs > 0 ->
	    TimeoutSecs * 1000;
	_ -> ?DEFAULT_TIMEOUT * 1000
    end.
