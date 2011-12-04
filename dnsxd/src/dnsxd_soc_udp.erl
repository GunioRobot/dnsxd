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
-module(dnsxd_soc_udp).
-include("dnsxd_internal.hrl").
-export([start_link/2, init/3, loop/3]).

start_link(#dnsxd_if_spec{protocol = udp} = IfSpec, ReqSupPid)
  when is_pid(ReqSupPid) ->
    Self = self(),
    Pid = spawn_link(fun() -> ?MODULE:init(Self, IfSpec, ReqSupPid) end),
    receive {Pid, ok} -> {ok, Pid} end.

init(Parent, #dnsxd_if_spec{protocol = udp, ip = IP, port = Port} = IfSpec,
     ReqSupPid) when is_pid(ReqSupPid) ->
    {ok, Socket} = open(IP, Port),
    Parent ! {self(), ok},
    loop(IfSpec, Socket, ReqSupPid).

loop(#dnsxd_if_spec{} = IfSpec, Socket, ReqSupPid) ->
    ok = inet:setopts(Socket, [{active, once}]),
    receive
	{udp, Socket, _, _, _} = Msg ->
	    {ok, ReqPid} = supervisor:start_child(ReqSupPid, []),
	    ReqPid ! Msg,
	    ?MODULE:loop(IfSpec, Socket, ReqSupPid);
	Other ->
	    ?DNSXD_ERR("Stray message:~n~p~n", [Other]),
	    ?MODULE:loop(IfSpec, Socket, ReqSupPid)
    end.

open(IP, Port) ->
    RecBufSize = case dnsxd:get_env(udp_recbuf_size) of
		     {ok, Size} -> Size;
		     _ -> 32768
		 end,
    Opts = [{ip, IP}, {active, false}, {recbuf, RecBufSize}, binary],
    case gen_udp:open(Port, Opts) of
	{error, eacces} = ErrEaccess ->
	    case dnsxd_lib:use_procket() of
		true ->
		    case dnsxd_lib:procket_open(IP, Port, udp, dgram) of
			{ok, Fd} ->
			    FdOpts = [{fd, Fd}|Opts],
			    gen_udp:open(Port, FdOpts);
			Other -> Other
		    end;
		false -> ErrEaccess
	    end;
	Other -> Other
    end.
