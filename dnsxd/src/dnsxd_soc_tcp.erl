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
-module(dnsxd_soc_tcp).
-include("dnsxd_internal.hrl").
-export([start_link/3, loop/3]).

start_link(#dnsxd_if_spec{protocol = tcp} = IfSpec, Socket, ReqSupPid)
  when is_pid(ReqSupPid) ->
    Pid = spawn_link(fun() -> ?MODULE:loop(IfSpec, Socket, ReqSupPid) end),
    {ok, Pid}.

loop(#dnsxd_if_spec{} = IfSpec, Socket, ReqSupPid) when is_pid(ReqSupPid) ->
    case gen_tcp:accept(Socket, 2000) of
	{ok, NewSocket} ->
	    {ok, ReqPid} = supervisor:start_child(ReqSupPid, []),
	    ok = gen_tcp:controlling_process(NewSocket, ReqPid),
	    ReqPid ! {start, NewSocket},
	    ?MODULE:loop(IfSpec, Socket, ReqSupPid);
	{error, _Reason} -> ?MODULE:loop(IfSpec, Socket, ReqSupPid)
    end.
