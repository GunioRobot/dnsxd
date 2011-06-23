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
-module(dnsxd_soc_tcp_sup).
-include("dnsxd.hrl").
-behaviour(supervisor).

%% API
-export([start_link/2]).

%% Supervisor callbacks
-export([init/1]).

-define(SERVER, ?MODULE).

%%%===================================================================
%%% API functions
%%%===================================================================

start_link(#dnsxd_if_spec{protocol = tcp} = IfSpec, ReqSupPid) ->
    supervisor:start_link(?MODULE, [IfSpec, ReqSupPid]).

%%%===================================================================
%%% Supervisor callbacks
%%%===================================================================

init([#dnsxd_if_spec{protocol = tcp} = IfSpec, ReqSupPid]) ->
    {ok, Socket} = listen(IfSpec),
    RestartStrategy = one_for_one,
    MaxRestarts = 10,
    MaxSecondsBetweenRestarts = 10,
    SupFlags = {RestartStrategy, MaxRestarts, MaxSecondsBetweenRestarts},
    Restart = permanent,
    Shutdown = 2000,
    Type = worker,
    Children = [ {{dnsxd_soc_tcp, N},
		  {dnsxd_soc_tcp, start_link, [IfSpec, Socket, ReqSupPid]},
		  Restart, Shutdown, Type, dynamic}
		 || N <- lists:seq(1, 8) ],
    {ok, {SupFlags, Children}}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

listen(#dnsxd_if_spec{protocol = tcp, ip = IP, port = Port}) ->
    Opts = [{ip, IP}, {backlog, 128}, {packet, 2}, {reuseaddr, true},
	    {keepalive, true}, {active, false}, binary],
    case gen_tcp:listen(Port, Opts) of
	{error, eacces} = ErrEacces ->
	    case dnsxd_lib:use_procket() of
		true ->
		    case dnsxd_lib:procket_open(Port, tcp, stream) of
			{ok, Fd} ->
			    FdOpts = [{fd, Fd}|Opts],
			    gen_tcp:listen(Port, FdOpts);
			Other -> Other
		    end;
		false -> ErrEacces
	    end;
	Other -> Other
    end.
