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
-module(dnsxd_socs_sup).
-include("dnsxd.hrl").
-behaviour(supervisor).

%% API
-export([start_link/0]).

%% supervisor callbacks
-export([init/1]).

-define(SERVER, ?MODULE).

%%%===================================================================
%%% API
%%%===================================================================

start_link() -> supervisor:start_link({local, ?SERVER}, ?MODULE, []).

%%%===================================================================
%%% supervisor callbacks
%%%===================================================================

init([]) ->
    RestartStrategy = one_for_one,
    MaxRestarts = 0,
    MaxSecondsBetweenRestarts = 1,
    SupFlags = {RestartStrategy, MaxRestarts, MaxSecondsBetweenRestarts},
    Restart = permanent,
    Shutdown = 2000,
    case build_interfaces() of
	Interfaces when is_list(Interfaces) ->
	    ChildSpecs = [ {if_spec_to_name(IfSpec),
			    {dnsxd_soc_sup, start_link, [IfSpec]},
			    Restart, Shutdown, supervisor, [dnsxd_soc_sup]}
			   || IfSpec <- Interfaces ],
	    {ok, {SupFlags, ChildSpecs}};
	{error, _Reason} = Error -> Error
    end.

%%%===================================================================
%%% Internal functions
%%%===================================================================

if_spec_to_name(#dnsxd_if_spec {ip = IP, port = Port, protocol = Proto}) ->
    {dnsxd_soc_server, {IP, Port, Proto}}.

build_interfaces() ->
    case dnsxd:get_env(interfaces) of
	{ok, Interfaces} -> build_interfaces(Interfaces);
	undefined -> {error, no_interfaces}
    end.

build_interfaces([_|_] = Interfaces) ->
    try [ build_if_spec(Interface) || Interface <- Interfaces ]
    catch throw:{_, _} = Reason -> {error, Reason} end;
build_interfaces(Term) -> {error, {bad_ifspecs, Term}}.

build_if_spec({_IP, Port, _Protocol} = Term) when not is_integer(Port) ->
    throw({bad_port, Term});
build_if_spec({_IP, Port, _Protocol} = Term)
  when Port < 1 orelse Port > 65535 -> throw({bad_port, Term});
build_if_spec({_IP, _Port, Protocol} = Term)
  when Protocol =/= udp andalso Protocol =/= tcp ->
    throw({bad_protocol, Term});
build_if_spec({IP, Port, Protocol} = Term) ->
    case inet_parse:address(IP) of
	{ok, ParsedIP} ->
	    #dnsxd_if_spec{ip = ParsedIP,
			   port = Port,
			   protocol = Protocol};
	_ -> throw({bad_ip, Term})
    end;
build_if_spec(Term) -> throw({bad_ifspec, Term}).
