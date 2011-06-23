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
-module(dnsxd_sup).

-behaviour(supervisor).

%% API
-export([start_link/0]).

%% supervisor callbacks
-export([init/1]).

-define(SERVER, ?MODULE).

start_link() ->
    supervisor:start_link({local, ?SERVER}, ?MODULE, []).

init([]) ->
    RestartStrategy = one_for_all,
    MaxRestarts = 1000,
    MaxSecondsBetweenRestarts = 3600,
    SupFlags = {RestartStrategy, MaxRestarts, MaxSecondsBetweenRestarts},
    Restart = permanent,
    Shutdown = 2000,
    DsSpec = {dnsxd_ds_server, {dnsxd_ds_server, start_link, []},
	      Restart, Shutdown, worker, [dnsxd_ds_server]},
    SocSpec = {dnsxd_socs_sup, {dnsxd_socs_sup, start_link, []},
	       Restart, Shutdown, supervisor, [dnsxd_socs_sup]},
    Mod = dnsxd:datastore(),
    Specs = case should_supervise(Mod) of
		true ->
		    ModSpec = {Mod, {Mod, start_link, []}, Restart, Shutdown,
			       supervise_type(Mod), [Mod]},
		    [DsSpec, ModSpec, SocSpec];
		false -> [DsSpec, SocSpec]
	    end,
    {ok, {SupFlags, Specs}}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

should_supervise(Mod) ->
    is_supervisor(Mod) orelse is_gen_server(Mod).

supervise_type(Mod) ->
    case is_supervisor(Mod) of
	true -> supervisor;
	false ->
	    true = is_gen_server(Mod),
	    worker
    end.

is_supervisor(Mod) ->
    has_behaviour(Mod, supervisor).

is_gen_server(Mod) ->
    has_behaviour(Mod, gen_server).

has_behaviour(Mod, Behaviour) ->
    ModAttributes = Mod:module_info(attributes),
    Behaviours = proplists:get_value(behaviour, ModAttributes, []),
    lists:member(Behaviour, Behaviours).
