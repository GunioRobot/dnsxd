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
    LogSpec = {dnsxd_log_sup, {dnsxd_log_sup, start_link, []},
	       Restart, Shutdown, supervisor, [dnsxd_log_sup]},
    DsSpec = {dnsxd_ds_server, {dnsxd_ds_server, start_link, []},
	      Restart, Shutdown, worker, [dnsxd_ds_server]},
    LLQSpec = {dnsxd_llq_sup, {dnsxd_llq_sup, start_link, []},
	       Restart, Shutdown, supervisor, [dnsxd_llq_sup]},
    SocSpec = {dnsxd_socs_sup, {dnsxd_socs_sup, start_link, []},
	       Restart, Shutdown, supervisor, [dnsxd_socs_sup]},
    AdditionalSpecs = specs_for_modules([dnsxd:log(), dnsxd:datastore()]),
    Specs = [LogSpec, DsSpec, LLQSpec] ++ AdditionalSpecs ++ [SocSpec],
    {ok, {SupFlags, Specs}}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

specs_for_modules(Modules) -> specs_for_modules(Modules, [], []).

specs_for_modules([], _Setup, Specs) -> lists:reverse(Specs);
specs_for_modules([undefined|Modules], Setup, Specs) ->
    specs_for_modules(Modules, Setup, Specs);
specs_for_modules([Module|Modules], Setup, Specs) ->
    case lists:member(Module, Setup) of
	true -> specs_for_modules(Modules, Setup, Specs);
	false ->
	    NewSetup = [Module|Setup],
	    case should_supervise(Module) of
		true ->
		    NewSpec = {Module, {Module, start_link, []}, permanent,
			       2000, supervise_type(Module), [Module]},
		    NewSpecs = [NewSpec|Specs],
		    specs_for_modules(Modules, NewSetup, NewSpecs);
		false -> specs_for_modules(Modules, NewSetup, Specs)
	    end
    end.

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
