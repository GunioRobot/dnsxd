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
-module(dnsxd_couch).

-behaviour(supervisor).

%% API
-export([start_link/0]).

-export([dnsxd_admin_zone_list/0, dnsxd_admin_get_zone/1,
	 dnsxd_admin_change_zone/2, dnsxd_dns_update/6, dnsxd_log/1]).

%% Supervisor callbacks
-export([init/1]).

-define(SERVER, ?MODULE).

%%%===================================================================
%%% API functions
%%%===================================================================

start_link() ->
    supervisor:start_link({local, ?SERVER}, ?MODULE, []).

dnsxd_admin_zone_list() -> dnsxd_couch_ds_server:dnsxd_admin_zone_list().

dnsxd_admin_get_zone(Zone) -> dnsxd_couch_ds_server:dnsxd_admin_get_zone(Zone).

dnsxd_admin_change_zone(Zone, Changes) ->
    dnsxd_couch_ds_server:dnsxd_admin_change_zone(Zone, Changes).

dnsxd_dns_update(MsgCtx, Key, ZoneName, ZoneClass, PreReqs, Updates) ->
    dnsxd_couch_ds_server:dnsxd_dns_update(MsgCtx, Key, ZoneName, ZoneClass,
					   PreReqs, Updates).

dnsxd_log(Props) -> dnsxd_couch_log_server:dnsxd_log(Props).

%%%===================================================================
%%% Supervisor callbacks
%%%===================================================================

init([]) ->
    ok = dnsxd_couch_app:install(),
    Servers = [dnsxd_couch_ds_server, dnsxd_couch_log_server],
    Children = [{Mod, {Mod, start_link, []},
		 permanent, 5000, worker, [Mod]} || Mod <- Servers ],
    {ok, {{one_for_one, 1, 1}, Children}}.
