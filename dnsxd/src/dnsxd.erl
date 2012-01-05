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
-module(dnsxd).
-include("dnsxd_internal.hrl").
-behaviour(application).

% app callbacks
-export([start/2, stop/1]).

%% expose for dev use
-export([start/0, stop/0, start_deps/0]).

%% config
-export([get_env/1, get_env/2, set_env/2,
	 datastore/0, datastore_opts/0,
	 log/0, log_opts/0,
	 llq_opts/0, update_opts/0]).

%% zone management
-export([load_zone/1, reload_zone/1, delete_zone/1, zone_loaded/1]).

%% querying
-export([get_zone/1, get_key/1]).

%% llq
-export([new_llq/3, msg_llq/2]).

%% logging
-export([log/2]).

-define(APP_DEPS, [sasl, lager, crypto, public_key, dns]).

%%%===================================================================
%%% API
%%%===================================================================

start(_StartType, _StartArgs) ->
    case start_deps() of
	ok ->
	    dnsxd_sup:start_link();
	{error, {App, Error}} ->
	    lager:critical("Failed to start application ~p:~n~p~n", [App, Error]),
	    throw({app_start_failed,App})
    end.

stop(_) -> ok.

start() ->
    ok = start_deps(),
    application:start(dnsxd).

stop() -> application:stop(dnsxd).

start_deps() ->
    dnsxd_lib:ensure_apps_started(?APP_DEPS).

get_env(Key) ->
    get_env(Key, undefined).

get_env(Key, Default) ->
    case application:get_env(dnsxd, Key) of
	undefined when Default =/= undefiend ->
	    {ok, Default};
	undefined -> undefined;
	{ok, _Value} = Result -> Result
    end.

set_env(Key, Value) -> application:set_env(dnsxd, Key, Value).

datastore() ->
    case get_env(datastore_mod) of
	{ok, Datastore} when is_atom(Datastore) -> Datastore;
	_ -> throw({bad_config, datastore_mod})
    end.

log() ->
    case get_env(log_mod) of
	{ok, Logger} when is_atom(Logger) -> Logger;
	_ -> datastore()
    end.

llq_opts() ->
    case dnsxd:get_env(llq_opts) of
	{ok, List} when is_list(List) -> List;
	undefined -> {ok, []};
	_ -> throw({bad_config, llq_opts})
    end.

update_opts() ->
    case dnsxd:get_env(update_opts) of
	{ok, List} when is_list(List) -> List;
	undefined -> [];
	_ -> throw({bad_config, update_opts})
    end.

datastore_opts() ->
    case dnsxd:get_env(datastore_opts) of
	{ok, List} when is_list(List) -> List;
	undefined -> [];
	_ -> throw({bad_config, datastore_opts})
    end.

log_opts() ->
    case dnsxd:get_env(log_opts) of
	{ok, List} when is_list(List) -> List;
	undefined -> [];
	_ -> throw({bad_config, log_opts})
    end.

zone_loaded(ZoneName) -> dnsxd_ds_server:zone_loaded(ZoneName).

get_zone(ZoneName) -> dnsxd_ds_server:get_zone(ZoneName).

load_zone(Zone) -> dnsxd_ds_server:load_zone(Zone).

reload_zone(Zone) -> dnsxd_ds_server:reload_zone(Zone).

delete_zone(ZoneName) -> dnsxd_ds_server:delete_zone(ZoneName).

get_key(KeyName) -> dnsxd_ds_server:get_key(KeyName).

new_llq(Pid, MsgCtx, Msg) -> dnsxd_llq_manager:new_llq(Pid, MsgCtx, Msg).

msg_llq(MsgCtx, Msg) -> dnsxd_llq_manager:msg_llq(MsgCtx, Msg).

log(MsgCtx, Props) -> dnsxd_log:log(MsgCtx, Props).
