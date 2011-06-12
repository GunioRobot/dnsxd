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
-module(dnsxd_couch_lib).
-include("dnsxd_couch.hrl").

%% API
-export([get_db/0, db_exists/0, get_serials/1]).

-define(SERVER, dnsxd_couch).
-define(DB_PREFIX, "dnsxd_couch").

%%%===================================================================
%%% API
%%%===================================================================

get_db() ->
    Server = get_server(),
    DbName = get_db_name(),
    couchbeam:open_or_create_db(Server, DbName, []).

db_exists() ->
    Server = get_server(),
    DbName = get_db_name(),
    couchbeam:db_exists(Server, DbName).

get_serials(RR) ->
    All = lists:foldl(fun get_serials/2, sets:new(), RR),
    lists:sort(sets:to_list(All)).

get_serials(#dnsxd_couch_rr{incept = Incept, expire = Expire}, Acc)
  when is_integer(Incept) andalso is_integer(Expire) ->
    sets:add_element(Expire, sets:add_element(Incept, Acc));
get_serials(#dnsxd_couch_rr{incept = Incept}, Acc)
  when is_integer(Incept) -> sets:add_element(Incept, Acc);
get_serials(#dnsxd_couch_rr{expire = Expire}, Acc)
  when is_integer(Expire) -> sets:add_element(Expire, Acc).

%%% Internal functions

get_server() ->
    CfgOpts = dnsxd:datastore_opts(),
    Host = proplists:get_value(host, CfgOpts, "localhost"),
    Port = proplists:get_value(port, CfgOpts, 5984),
    Prefix = proplists:get_value(prefix, CfgOpts, ""),
    Options = proplists:get_value(options, CfgOpts, []),
    couchbeam:server_connection(Host, Port, Prefix, Options).

get_db_name() ->
    CfgOpts = dnsxd:datastore_opts(),
    proplists:get_value(database, CfgOpts, "dnsxd_zones").
