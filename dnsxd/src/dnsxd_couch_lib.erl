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
-export([get_db/1, get_serials/1]).

-define(SERVER, dnsxd_couch).
-define(DB_PREFIX, "dnsxd_couch").

%%%===================================================================
%%% API
%%%===================================================================

get_db(DbAtom)
  when DbAtom =:= local orelse DbAtom =:= import orelse DbAtom =:= export ->
    case dnsxd:datastore_opts() of
	{ok, CfgOpts} when is_list(CfgOpts) -> CfgOpts;
	_ -> CfgOpts = []
    end,
    Host = proplists:get_value(host, CfgOpts, "localhost"),
    Port = proplists:get_value(port, CfgOpts, 5984),
    Prefix = proplists:get_value(prefix, CfgOpts, ""),
    Options = proplists:get_value(options, CfgOpts, []),
    Server = couchbeam:server_connection(Host, Port, Prefix, Options),
    Databases = proplists:get_value(databases, CfgOpts, []),
    DefaultDbName = ?DB_PREFIX ++ atom_to_list(DbAtom),
    DbName = proplists:get_value(DbAtom, Databases, DefaultDbName),
    couchbeam:open_or_create_db(Server, DbName, []).

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
