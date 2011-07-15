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
-module(dnsxd_shell_admin_lib).

-export([zone_list/1, get_zone/2, change_zone/3]).

zone_list(Node) when is_atom(Node) andalso node() =/= Node ->
    rpc(Node, zone_list, [Node]);
zone_list(Node) when node() =:= Node ->
    Datastore = dnsxd:datastore(),
    Datastore:dnsxd_admin_zone_list().

get_zone(Node, ZoneName)
  when is_atom(Node) andalso node() =/= Node andalso is_binary(ZoneName) ->
    rpc(Node, get_zone, [Node, ZoneName]);
get_zone(Node, ZoneName) when node() =:= Node andalso is_binary(ZoneName) ->
    Datastore = dnsxd:datastore(),
    Datastore:dnsxd_admin_get_zone(ZoneName).

change_zone(Node, ZoneName, [_|_] = Changes)
  when is_atom(Node) andalso node() =/= Node andalso is_binary(ZoneName) ->
    rpc(Node, change_zone, [Node, ZoneName, Changes]);
change_zone(Node, ZoneName, [_|_] = Changes)
    when node() =:= Node andalso is_binary(ZoneName) ->
    Datastore = dnsxd:datastore(),
    Datastore:dnsxd_admin_change_zone(ZoneName, Changes).

rpc(Node, Fun, Args) -> rpc:call(Node, ?MODULE, Fun, Args).
