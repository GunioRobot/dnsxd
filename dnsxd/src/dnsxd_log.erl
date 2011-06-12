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
-module(dnsxd_log).
-include("dnsxd.hrl").

%% API
-export([log/2, log/3]).

log(MsgCtx, Props) ->
    Src = dnsxd_op_ctx:src(MsgCtx),
    Dst = dnsxd_op_ctx:dst(MsgCtx),
    spawn(?MODULE, log, [Src, Dst, Props]).

log({SrcIP, SrcPort}, {DstIP, DstPort}, Props) ->
    NewProps = prepare_props([{time, dns:unix_time()},
			      {node, node()},
			      {src_ip, format_ip(SrcIP)},
			      {src_port, SrcPort},
			      {dst_ip, format_ip(DstIP)},
			      {dst_port, DstPort}
			      |Props]),
    Datastore = dnsxd:datastore(),
    Datastore:log(NewProps).

prepare_props(List) when is_list(List) ->
    lists:sort([ prepare_props(Prop) || Prop <- List ]);
prepare_props({K, V}) when is_atom(V) ->
    prepare_props({K, atom_to_binary(V, latin1)});
prepare_props({K, V}) when is_atom(K) ->
    prepare_props({atom_to_binary(K, latin1), V});
prepare_props({K, V} = Prop)
  when is_binary(K) andalso (is_integer(V) orelse is_binary(V)) -> Prop.

format_ip(Tuple) when is_tuple(Tuple) ->
    case list_to_binary(inet_parse:ntoa(Tuple)) of
	<<"::FFFF:", Bin/binary>> -> Bin;
	Bin -> Bin
    end.
