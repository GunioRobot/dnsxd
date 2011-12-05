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
-include("dnsxd_internal.hrl").

%% API
-export([log/1, log/2]).

-export([start_link/1]).

log(Proplist) when is_list(Proplist) ->
    {ok, _Pid} = supervisor:start_child(dnsxd_log_sup, [Proplist]),
    ok.

log(MsgCtx, Props0) when is_list(Props0) ->
    {SrcIP, SrcPort} = dnsxd_op_ctx:src(MsgCtx),
    {DstIP, DstPort} = dnsxd_op_ctx:dst(MsgCtx),
    Props1 = [{src_ip, SrcIP}, {src_port, SrcPort},
	      {dst_ip, DstIP}, {dst_port, DstPort}|Props0],
    log(Props1).

start_link(Props) ->
    Pid = spawn_link(fun() -> prepare_props(Props) end),
    {ok, Pid}.

prepare_props(Props0) when is_list(Props0) ->
    Props1 = [{time, dns:unix_time()}, {node, node()}|Props0],
    Props2 = lists:keysort(1, [prepare_prop(Prop) || Prop <- Props1]),
    Logger = dnsxd:log(),
    Logger:dnsxd_log(Props2).

prepare_prop({K, IP}) when K =:= src_ip orelse K =:= dst_ip ->
    prepare_prop({binary(K), dnsxd_lib:ip_to_txt(IP)});
prepare_prop({K, V}) when is_atom(V) -> prepare_prop({K, binary(V)});
prepare_prop({K, V}) when is_atom(K) -> prepare_prop({binary(K), V});
prepare_prop({K, V} = Prop)
  when is_binary(K) andalso (is_integer(V) orelse is_binary(V)) -> Prop.

binary(Atom) when is_atom(Atom) -> atom_to_binary(Atom, latin1).
