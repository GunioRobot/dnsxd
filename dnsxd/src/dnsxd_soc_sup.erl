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
-module(dnsxd_soc_sup).
-include("dnsxd.hrl").
-behaviour(supervisor).

%% API
-export([start_link/1]).

%% supervisor callbacks
-export([init/1]).

-define(SERVER, ?MODULE).

%%%===================================================================
%%% API
%%%===================================================================

start_link(#dnsxd_if_spec{protocol = Protocol} = IfSpec) ->
    Return = {ok, SupPid} = supervisor:start_link(?MODULE, []),
    ReqSupSpec = {dnsxd_soc_req_sup,
		  {dnsxd_soc_req_sup, start_link, [IfSpec]},
		  permanent, 5000, supervisor, [dnsxd_soc_req_sup]},
    {ok, ReqSupPid} = supervisor:start_child(SupPid, ReqSupSpec),
    {Module, Type} = case Protocol of
			 tcp -> {dnsxd_soc_tcp_sup, supervisor};
			 udp -> {dnsxd_soc_udp, worker}
		     end,
    SocSpec = {Module, {Module, start_link, [IfSpec, ReqSupPid]},
	       permanent, 5000, Type, [Module]},
    {ok, _Pid} = supervisor:start_child(SupPid, SocSpec),
    Return.

%%%===================================================================
%%% supervisor callbacks
%%%===================================================================

init([]) -> {ok, {{one_for_all, 0, 1},[]}}.
