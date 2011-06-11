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
-module(dnsxd_soc_server).
-include("dnsxd.hrl").
-behaviour(gen_server).

%% API
-export([start_link/1]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3]).

-define(SERVER, ?MODULE).
-define(DEFAULT_MIN_WORKERS, 16).
-define(DEFAULT_MAX_WORKERS, 1024).

-define(TCP_OPTS, [{backlog, 128},
		   {packet, 2},
		   {reuseaddr, true},
		   {keepalive, true},
		   binary]).

-record(state, {socket,
		ip,
		port,
		protocol,
		idle = [],
		idle_c = 0,
		active = [],
		active_c = 0,
		min_workers,
		max_workers}).

%%%===================================================================
%%% API
%%%===================================================================

start_link(#dnsxd_if_spec{} = IfSpec) ->
    gen_server:start_link(?MODULE, IfSpec, []).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

init(#dnsxd_if_spec{ip = IP,
		    port = Port,
		    protocol = Protocol} = IfSpec) ->
    process_flag(trap_exit, true),
    {ok, MinWorkers} = dnsxd:get_env(min_workers, ?DEFAULT_MIN_WORKERS),
    {ok, MaxWorkers} = dnsxd:get_env(max_workers, ?DEFAULT_MAX_WORKERS),
    case listen(IP, Port, Protocol) of
	{ok, Socket} ->
	    Workers = spawn_workers(MinWorkers, IP, Port, Protocol, Socket),
	    State = #state{socket = Socket,
			   ip = IP,
			   port = Port,
			   protocol = Protocol,
			   idle = Workers,
			   idle_c = length(Workers),
			   min_workers = MinWorkers,
			   max_workers = MaxWorkers},
	    {ok, State};
	{error, Reason} = Error ->
	    ?DNSXD_ERR("listen failed:~n~p~nArgs:~p~n", [Reason, IfSpec]),
	    {stop, Error}
    end.

handle_call(Request, _From, State) ->
    ?DNSXD_ERR("Stray call:~n~p~nState:~n~p~n", [Request, State]),
    {noreply, State}.

handle_cast(Msg, State) ->
    ?DNSXD_ERR("Stray cast:~n~p~nState:~n~p~n", [Msg, State]),
    {noreply, State}.

handle_info({'EXIT', Pid, _Reason}, #state{} = State) ->
    case remove_worker(Pid, State) of
	{ok, TmpState} ->
	    {ok, NewState} = ensure_min_workers(TmpState),
	    {noreply, NewState};
	{error, bad_pid} -> {noreply, State}
    end;
handle_info({loaded, _Pid}, #state{protocol = udp} = State) ->
    {ok, NewState} = add_worker(State),
    {noreply, NewState};
handle_info({accepted, Pid}, #state{protocol = tcp} = State) ->
    case activate_worker(Pid, State) of
	{ok, TmpState} ->
	    {ok, NewState} = ensure_min_workers(TmpState),
	    {noreply, NewState};
	{error, bad_pid} -> {noreply, State}
    end;
handle_info({udp, Socket, _, _, _} = Msg,
	    #state{socket = Socket, idle = [Worker|Workers]} = State) ->
    Worker ! {udp, self(), os:timestamp(), Msg},
    NewWorkers = Workers ++ [Worker],
    NewState = State#state{idle = NewWorkers},
    ok = inet:setopts(Socket, [{active, once}]),
    {noreply, NewState};
handle_info(Info, State) ->
    ?DNSXD_ERR("Stray message:~n~p~nState:~n~p~n", [Info, State]),
    {noreply, State}.

terminate(_Reason, _State) -> ok.

code_change(_OldVsn, State, _Extra) -> {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

listen(IP, Port, Protocol) when is_integer(Port) ->
    Opts = [{ip, IP}],
    listen(Port, Protocol, Opts);
listen(Port, udp, BaseOpts) ->
    Opts = [{active, once}, binary|BaseOpts],
    case gen_udp:open(Port, Opts) of
	{error, eacces} = ErrEacces  ->
	    case use_procket() of
		true ->
		    case procket_open(Port, udp, dgram) of
			{ok, Fd} ->
			    FdOpts = [{fd, Fd}|Opts],
			    gen_udp:open(Port, FdOpts);
			Error ->
			    {error, {procket_bind_failed, Error}}
		    end;
		false -> ErrEacces
	    end;
	Other -> Other
    end;
listen(Port, tcp, BaseOpts) ->
    Opts = ?TCP_OPTS ++ BaseOpts,
    case gen_tcp:listen(Port, Opts) of
	{error, eacces} = ErrEacces ->
	    case use_procket() of
		true ->
		    case procket_open(Port, tcp, stream) of
			{ok, Fd} ->
			    FdOpts = [{fd, Fd}|Opts],
			    gen_tcp:listen(Port, FdOpts);
			Error ->
			    {error, {procket_bind_failed, Error}}
		    end;
		false -> ErrEacces
	    end;
	Other -> Other
    end.

remove_worker(Pid, #state{active = Active,
			  active_c = ActiveC,
			  idle = Idle,
			  idle_c = IdleC} = State) ->
    case lists:delete(Pid, Active) of
	Active ->
	    case lists:delete(Pid, Idle) of
		Idle -> {error, bad_pid};
		NewIdle -> {ok, State#state{idle = NewIdle, idle_c = IdleC - 1}}
	    end;
	NewActive ->
	    {ok, State#state{active = NewActive, active_c = ActiveC - 1}}
    end.

activate_worker(Pid, #state{active = Active,
			    active_c = ActiveC,
			    idle = Idle,
			    idle_c = IdleC} = State) ->
    case lists:delete(Pid, Idle) of
	Idle -> {error, bad_pid};
	NewIdle ->
	    NewIdleC = IdleC - 1,
	    NewActive = [Pid|Active],
	    NewActiveC = ActiveC + 1,
	    NewState = State#state{active = NewActive,
				   active_c = NewActiveC,
				   idle = NewIdle,
				   idle_c = NewIdleC},
	    {ok, NewState}
    end.

add_worker(#state{ip = IP,
		  port = Port,
		  protocol = Protocol,
		  socket = Socket,
		  active_c = ActiveC,
		  idle = Idle,
		  idle_c = IdleC,
		  max_workers = MaxWorkers} = State)
  when (IdleC + ActiveC) > MaxWorkers ->
    New = spawn_workers(1, IP, Port, Protocol, Socket),
    NewIdleC = IdleC + 1,
    NewIdle = New ++ Idle,
    NewState = State#state{idle_c = NewIdleC, idle = NewIdle},
    {ok, NewState};
add_worker(#state{ip = IP,
		  port = Port,
		  protocol = Protocol,
		  max_workers = MaxWorkers} = State) ->
    ?DNSXD_INFO("~p:~p (~p) hit worker limit ~p~n",
		[IP, Port, Protocol, MaxWorkers]),
    {ok, State}.

ensure_min_workers(#state{ip = IP,
			  port = Port,
			  protocol = Protocol,
			  idle_c = IdleC,
			  active_c = ActiveC,
			  max_workers = MaxWorkers} = State)
  when MaxWorkers =< (IdleC + ActiveC) ->
    ?DNSXD_ERR("~p:~p (~p) hit worker limit ~p~n",
	       [IP, Port, Protocol, MaxWorkers]),
    {ok, State};
ensure_min_workers(#state{idle_c = IdleC, min_workers = MinWorkers} = State)
  when IdleC >= MinWorkers -> {ok, State};
ensure_min_workers(#state{ip = IP,
			  port = Port,
			  protocol = Protocol,
			  socket = Socket,
			  idle = Idle,
			  idle_c = IdleC,
			  min_workers = MinWorkers} = State) ->
    Add = MinWorkers - IdleC,
    NewIdleC = Add + IdleC,
    NewPids = spawn_workers(Add, IP, Port, Protocol, Socket),
    NewIdle = NewPids ++ Idle,
    {ok, State#state{idle = NewIdle, idle_c = NewIdleC}}.

spawn_workers(Num, IP, Port, Protocol, Socket) ->
    spawn_workers(Num, IP, Port, Protocol, Socket, []).
spawn_workers(0, _IP, _Port, _Protocol, _Socket, NewWorkers) -> NewWorkers;
spawn_workers(Num, IP, Port, Proto, Socket, Workers) ->
    {ok, Pid} = dnsxd_soc_fsm:start_link({IP, Port, Proto, Socket}),
    NewNum = Num - 1,
    NewWorkers = [Pid|Workers],
    spawn_workers(NewNum, IP, Port, Proto, Socket, NewWorkers).

use_procket() ->
    case dnsxd:get_env(procket) of
	{ok, Props} when is_list(Props) -> proplists:get_bool(enabled, Props);
	_ -> false
    end.

procket_open(Port, Proto, Type) ->
    {ok, Props} = dnsxd:get_env(procket),
    Progname = proplists:get_value(progname, Props, "procket"),
    procket:open(Port, [{progname, Progname}, {protocol, Proto}, {type, Type}]).
