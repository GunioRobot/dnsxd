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
-module(dnsxd_soc_fsm).
-include("dnsxd.hrl").
-behaviour(gen_fsm).

%% API
-export([start_link/1]).

%% gen_fsm callbacks
-export([init/1, handle_event/3, handle_sync_event/4, handle_info/3,
	 terminate/3, code_change/4]).

%% udp states
-export([udp_active/2, udp_active/3]).

%% tcp states
-export([tcp_accept/2, tcp_accept/3, tcp_active/2, tcp_active/3]).

-define(SERVER, ?MODULE).
-define(DEFAULT_TIMEOUT, 60).

-record(state, {parent,
		ip,
		port,
		protocol,
		socket,
		loaded = false,
		ctx}).

%%%===================================================================
%%% API
%%%===================================================================

start_link(Arg) when is_tuple(Arg) andalso tuple_size(Arg) =:= 4 ->
    gen_fsm:start_link(?MODULE, [{self(), Arg}], []).

%%%===================================================================
%%% gen_fsm callbacks
%%%===================================================================

init([{Pid, {IP, Port, Protocol, Socket}}]) ->
    NewState = #state{parent = Pid,
		      ip = IP,
		      port = Port,
		      protocol = Protocol,
		      socket = Socket},
    {NextState, Timeout} = case Protocol of
			       udp -> {udp_active, infinity};
			       tcp -> {tcp_accept, 0}
			   end,
    {ok, NextState, NewState, Timeout}.

udp_active(timeout, #state{loaded = true} = State) ->
    {next_state, udp_active, State#state{loaded = false}};
udp_active(timeout, #state{loaded = false} = State) ->
    {stop, normal, State}.

tcp_active(timeout, #state{socket = Socket} = State) ->
    ok = gen_tcp:close(Socket),
    {stop, normal, State}.

tcp_accept(timeout, #state{parent = Parent, socket = Socket} = State) ->
    case gen_tcp:accept(Socket, 2000) of
	{ok, NewSocket} ->
	    ok = inet:setopts(NewSocket, [{active, once}]),
	    Parent ! {accepted, self()},
	    NewState = State#state{socket = NewSocket},
	    Timeout = tcp_timeout(),
	    {next_state, tcp_active, NewState, Timeout};
	{error, timeout} ->
	    {next_state, tcp_accept, State, 0}
    end.

udp_active(Event, _From, State) ->
    ?DNSXD_ERR("Stray sync_send_event in state udp_active:~n~p", [Event]),
    {next_state, udp_active, State}.

tcp_active(Event, _From, State) ->
    ?DNSXD_ERR("Stray sync_send_event in state tcp_active:~n~p", [Event]),
    {next_state, tcp_active, State}.

tcp_accept(Event, _From, State) ->
    ?DNSXD_ERR("Stray sync_send_event in state tcp_accept:~n~p", [Event]),
    {next_state, tcp_accept, State}.

handle_event(Event, StateName, State) ->
    FMT = "Stray send_all_state_event in state ~s:~n~p",
    ?DNSXD_INFO(FMT, [StateName, Event]),
    {next_state, StateName, State}.

handle_sync_event(Event, _From, StateName, State) ->
    FMT = "Stray sync_send_all_state_event in state ~s:~n~p",
    ?DNSXD_INFO(FMT, [StateName, Event]),
    {next_state, StateName, State}.

handle_info({udp, Parent, Sent, {udp, Soc, _SrcIP, _SrcPort, _MsgBin} = Req},
	    udp_active, #state{socket = Soc, parent = Parent,
			       loaded = Loaded} = State) ->
    QueuedFor = timer:now_diff(os:timestamp(), Sent),
    {NewLoaded, Timeout} = if QueuedFor > 10000 % 10 ms
			      andalso Loaded =:= false ->
				   Parent ! {loaded, self()},
				   {true, 500};
			      Loaded -> {Loaded, 500};
			      true -> {Loaded, 2000} end,
    if QueuedFor > 1500000 -> % 1.5 seconds
	    NewState = State#state{loaded = NewLoaded},
	    {next_state, udp_active, NewState, 500};
       true ->
	    NewState = State#state{loaded = NewLoaded},
	    ok = dispatch_msgbin(Req, NewState),
	    {next_state, udp_active, NewState, Timeout}
    end;
handle_info({tcp, _Socket, _MsgBin} = Req, tcp_active,
	    #state{socket = Socket} = State) ->
    {ok, {NewState, Timeout}} = dispatch_msgbin(Req, State),
    ok = inet:setopts(Socket, [{active, once}]),
    {next_state, tcp_active, NewState, Timeout};
handle_info({tcp_closed, Socket}, tcp_active,
	    #state{socket = Socket} = State) ->
    {stop, normal, State};
handle_info(mod_timeout, tcp_active, #state{socket = Socket} = State) ->
    ok = gen_tcp:close(Socket),
    {stop, normal, State};
handle_info(Info, StateName, State) ->
    ?DNSXD_ERR("Stray message in state ~s:~n~p", [StateName, Info]),
    {next_state, StateName, State}.

terminate(_Reason, _StateName, _State) ->
    ok.

code_change(_OldVsn, StateName, State, _Extra) ->
    {ok, StateName, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

dispatch_msgbin({udp, Socket, SrcIP, SrcPort, MsgBin},
	#state{socket = Socket,
	       protocol = udp,
	       ip = DstIP,
	       port = DstPort,
	       ctx = undefined} = State) ->
    Context = dnsxd_op_ctx:new_udp(Socket, SrcIP, SrcPort, DstIP, DstPort),
    dispatch_msgbin(State, Context, MsgBin);
dispatch_msgbin({tcp, Socket, _MsgBin} = Req,
	     #state{socket = Socket,
		    protocol = tcp,
		    ip = DstIP,
		    port = DstPort,
		    ctx = undefined} = State) ->
    Context = dnsxd_op_ctx:new_tcp(Socket, DstIP, DstPort),
    NewState = State#state{ctx = Context},
    dispatch_msgbin(Req, NewState);
dispatch_msgbin({tcp, Socket, MsgBin},
	     #state{socket = Socket, ctx = Context} = State) ->
    dispatch_msgbin(State, Context, MsgBin).

dispatch_msgbin(#state{protocol = Protocol} = State, Context, MsgBin)
  when is_binary(MsgBin) ->
    ok = dnsxd_op:dispatch(Context, MsgBin),
    case Protocol of
	udp ->
	    ok;
	tcp ->
	    Timeout = tcp_timeout(),
	    {ok, {State, Timeout}}
    end.

tcp_timeout() ->
    case dnsxd:get_env(tcp_timeout) of
	{ok, TimeoutSecs}
	  when is_integer(TimeoutSecs) andalso TimeoutSecs > 0 ->
	    TimeoutSecs * 1000;
	_ ->
	    ?DEFAULT_TIMEOUT * 1000
    end.
