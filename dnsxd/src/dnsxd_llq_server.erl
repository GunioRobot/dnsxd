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
-module(dnsxd_llq_server).
-include("dnsxd.hrl").
-behaviour(gen_server).

%% API
-export([start_link/6, handle_msg/3]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3]).

-define(DEFAULT_MAX_LEASE_LIFE, 7200).
-define(DEFAULT_MIN_LEASE_LIFE, 1800).
-define(DEFAULT_KEEPALIVE, 29).

-record(state, {id,
		zonename,
		msgctx,
		q,
		do_dnssec,
		active = false,
		answers = [],
		expire,
		expire_ref,
		protocol,
		protocol_pid,
		protocol_ref,
		zone_changed = false,
		pending_events = [],
		pending_ref,
		keepalive_ref
	       }).
-record(event, {id, changes, send_count, last_sent = dns:unix_time()}).

%%%===================================================================
%%% API
%%%===================================================================

start_link(Pid, Id, ZoneName, MsgCtx, Q, DoDNSSEC) ->
    Args = [Pid, Id, ZoneName, MsgCtx, Q, DoDNSSEC],
    gen_server:start_link(?MODULE, Args, []).

handle_msg(Pid, MsgCtx,
	   #dns_message{
		  qc = 1, adc = 1,
		  questions = [#dns_query{}],
		  additional = [#dns_optrr{data = [#dns_opt_llq{} = LLQ]}]
		 } = Msg) ->
    handle_msg(Pid, MsgCtx, Msg, LLQ).

handle_msg(Pid, MsgCtx, #dns_message{} = Msg, #dns_opt_llq{errorcode = Error})
  when Error =/= noerror -> gen_server:call(Pid, {error, MsgCtx, Msg});
handle_msg(Pid, MsgCtx, #dns_message{} = Msg,
	   #dns_opt_llq{opcode = setup, id = 0}) ->
    gen_server:call(Pid, {setup_request, MsgCtx, Msg});
handle_msg(Pid, MsgCtx, #dns_message{} = Msg,
	   #dns_opt_llq{opcode = setup}) ->
    gen_server:call(Pid, {setup_response, MsgCtx, Msg});
handle_msg(Pid, MsgCtx, #dns_message{} = Msg,
	   #dns_opt_llq{opcode = refresh, leaselife = 0}) ->
    gen_server:call(Pid, {cancel_lease, MsgCtx, Msg});
handle_msg(Pid, MsgCtx, #dns_message{} = Msg,
	   #dns_opt_llq{opcode = refresh}) ->
    gen_server:call(Pid, {renew_lease, MsgCtx, Msg});
handle_msg(Pid, MsgCtx, #dns_message{} = Msg,
	   #dns_opt_llq{opcode = event}) ->
    gen_server:call(Pid, {event, MsgCtx, Msg}).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

init([Pid, Id, ZoneName, MsgCtx, Q, DoDNSSEC]) ->
    {Proto, ProtoPid, ProtoRef} = case dnsxd_op_ctx:protocol(MsgCtx) of
				      udp -> {udp, undefined, undefined};
				      tcp ->
					  {tcp, Pid,
					   erlang:monitor(process, Pid)}
				  end,
    {_LeaseLife, State} = set_lease_life(?DEFAULT_MAX_LEASE_LIFE,
					 #state{id = Id,
						zonename = ZoneName,
						msgctx = MsgCtx,
						q = Q,
						do_dnssec = DoDNSSEC,
						protocol = Proto,
						protocol_pid = ProtoPid,
						protocol_ref = ProtoRef}),
    {ok, State}.

handle_call({error, _MsgCtx, Msg}, _From, #state{} = State) ->
    ?DNSXD_ERR("LLQ client reported error:~nMessage:~n~p~nState:~p~n",
	       [Msg, State]),
    {stop, normal, ok, State};
handle_call({setup_request, MsgCtx, Msg}, _From,
	    #state{active = false, id = Id, do_dnssec = DoDNSSEC} = State) ->
    #dns_opt_llq{leaselife = ReqLeaseLife} = ReqLLQ = extract_llq(Msg),
    {LeaseLife, NewState} = set_lease_life(ReqLeaseLife, State),
    RespLLQ = ReqLLQ#dns_opt_llq{id = Id, leaselife = LeaseLife},
    ok = dnsxd_op_ctx:reply(MsgCtx, Msg, [{dnssec, DoDNSSEC}, RespLLQ]),
    {reply, ok, NewState};
handle_call({setup_response, MsgCtx, Msg}, _From,
	    #state{active = false, id = Id, do_dnssec = DoDNSSEC} = State) ->
    #dns_opt_llq{id = Id, leaselife = ReqLeaseLife} = ReqLLQ = extract_llq(Msg),
    {LeaseLife, NewState0} = set_lease_life(ReqLeaseLife,
					    State#state{active = true}),
    RespLLQ = ReqLLQ#dns_opt_llq{id = Id, leaselife = LeaseLife},
    ok = dnsxd_op_ctx:reply(MsgCtx, Msg, [{dnssec, DoDNSSEC}, RespLLQ]),
    NewState1 = send_changes(NewState0),
    {reply, ok, NewState1};
handle_call({cancel_lease, MsgCtx, Msg}, _From,
	    #state{active = true, id = Id, do_dnssec = DoDNSSEC} = State) ->
    #dns_opt_llq{id = Id, leaselife = 0} = LLQ = extract_llq(Msg),
    ok = dnsxd_op_ctx:reply(MsgCtx, Msg, [{dnssec, DoDNSSEC}, LLQ]),
    {stop, normal, ok, State};
handle_call({renew_lease, MsgCtx, Msg}, _From,
	   #state{active = true, id = Id, do_dnssec = DoDNSSEC} = State) ->
    #dns_opt_llq{id = Id, leaselife = ReqLeaseLife} = ReqLLQ = extract_llq(Msg),
    {LeaseLife, NewState0} = set_lease_life(ReqLeaseLife, State),
    RespLLQ = ReqLLQ#dns_opt_llq{leaselife = LeaseLife},
    ok = dnsxd_op_ctx:reply(MsgCtx, Msg, [{dnssec, DoDNSSEC}, RespLLQ]),
    NewState1 = set_keepalive(NewState0),
    {reply, ok, set_keepalive(NewState1)};
handle_call({event, _MsgCtx, #dns_message{id = EventId}}, _From,
	    #state{active = true, zone_changed = ZoneChanged} = State) ->
    NewState0 = ack_event(EventId, State),
    NewState1 = case ZoneChanged of
		    false -> NewState0;
		    true -> send_changes(NewState0#state{zone_changed = false})
		end,
    NewState2 = set_keepalive(NewState1),
    {reply, ok, NewState2};
handle_call(Request, _From, State) ->
    ?DNSXD_ERR("Stray call:~n~p~nState:~n~p~n", [Request, State]),
    {noreply, State}.

handle_cast({zone_changed, ZoneName},
	    #state{zonename = ZoneName, active = true,
		   pending_events = Events} = State) ->
    NewState = case Events =:= [] of
		   true -> send_changes(State);
		   false -> State#state{zone_changed = true}
	       end,
    {noreply, NewState};
handle_cast({zone_changed, ZoneName}, #state{zonename = ZoneName} = State) ->
    {noreply, State};
handle_cast(Msg, State) ->
    ?DNSXD_ERR("Stray cast:~n~p~nState:~n~p~n", [Msg, State]),
    {noreply, State}.

handle_info({'DOWN', Ref, _Type, _Object,_Info},
	    #state{protocol_ref = Ref} = State) ->
    ?DNSXD_INFO("Transport down. Stopping"),
    {stop, normal, State};
handle_info(expire, #state{expire = Expire} = State) ->
    case dns:unix_time() >= Expire of
	true -> {stop, normal, State};
	false ->
	    NewState = set_expire_timer(State),
	    {noreply, NewState}
    end;
handle_info(keepalive, #state{pending_events = []} = State) ->
    NewState = send_changes(State),
    {noreply, NewState};
handle_info(keepalive, #state{} = State) ->
    {noreply, State};
handle_info(resend, #state{} = State) ->
    case resend_changes(State) of
	{ok, missing_ack} ->
	    ?DNSXD_INFO("Client not-responding - exiting"),
	    {stop, normal, State};
	{ok, #state{} = NewState} -> {noreply, NewState}
    end;
handle_info(Info, State) ->
    ?DNSXD_ERR("Stray message:~n~p~nState:~n~p~n", [Info, State]),
    {noreply, State}.

terminate(_Reason, _State) -> ok.

code_change(_OldVsn, State, _Extra) -> {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

extract_llq(
  #dns_message{additional = [#dns_optrr{data = [#dns_opt_llq{} = LLQ]}]}
 ) -> LLQ.

set_lease_life(RequestedLeaseLife, #state{} = State) ->
    MaxLeaseLife = max_lease_life(),
    MinLeaseLife = min_lease_life(),
    GrantedLeaseLife = if RequestedLeaseLife > MaxLeaseLife -> MaxLeaseLife;
			  RequestedLeaseLife < MinLeaseLife -> MinLeaseLife;
			  true -> RequestedLeaseLife end,
    NewExpire = dns:unix_time() + GrantedLeaseLife,
    NewState = set_expire_timer(State#state{expire = NewExpire}),
    {GrantedLeaseLife, NewState}.

set_expire_timer(#state{expire = Expire, expire_ref = Ref} = State)
  when is_integer(Expire) ->
    ok = cancel_timer(Ref),
    ExpireIn = Expire - dns:unix_time(),
    case ExpireIn > 0 of
	true ->
	    NewRef = erlang:send_after(ExpireIn * 1000, self(), expire),
	    State#state{expire_ref = NewRef};
	false ->
	    NewRef = erlang:send_after(0, self(), expire),
	    State#state{expire_ref = NewRef}
    end.

set_keepalive(#state{keepalive_ref = Ref, pending_events = []} = State) ->
    ok = cancel_timer(Ref),
    NewRef = erlang:send_after(?DEFAULT_KEEPALIVE * 1000, self(), keepalive),
    State#state{keepalive_ref = NewRef};
set_keepalive(#state{keepalive_ref = Ref} = State) ->
    ok = cancel_timer(Ref),
    State#state{keepalive_ref = undefined}.

resend_changes(#state{pending_events = Events, pending_ref = Ref} = State) ->
    ok = cancel_timer(Ref),
    Now = dns:unix_time(),
    resend_changes(Now, State#state{pending_events = []}, Events).

resend_changes(_Now, #state{} = State, []) ->
    NewState = set_resend_timer(State),
    {ok, NewState};
resend_changes(Now, #state{}, [#event{send_count = 3, last_sent = LastSent}|_])
  when (LastSent + 8) < Now ->
    {ok, missing_ack};
resend_changes(Now, #state{id = LLQId, q = Q, msgctx = MsgCtx,
			   do_dnssec = DoDNSSEC, expire = Expire,
			   pending_events = Checked} = State,
	       [#event{send_count = Count, last_sent = LastSent,
		       changes = Changes}|Unchecked])
  when (LastSent + Count * 2) < Now ->
    LeaseLife = Expire - dns:unix_time(),
    LLQ = #dns_opt_llq{opcode = event, errorcode = noerror, id = LLQId,
		       leaselife = LeaseLife},
    OptRR = #dns_optrr{dnssec = DoDNSSEC, data = [LLQ]},
    Msg = #dns_message{qr = true, aa = true,
		       qc = 1, questions = [Q],
		       anc = length(Changes), answers = Changes,
		       adc = 1, additional = [OptRR]},
    ok =  dnsxd_op_ctx:to_wire(MsgCtx, Msg),
    NewEvent = #event{id = Msg#dns_message.id, changes = Changes,
		      send_count = Count + 1, last_sent = Now},
    NewState = State#state{pending_events = [NewEvent|Checked]},
    resend_changes(Now, NewState, Unchecked);
resend_changes(Now, #state{pending_events = Checked} = State,
	       [Event|Unchecked]) ->
    NewState = State#state{pending_events = [Event|Checked]},
    resend_changes(Now, NewState, Unchecked).

send_changes(#state{id = LLQId, zonename = ZoneName, q = Q, msgctx = MsgCtx,
		    do_dnssec = DoDNSSEC, answers = Ans, expire = Expire,
		    pending_ref = PendingRef, pending_events = Events
		   } = State) ->
    ok = cancel_timer(PendingRef),
    {NewAns, Changes} = changes(ZoneName, Q, DoDNSSEC, Ans),
    LeaseLife = Expire - dns:unix_time(),
    NewEvents = send_changes(Events, MsgCtx, LLQId, Q, DoDNSSEC, Changes,
			     LeaseLife),
    NewState = State#state{answers = NewAns, pending_events = NewEvents},
    set_resend_timer(NewState).

send_changes(Events, MsgCtx, LLQId, Q, DoDNSSEC, Changes, LeaseLife) ->
    MsgId = send_changes_mkid(Events),
    LLQ = #dns_opt_llq{opcode = event, errorcode = noerror, id = LLQId,
		       leaselife = LeaseLife},
    OptRR = #dns_optrr{dnssec = DoDNSSEC, data = [LLQ]},
    MsgBase = #dns_message{id = MsgId, qr = true, aa = true,
			   qc = 1, questions = [Q],
			   adc = 1, additional = [OptRR]},
    case send_changes(Events, MsgCtx, MsgBase, Changes) of
	{NewEvents, []} -> NewEvents;
	{NewEvents, LeftoverChanges} ->
	    send_changes(NewEvents, MsgCtx, LLQId, Q, DoDNSSEC,
			 LeftoverChanges, LeaseLife)
    end.

send_changes(Events, MsgCtx, MsgBase, Changes) ->
    send_changes(Events, MsgCtx, MsgBase, Changes, []).

send_changes(Events, MsgCtx, MsgBase, Changes, Leftover) ->
    ChangesLen = length(Changes),
    Msg = MsgBase#dns_message{anc = ChangesLen, answers = Changes},
    case dnsxd_op_ctx:to_wire(MsgCtx, Msg, false) of
	ok ->
	    NewEvent = #event{id = Msg#dns_message.id, changes = Changes,
			      send_count = 1},
	    NewEvents = [NewEvent|Events],
	    {NewEvents, Leftover};
	truncate ->
	    {NewChanges, [DroppedRR]} = lists:split(ChangesLen - 1, Changes),
	    NewLeftover = [DroppedRR|Leftover],
	    send_changes(Events, MsgCtx, MsgBase, NewChanges, NewLeftover)
    end.

send_changes_mkid(Events) ->
    Id = dns:random_id(),
    case lists:keymember(Id, #event.id, Events) of
	true -> send_changes_mkid(Events);
	false -> Id
    end.

set_resend_timer(#state{pending_ref = Ref, pending_events = Events} = State) ->
    ok = cancel_timer(Ref),
    NextResend = next_resend(Events),
    NewRef = erlang:send_after(NextResend * 1000, self(), resend),
    State#state{pending_ref = NewRef}.

next_resend(Events) -> next_resend(dns:unix_time(), Events, 8).

next_resend(_Now, [], Seconds) -> Seconds;
next_resend(Now, [#event{send_count = Count,
			 last_sent = LastSent}|Events], Seconds)
  when ((LastSent + (Count * 2)) - Now) < Seconds ->
    NewSeconds = ((LastSent + (Count * 2)) - Now),
    case NewSeconds =< 0 of
	true -> 0;
	false -> next_resend(Now, Events, NewSeconds)
    end;
next_resend(Now, [_|Events], Seconds) -> next_resend(Now, Events, Seconds).

changes(ZoneName, Query, DNSSEC, LastAns) ->
    Zone = dnsxd:get_zone(ZoneName),
    {_RC, Ans, _Au, _Ad} = dnsxd_query:answer(Zone, Query, DNSSEC),
    CurAns = [ RR#dns_rr{ttl = undefined} || RR <- Ans ],
    Added = [ RR#dns_rr{ttl = 1} || RR <- CurAns -- LastAns ],
    Removed =[ RR#dns_rr{ttl = -1} || RR <- LastAns -- CurAns ],
    {CurAns, Added ++ Removed}.

cancel_timer(Ref) when is_reference(Ref) ->
    _ = erlang:cancel_timer(Ref), ok;
cancel_timer(_) -> ok.

ack_event(EventId, #state{pending_events = Events} = State) ->
    case lists:keytake(EventId, #event.id, Events) of
	{value, _Event, NewEvents} -> State#state{pending_events = NewEvents};
	false -> State
    end.

max_lease_life() ->
    proplists:get_value(max_length, llq_opts(), ?DEFAULT_MAX_LEASE_LIFE).

min_lease_life() ->
    proplists:get_value(min_length, llq_opts(), ?DEFAULT_MIN_LEASE_LIFE).

llq_opts() ->
    case dnsxd:get_env(llq_opts) of
	{ok, List} when is_list(List) -> List;
	undefined -> {ok, []};
	_ -> throw({bad_config, llq_opts})
    end.
