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

-define(SERVER, ?MODULE).
-define(DEFAULT_UDP_KEEPALIVE, 29).

-record(state, {id,
		zonename,
		q,
		dnssec = false,
		msgctx,
		pmsg,
		pmsg_sent,
		pmsg_attempts = 0,
		answers,
		active = false,
		expires,
		expires_relative,
		zone_changed = false,
		timer_ref,
		transport_pid,
		transport_ref
	       }).

%%%===================================================================
%%% API
%%%===================================================================

start_link(Pid, Id, ZoneName, MsgCtx, Q, DNSSEC) ->
    gen_server:start_link(?MODULE, [Pid, Id, ZoneName, MsgCtx, Q, DNSSEC], []).

handle_msg(Pid, MsgCtx, Message) ->
    gen_server:call(Pid, {MsgCtx, Message}).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

init([Pid, Id, ZoneName, MsgCtx, Q, DNSSEC]) ->
    LLQOpts = dnsxd:llq_opts(),
    MaxLength = proplists:get_value(max_length, LLQOpts, 7200),
    TimerRef = erlang:send_after(MaxLength * 1000, self(), expire),
    StateBase = #state{id = Id,
		       q = Q,
		       dnssec = DNSSEC,
		       zonename = ZoneName,
		       msgctx = MsgCtx,
		       timer_ref = TimerRef},
    State = case dnsxd_op_ctx:protocol(MsgCtx) of
		udp -> StateBase;
		_ ->
		    Ref = erlang:monitor(process, Pid),
		    StateBase#state{transport_pid = Pid,
				    transport_ref = Ref}
	    end,
    {ok, State}.

handle_call({MsgCtx,
	     #dns_message{
	       qc = 1, adc = 1,
	       questions = [#dns_query{} = Q],
	       additional = [#dns_optrr{data = [#dns_opt_llq{
						   opcode = setup,
						   leaselife = ReqLength,
						   id = 0} = LLQ]} = OptRR]
	      } = Msg}, _From, #state{id = Id, timer_ref = Ref} = State) ->
    ok = cancel_timer(Ref),
    Length = new_leaselength(ReqLength),
    RespLLQ = LLQ#dns_opt_llq{id = Id, leaselife = Length},
    RespOptRR = OptRR#dns_optrr{dnssec = State#state.dnssec, data = [RespLLQ]},
    Reply = Msg#dns_message{qr = true, additional = [RespOptRR]},
    ReplyBin = dns:encode_message(Reply),
    ok = dnsxd_op_ctx:send(MsgCtx, ReplyBin),
    Expires = dns:unix_time() + Length,
    NewRef = erlang:send_after(Length * 1000, self(), expire),
    NewState = State#state{q = Q, expires = Expires, timer_ref = NewRef,
			   msgctx = MsgCtx},
    {reply, ok, NewState};
handle_call({MsgCtx,
	     #dns_message{
	       qc = 1, adc = 1,
	       questions = [#dns_query{} = Q],
	       additional = [#dns_optrr{data = [#dns_opt_llq{
						   opcode = setup,
						   leaselife = ReqLength,
						   id = Id} = LLQ]} = OptRR]
	      } = Msg}, _From, #state{id = Id, q = Q} = State) ->
    ZoneName = State#state.zonename,
    ok = cancel_timer(State#state.timer_ref),
    Length = new_leaselength(ReqLength),
    RespLLQ = LLQ#dns_opt_llq{id = Id, leaselife = Length},
    RespOptRR = OptRR#dns_optrr{dnssec = State#state.dnssec, data = [RespLLQ]},
    {Answers, Changes} = answer(ZoneName, Q, State#state.dnssec),
    AnC = length(Changes),
    Reply = Msg#dns_message{qr = true, anc = AnC, answers = Changes,
			    additional = [RespOptRR]},
    ReplyBin = dns:encode_message(Reply),
    ok = dnsxd_op_ctx:send(MsgCtx, ReplyBin),
    Expires = dns:unix_time() + Length,
    NewState = set_timer(State#state{q = Q, msgctx = MsgCtx, expires = Expires,
				     answers = Answers, active = true}),
    {reply, ok, NewState};
handle_call({MsgCtx,
	     #dns_message{
	       qc = 1, adc = 1,
	       questions = [#dns_query{} = Q],
	       additional = [#dns_optrr{data = [#dns_opt_llq{
						   opcode = refresh,
						   leaselife = 0,
						   id = Id}]}]
	      } = Msg}, _From, #state{id = Id, q = Q} = State) ->
    ok = cancel_timer(State#state.timer_ref),
    Reply = Msg#dns_message{qr = true},
    ReplyBin = dns:encode_message(Reply),
    ok = dnsxd_op_ctx:send(MsgCtx, ReplyBin),
    {stop, normal, ok, State};
handle_call({MsgCtx,
	     #dns_message{
	       qc = 1, adc = 1,
	       questions = [#dns_query{} = Q],
	       additional = [#dns_optrr{data = [#dns_opt_llq{
						   opcode = refresh,
						   leaselife = ReqLength,
						   id = Id} = LLQ]} = OptRR]
	      } = Msg}, _From,
	    #state{id = Id, q = Q, pmsg = undefined} = State) ->
    ok = cancel_timer(State#state.timer_ref),
    Length = new_leaselength(ReqLength),
    RespLLQ = LLQ#dns_opt_llq{id = Id, leaselife = Length},
    RespOptRR = OptRR#dns_optrr{dnssec = State#state.dnssec, data = [RespLLQ]},
    Reply = Msg#dns_message{qr = true, additional = [RespOptRR]},
    ReplyBin = dns:encode_message(Reply),
    ok = dnsxd_op_ctx:send(MsgCtx, ReplyBin),
    NewRef = erlang:send_after(Length * 1000, self(), expire),
    NewState = set_timer(State#state{timer_ref = NewRef, msgctx = MsgCtx}),
    {reply, ok, NewState};
handle_call({MsgCtx,
	     #dns_message{
	       qc = 1, adc = 1,
	       questions = [#dns_query{} = Q],
	       additional = [#dns_optrr{data = [#dns_opt_llq{
						   opcode = refresh,
						   leaselife = ReqLength,
						   id = Id} = LLQ]} = OptRR]
	      } = Msg}, _From, #state{id = Id, q = Q} = State) ->
    Length = new_leaselength(ReqLength),
    RespLLQ = LLQ#dns_opt_llq{id = Id, leaselife = Length},
    RespOptRR = OptRR#dns_optrr{dnssec = State#state.dnssec, data = [RespLLQ]},
    Reply = Msg#dns_message{qr = true, additional = [RespOptRR]},
    ReplyBin = dns:encode_message(Reply),
    ok = dnsxd_op_ctx:send(MsgCtx, ReplyBin),
    NewState = set_timer(State#state{msgctx = MsgCtx}),
    {reply, ok, NewState};
handle_call({MsgCtx,
	     #dns_message{
	       id = MsgId, qc = 1, adc = 1,
	       questions = [#dns_query{} = Q],
	       additional = [#dns_optrr{data = [#dns_opt_llq{opcode = event,
							     id = Id}]}]}},
	    _From, #state{id = Id, q = Q, zone_changed = false,
			  pmsg = #dns_message{id = MsgId}} = State) ->
    NewState = set_timer(State#state{msgctx = MsgCtx, pmsg = undefined}),
    {reply, ok, NewState};
handle_call({MsgCtx,
	     #dns_message{
	       id = MsgId, qc = 1, adc = 1,
	       questions = [#dns_query{} = Q],
	       additional = [#dns_optrr{data = [#dns_opt_llq{opcode = event,
							     id = Id}]}]}},
	    _From, #state{id = Id, q = Q, zone_changed = true,
			  pmsg = #dns_message{id = MsgId}} = State) ->
    {ok, NewState} = send_update(State#state{msgctx = MsgCtx,
					     pmsg = undefined,
					     zone_changed = false}),
    {reply, ok, NewState};
handle_call(Request, _From, State) ->
    ?DNSXD_ERR("Stray call:~n~p", [Request]),
    {noreply, State}.

handle_cast(Msg, State) ->
    ?DNSXD_ERR("Stray cast:~n~p", [Msg]),
    {noreply, State}.

handle_info({'DOWN', Ref, _Type, _Object,_Info},
	    #state{transport_ref = Ref} = State) ->
    ?DNSXD_INFO("Transport down. Stopping"),
    {stop, normal, State};
handle_info(zone_changed, #state{active = false} = State) ->
    {noreply, State};
handle_info(zone_changed, #state{active = true, pmsg = undefined} = State) ->
    {ok, NewState} = send_update(State),
    {noreply, NewState};
handle_info(zone_changed, #state{active = true} = State) ->
    NewState = State#state{zone_changed = true},
    {noreply, NewState};
handle_info(resend_update, #state{} = State) ->
    case send_update(State) of
	terminate -> {stop, normal, State};
	{ok, NewState} -> {noreply, NewState}
    end;
handle_info(keepalive, #state{pmsg = undefined} = State) ->
    {ok, NewState} = send_empty_update(State),
    {noreply, NewState};
handle_info(keepalive, State) ->
    NewState = set_timer(State),
    {noreply, NewState};
handle_info(expire, #state{expires = Expires} = State) ->
    case dns:unix_time() > Expires of
	true ->
	    {stop, normal, State};
	false ->
	    NewState = set_timer(State),
	    {noreply, NewState}
    end;
handle_info(Info, State) ->
    ?DNSXD_ERR("Stray message:~n~p", [Info]),
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

answer(ZoneName, Query, DNSSEC) ->
    answer(ZoneName, Query, DNSSEC, []).

answer(ZoneName, Query, DNSSEC, LastAns) ->
    Zone = dnsxd:get_zone(ZoneName),
    {_RC, Ans, _Au, _Ad} = dnsxd_query:answer(Zone, Query, DNSSEC),
    CurAns = [ RR#dns_rr{ttl = undefined} || RR <- Ans ],
    Added = [ RR#dns_rr{ttl = 1} || RR <- lists:subtract(CurAns, LastAns) ],
    Removed =[ RR#dns_rr{ttl = -1} || RR <- lists:subtract(LastAns, CurAns) ],
    {CurAns, Added ++ Removed}.

cancel_timer(Ref) when is_reference(Ref) ->
    _ = erlang:cancel_timer(Ref),
    ok;
cancel_timer(_) -> ok.

new_leaselength(ReqLength) when is_integer(ReqLength) ->
    Opts = dnsxd:llq_opts(),
    MaxLength = proplists:get_value(max_length, Opts, 7200),
    MinLength = proplists:get_value(min_length, Opts, 900),
    if ReqLength > MaxLength -> MaxLength;
       ReqLength < MinLength -> MinLength;
       true -> MaxLength end.

send_empty_update(#state{id = LLQId,
			 q = Q,
			 pmsg = undefined,
			 msgctx = MsgCtx,
			 active = true,
			 timer_ref = Ref,
			 expires = Expires} = State) ->
    ok = cancel_timer(Ref),
    LeaseLife = Expires - dns:unix_time(),
    LLQ = #dns_opt_llq{opcode = event, errorcode = noerror, id = LLQId,
		       leaselife = LeaseLife},
    OptRR = #dns_optrr{dnssec = State#state.dnssec, data = [LLQ]},
    Msg = #dns_message{qr = true, aa = true,
		       qc = 1, questions = [Q],
		       adc = 1, additional = [OptRR]},
    ok =  dnsxd_op_ctx:to_wire(MsgCtx, Msg),
    NewRef = erlang:send_after(2 * 1000, self(), resend_update),
    NewState = State#state{pmsg = Msg,
			   pmsg_sent = dns:unix_time(),
			   pmsg_attempts = 1,
			   timer_ref = NewRef},
    {ok, NewState}.

send_update(#state{id = LLQId,
		   zonename = ZoneName,
		   q = Q,
		   pmsg = undefined,
		   msgctx = MsgCtx,
		   active = true,
		   timer_ref = Ref,
		   answers = Answers,
		   expires = Expires} = State) ->
    ok = cancel_timer(Ref),
    {NewAnswers, Changes} = answer(ZoneName, Q, State#state.dnssec, Answers),
    LeaseLife = Expires - dns:unix_time(),
    LLQ = #dns_opt_llq{opcode = event, errorcode = noerror, id = LLQId,
		       leaselife = LeaseLife},
    OptRR = #dns_optrr{dnssec = State#state.dnssec, data = [LLQ]},
    Msg = #dns_message{qr = true, aa = true,
		       qc = 1, questions = [Q],
		       anc = length(Changes), answers = Changes,
		       adc = 1, additional = [OptRR]},
    ok =  dnsxd_op_ctx:to_wire(MsgCtx, Msg),
    NewRef = erlang:send_after(2 * 1000, self(), resend_update),
    NewState = State#state{pmsg = Msg,
			   pmsg_sent = dns:unix_time(),
			   pmsg_attempts = 1,
			   answers = NewAnswers,
			   timer_ref = NewRef},
    {ok, NewState};
send_update(#state{msgctx = MsgCtx,
		   pmsg = #dns_message{} = Msg,
		   pmsg_attempts = Attempts,
		   timer_ref = Ref} = State)
  when Attempts =:= 1 orelse Attempts =:= 2 ->
    ok = cancel_timer(Ref),
    ok =  dnsxd_op_ctx:to_wire(MsgCtx, Msg),
    NewRef = erlang:send_after(Attempts * 2 * 1000, self(), resend_update),
    NewState = State#state{pmsg_sent = dns:unix_time(),
			   pmsg_attempts = Attempts + 1,
			   timer_ref = NewRef},
    {ok, NewState};
send_update(#state{pmsg_attempts = 3}) -> terminate.

set_timer(#state{msgctx = MsgCtx, timer_ref = OldRef,
		 expires = Expires} = State) ->
    ok = cancel_timer(OldRef),
    ExpireRel = Expires - dns:unix_time(),
    NewRef = case dnsxd_op_ctx:protocol(MsgCtx) of
		 udp ->
		     Timeout = get_udp_timeout(),
		     erlang:send_after(Timeout, self(), keepalive);
		 _ -> erlang:send_after(ExpireRel * 1000, self(), expire)
	     end,
    State#state{timer_ref = NewRef}.

get_udp_timeout() ->
    Opts = dnsxd:llq_opts(),
    case proplists:get_value(udp_keepalive, Opts) of
	TimeoutSecs when is_integer(TimeoutSecs) andalso TimeoutSecs >= 10 ->
	    TimeoutSecs * 1000;
	_ ->
	    ?DEFAULT_UDP_KEEPALIVE * 1000
    end.
