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
-module(dnsxd_llq_manager).
-include("dnsxd_internal.hrl").
-behaviour(gen_server).

%% API
-export([start_link/1, new_llq/3, msg_llq/2, list_llq/0, list_llq/1,
	 zone_changed/1]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3]).

-define(SERVER, ?MODULE).

-define(TAB_LLQ, dnsxd_ds_llq).

-record(state, {sup_pid, serialchange_tab, llq_count = 0}).
-record(llq_ref, {id, pid, monitor_ref, zonename, q}).
-record(serialchange, {zonename, ref, next_serial}).

%%%===================================================================
%%% API
%%%===================================================================

start_link(SupPid) when is_pid(SupPid) ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, SupPid, []).

new_llq(Pid, MsgCtx, #dns_message{} = Msg) ->
    gen_server:call(?SERVER, {new_llq, Pid, MsgCtx, Msg}).

msg_llq(MsgCtx, #dns_message{
	  additional = [#dns_optrr{data = [#dns_opt_llq{id = Id}]}]
	 } = Msg) ->
    case ets:lookup(?TAB_LLQ, Id) of
	[#llq_ref{id = Id, pid = Pid}] when is_pid(Pid) ->
	    dnsxd_llq_server:handle_msg(Pid, MsgCtx, Msg);
	[] -> {error, nosuchllq}
    end.

list_llq() ->
    MS = {#llq_ref{id = '$1', zonename = '$2', q = '$3', _ = '_'},
	  [], [{{'$1', '$2', '$3'}}] },
    ets:select(?TAB_LLQ, [MS]).

list_llq(ZoneName) when is_binary(ZoneName) ->
    MS = {#llq_ref{id = '$1', zonename = ZoneName, q = '$3', _ = '_'},
	  [], [{{'$1', ZoneName, '$3'}}] },
    ets:select(?TAB_LLQ, [MS]).

zone_changed(ZoneName) ->
    MS = {#llq_ref{zonename = ZoneName, pid = '$1', _ = '_'}, [], ['$1']},
    Pids = [?SERVER|ets:select(?TAB_LLQ, [MS])],
    [ gen_server:cast(Pid, {zone_changed, ZoneName}) || Pid <- Pids ],
    ok.

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

init(SupPid) when is_pid(SupPid) ->
    ?TAB_LLQ = ets:new(?TAB_LLQ, [named_table, {keypos, #llq_ref.id}]),
    SerialChangeTab = ets:new(?MODULE, [{keypos, #serialchange.zonename}]),
    {ok, #state{sup_pid = SupPid, serialchange_tab = SerialChangeTab}}.

handle_call({new_llq, ClientPid, MsgCtx,
	     #dns_message{questions = [#dns_query{} = Q],
			  additional = [#dns_optrr{dnssec = ClientDNSSEC}|_]
			 } = Msg}, _From,
	    #state{sup_pid = SupPid,
		   serialchange_tab = SerialChangeTab,
		   llq_count = Count} = State) ->
    case servfull(State) of
	true -> {reply, {ok, servfull}, State};
	false ->
	    case start_new_llq(SupPid, Q, ClientPid, MsgCtx, ClientDNSSEC) of
		{ok, Id, ZoneName, LLQPid} ->
		    MonitorRef = erlang:monitor(process, LLQPid),
		    LLQRef = #llq_ref{id = Id,
				      pid = LLQPid,
				      monitor_ref = MonitorRef,
				      zonename = ZoneName,
				      q = Q},
		    true = ets:insert(?TAB_LLQ, LLQRef),
		    ok = update_serial_tracking(SerialChangeTab, ZoneName),
		    ok = dnsxd_llq_server:handle_msg(LLQPid, MsgCtx, Msg),
		    NewState = State#state{llq_count = Count + 1},
		    {reply, ok, NewState};
		bad_zone -> {reply, {ok, bad_zone}, State}
	    end
    end;
handle_call(Request, _From, State) ->
    ?DNSXD_ERR("Stray call:~n~p~nState:~n~p~n", [Request, State]),
    {noreply, State}.

handle_cast({zone_changed, ZoneName}, #state{serialchange_tab = Tab} = State) ->
    ok = update_serial_tracking(Tab, ZoneName),
    {noreply, State};
handle_cast(Msg, State) ->
    ?DNSXD_ERR("Stray cast:~n~p~nState:~n~p~n", [Msg, State]),
    {noreply, State}.

handle_info({new_serial, ZoneName}, State) ->
    ok = zone_changed(ZoneName),
    {noreply, State};
handle_info({'DOWN', _Ref, process, Pid, _Reason},
	    #state{llq_count = LLQCount} = State) ->
    MatchSpec = {#llq_ref{id = '$1', pid = Pid, _ = '_'}, [], ['$1']},
    NewState = case ets:select(?TAB_LLQ, [MatchSpec]) of
		   [Id] ->
		       true = ets:delete(?TAB_LLQ, Id),
		       State#state{llq_count = LLQCount - 1};
		   [] -> State
	       end,
    {noreply, NewState};
handle_info(Info, State) ->
    ?DNSXD_ERR("Stray message:~n~p~nState:~n~p~n", [Info, State]),
    {noreply, State}.

terminate(_Reason, _State) -> ok.

code_change(_OldVsn, State, _Extra) -> {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

servfull(#state{llq_count = Count}) ->
    Opts = dnsxd:llq_opts(),
    MaxLLQ = proplists:get_value(max_llq, Opts, 500),
    Count >= MaxLLQ.

start_new_llq(SupPid, #dns_query{name = NameM} = Q, ClientPid, MsgCtx,
	      ClientDNSSEC) ->
    Name = dns:dname_to_lower(NameM),
    ZoneRef = dnsxd_ds_server:zone_ref_for_name(Name),
    Refuse = case ZoneRef of
		 undefined -> true;
		 ZoneRef -> dnsxd_ds_server:is_cut(ZoneRef, Name)
	     end,
    case Refuse of
	true -> bad_zone;
	false ->
	    Id = new_id(),
	    ZoneName = dnsxd_ds_server:zonename_from_ref(ZoneRef),
	    ZoneDNSSEC = dnsxd_ds_server:is_dnssec_zone(ZoneRef),
	    DoDNSSEC = ClientDNSSEC andalso ZoneDNSSEC,
	    Spec = {Id, {dnsxd_llq_server, start_link,
			 [ClientPid, Id, ZoneName, MsgCtx, Q, DoDNSSEC]},
		    temporary, 2000, worker, [dnsxd_llq_server]},
	    {ok, LLQPid} = supervisor:start_child(SupPid, Spec),
	    {ok, Id, ZoneName, LLQPid};
	undefined -> bad_zone
    end.

new_id() ->
    Now = dns:unix_time(),
    Rand = crypto:rand_uniform(0, 16#FFFFFFFF),
    <<Id:64>> = <<Now:32, Rand:32>>,
    case ets:member(?TAB_LLQ, Id) of
	true -> new_id();
	false -> Id
    end.

update_serial_tracking(Tab, ZoneName) ->
    ok = remove_serial_tracking(Tab, ZoneName),
    case zone_has_clients(ZoneName) of
	true -> ok = add_serial_tracking(Tab, ZoneName);
	false -> ok
    end.

remove_serial_tracking(Tab, ZoneName) ->
    case ets:lookup(Tab, ZoneName) of
	[] -> ok;
	[#serialchange{zonename = ZoneName, ref = Ref}] ->
	    ok = dnsxd_lib:cancel_timer(Ref),
	    ets:delete(Tab, ZoneName),
	    ok
    end.

add_serial_tracking(Tab, ZoneName) ->
    Now = dns:unix_time(),
    case dnsxd_ds_server:next_serial(ZoneName) of
	Serial when Serial > Now ->
	    Msg = {new_serial, ZoneName},
	    Ref = timer:send_after((Serial - Now) * 1000, ?SERVER, Msg),
	    Entry = #serialchange{zonename = ZoneName,
				  ref = Ref,
				  next_serial = Serial},
	    ets:insert(Tab, Entry),
	    ok;
	_ -> ok
    end.

zone_has_clients(ZoneName) ->
    MS = {#llq_ref{zonename = ZoneName, _ = '_'}, [], [{{true}}]},
    '$end_of_table' =/= ets:select(?TAB_LLQ, [MS], 1).
