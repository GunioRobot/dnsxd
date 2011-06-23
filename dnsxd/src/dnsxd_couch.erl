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
-module(dnsxd_couch).
-include("dnsxd_couch.hrl").
-behaviour(gen_server).

%% API
-export([start_link/0]).

-export([update_zone/6, log/1]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3]).

-define(SERVER, ?DNSXD_COUCH_SERVER).

-define(APP_DEPS, [sasl, ibrowse, couchbeam]).

-record(state, {db_ref, db_seq, db_lost = false,
		compact_ref, compact_finished, compact_pid}).

%%%===================================================================
%%% API
%%%===================================================================

start_link() ->
    DsOpts = dnsxd:datastore_opts(),
    Timeout = proplists:get_value(init_timeout, DsOpts, 60000),
    case dnsxd_lib:ensure_apps_started(?APP_DEPS) of
	ok ->
	    Opts = [{timeout, Timeout}],
	    gen_server:start_link({local, ?SERVER}, ?MODULE, [], Opts);
	{error, _Reason} = Error -> Error
    end.

update_zone(MsgCtx, Key, ZoneName, ?DNS_CLASS_IN, PreReqs, Updates) ->
    DsOpts = dnsxd:datastore_opts(),
    Attempts = proplists:get_value(update_attempts, DsOpts, 10),
    update_zone_int(Attempts, MsgCtx, Key, ZoneName, PreReqs, Updates);
update_zone(_, _, _, _, _, _) -> refused.

log(Props) ->
    Doc = {[{dnsxd_couch_rec, <<"dnsxd_couch_log">>}|Props]},
    {ok, DbRef} = dnsxd_couch_lib:get_db(),
    {ok, _} = couchbeam:save_doc(DbRef, Doc).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

init([]) ->
    case dnsxd_couch_lib:db_exists() of
	true -> ok;
	false -> ok = dnsxd_couch_app:install()
    end,
    {ok, DbRef, DbSeq} = setup_monitor(),
    State = #state{db_ref = DbRef, db_seq = DbSeq},
    ok = init_load_zones(),
    {ok, State}.

handle_call(compact_finished, _From, #state{} = State) ->
    ?DNSXD_INFO("Database compact completed"),
    NewState = State#state{compact_pid = undefined,
			   compact_finished = dns:unix_time()},
    {reply, ok, NewState};
handle_call(Request, _From, State) ->
    ?DNSXD_ERR("Stray call:~n~p~nState:~n~p~n", [Request, State]),
    {noreply, State}.

handle_cast(Msg, State) ->
    ?DNSXD_ERR("Stray cast:~n~p~nState:~n~p~n", [Msg, State]),
    {noreply, State}.

handle_info(wrote_zone, #state{compact_ref = Ref,
			       compact_finished = Finished,
			       compact_pid = Pid} = State) ->
    Now = dns:unix_time(),
    ok = cancel_timer(Ref),
    Running = is_pid(Pid) andalso is_process_alive(Pid),
    RunRecently = is_integer(Finished) andalso (Now - Finished) < 900,
    if not Running andalso RunRecently ->
	    %% machines often register services in a flurry;
	    %% not compacting immediately following a write
	    %% should avoid running compact under load
	    NewRef = erlang:send_after(10 * 1000, self(), run_compact),
	    NewState = State#state{compact_ref = NewRef},
	    {noreply, NewState};
       not Running andalso not RunRecently ->
	    %% avoid consistent writes preventing compact from running
	    self() ! run_compact,
	    {noreply, State};
       true -> {noreply, State}
    end;
handle_info(run_compact, #state{compact_pid = OldPid} = State) ->
    case is_pid(OldPid) andalso is_process_alive(OldPid) of
	true ->
	    {noreply, State};
	false ->
	    Pid = start_compact(),
	    NewState = State#state{compact_pid = Pid},
	    {noreply, NewState}
    end;
handle_info({Ref, {last_seq, NewSeq}}, #state{db_ref = Ref} = State) ->
    NewState = State#state{db_seq = NewSeq},
    {noreply, NewState};
handle_info({Ref, done} = Message,
	    #state{db_ref = Ref, db_seq = Seq, db_lost = Lost} = State) ->
    case setup_monitor(Seq) of
	{ok, NewRef, Seq} ->
	    if Lost -> ?DNSXD_INFO("Reconnected db poll");
	       true -> ok end,
	    {noreply, State#state{db_ref = NewRef, db_lost = false}};
	{error, Error} ->
	    ?DNSXD_ERR("Unable to reconnect db poll:~n"
		       "~p~n"
		       "Retrying in 30 seconds", [Error]),
	    {ok, _} = timer:send_after(30000, self(), Message),
	    {noreply, State}
    end;
handle_info({Ref, {error, Error}}, #state{db_ref = Ref} = State) ->
    ?DNSXD_ERR("Lost db connection:~n~p", [Error]),
    {ok, _} = timer:send_after(0, self(), {Ref, done}),
    NewState = State#state{db_lost = true},
    {noreply, NewState};
handle_info({Ref, {change, {Props}}}, #state{db_ref = Ref} = State) ->
    Name = proplists:get_value(<<"id">>, Props),
    Exists = dnsxd:zone_loaded(Name),
    Message = case load_zone(Name) of
		  {error, not_zone} ->
		      dnsxd:delete_zone(Name),
		      "Doc ~s is not a zone.";
		  {error, not_found} ->
		      dnsxd:delete_zone(Name),
		      "Zone ~s deleted.";
		  {error, deleted} ->
		      dnsxd:delete_zone(Name),
		      "Zone ~s deleted.";
		  {error, disabled} ->
		      dnsxd:delete_zone(Name),
		      "Zone ~s disabled.";
		  ok when Exists ->
		      "Zone ~s reloaded.";
		  ok ->
		      "Zone ~s loaded."
	      end,
    ?DNSXD_INFO(Message, [Name]),
    {noreply, State};
handle_info({Ref, Msg}, #state{db_ref = Ref} = State) ->
    ?DNSXD_ERR("Stray message concerning db_ref: ~n~p~n", [Msg]),
    {noreply, State};
handle_info(Info, State) ->
    ?DNSXD_ERR("Stray message:~n~p~nState:~n~p~n", [Info, State]),
    {noreply, State}.

terminate(_Reason, _State) -> ok.

code_change(_OldVsn, State, _Extra) -> {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

load_zone(ZoneName) ->
    case dnsxd_couch_zone:get(ZoneName) of
	{ok, #dnsxd_couch_zone{} = Zone} -> insert_zone(Zone);
	{error, _Reason} = Error -> Error
    end.

insert_zone(#dnsxd_couch_zone{enabled = true} = CouchZone) ->
    Zone = to_dnsxd_zone(CouchZone),
    dnsxd:reload_zone(Zone);
insert_zone(#dnsxd_couch_zone{enabled = false}) -> {error, disabled}.

update_zone_int(0, _MsgCtx, _Key, _ZoneName, _PreReqs, _Updates) -> servfail;
update_zone_int(Attempts, MsgCtx, Key, ZoneName, PreReqs, Updates) ->
    NewAttempts = Attempts - 1,
    case dnsxd_couch_zone:update(MsgCtx, Key, ZoneName, PreReqs, Updates) of
	{ok, Rcode} -> Rcode;
	{error, disabled} -> refused;
	{error, conflict} ->
	    update_zone_int(NewAttempts, MsgCtx, Key, ZoneName, PreReqs,
			    Updates);
	{error, _Error} ->
	    %% todo: log the error
	    update_zone_int(NewAttempts, MsgCtx, Key, ZoneName, PreReqs,
			    Updates)
    end.

init_load_zones() ->
    {ok, DbRef} = dnsxd_couch_lib:get_db(),
    ViewName = {?DNSXD_COUCH_DESIGNDOC, "dnsxd_couch_zone"},
    {ok, InitView} = couchbeam:view(DbRef, ViewName, [{key, true}]),
    Fun = fun({Props}) ->
		  ZoneName = get_value(<<"id">>, Props),
		  case dnsxd_couch_zone:get(DbRef, ZoneName) of
		      {ok, #dnsxd_couch_zone{enabled = true} = Zone} ->
			  ok = insert_zone(Zone);
		      {ok, #dnsxd_couch_zone{enabled = false}} -> ok;
		      {error, deleted} -> ok;
		      {error, not_zone} -> ok
		  end
	  end,
    ok = couchbeam_view:foreach(InitView, Fun).

couch_tk_to_dnsxd_key(#dnsxd_couch_tk{id = Id,
				      name = Name,
				      secret = Secret,
				      dnssd_only = DnssdOnly}) ->
    #dnsxd_tsig_key{opaque_ds_id = Id,
		    name = Name,
		    secret = base64:decode(Secret),
		    dnssd_only = DnssdOnly}.

couch_dk_to_dnsxd_key(#dnsxd_couch_dk{id = Id, incept = Incept, expire = Expire,
				      alg = Alg, ksk = KSK,
				      data = #dnsxd_couch_dk_rsa{} = Data}) ->
    #dnsxd_couch_dk_rsa{e = E, n = N, d = D} = Data,
    Fun = fun(B64) ->
		  Bin = base64:decode(B64),
		  BinSize = byte_size(Bin),
		  <<BinSize:32, Bin/binary>>
	  end,
    Key = [ Fun(X) || X <- [E, N, D] ],
    #dnsxd_dnssec_key{ds_id = Id, incept = Incept, expire = Expire, alg = Alg,
		      ksk = KSK, key = Key}.

cancel_timer(Ref) when is_reference(Ref) -> _ = erlang:cancel_timer(Ref), ok;
cancel_timer(undefined) -> ok.

to_dnsxd_zone(#dnsxd_couch_zone{name = Name,
				rr = CouchRRs,
				axfr_enabled = AXFREnabled,
				axfr_hosts = AXFRHosts,
				tsig_keys = CouchTSIGKeys,
				soa_param = CouchSP,
				dnssec_enabled = DNSSEC,
				dnssec_keys = CouchDNSSECKeys,
				dnssec_nsec3_param = NSEC3Param,
				dnssec_siglife = SigLife}) ->
    RRs = [ to_dnsxd_rr(RR) || RR <- CouchRRs ],
    Serials = dnsxd_couch_lib:get_serials(CouchRRs),
    TSIGKeys = [ couch_tk_to_dnsxd_key(Key)
		 || Key <- CouchTSIGKeys,
		    Key#dnsxd_couch_tk.enabled,
		    not is_integer(Key#dnsxd_couch_tk.tombstone) ],
    DNSSECKeys = [ couch_dk_to_dnsxd_key(Key)
		   || Key <- CouchDNSSECKeys ],
    #dnsxd_couch_sp{mname = MName,
		    rname = RName,
		    refresh = Refresh,
		    retry = Retry,
		    expire = Expire,
		    minimum = Minimum} = CouchSP,
    SP = #dnsxd_soa_param{mname = MName,
			  rname = RName,
			  refresh = Refresh,
			  retry = Retry,
			  expire = Expire,
			  minimum = Minimum},
    NSEC3 = case NSEC3Param of
		#dnsxd_couch_nsec3param{salt = Salt, iter = Iter, alg = Alg} ->
		    #dnsxd_nsec3_param{hash = Alg, salt = Salt, iter = Iter};
		_ ->
		    undefined
	    end,
    #dnsxd_zone{opaque_ds_id = Name,
		name = Name,
		rr = RRs,
		serials = Serials,
		axfr_enabled = AXFREnabled,
		axfr_hosts = AXFRHosts,
		tsig_keys = TSIGKeys,
		soa_param = SP,
		dnssec_enabled = DNSSEC,
		dnssec_keys = DNSSECKeys,
		dnssec_siglife = SigLife,
		nsec3 = NSEC3}.

to_dnsxd_rr(#dnsxd_couch_rr{incept = Incept,
			    expire = Expire,
			    name = Name,
			    class = Class,
			    type = Type,
			    ttl = TTL,
			    data = Data}) ->
    #dnsxd_rr{incept = Incept,
	      expire = Expire,
	      name = Name,
	      class = Class,
	      type = Type,
	      ttl = TTL,
	      data = Data}.

setup_monitor() ->
    case dnsxd_couch_lib:get_db() of
	{ok, DbRef} ->
	    case couchbeam:db_info(DbRef) of
		{ok, {DbInfo}} ->
		    Since = get_value(<<"update_seq">>, DbInfo),
		    setup_monitor(DbRef, Since);
		{error, _Reason} = Error -> Error
	    end;
	{error, _Reason} = Error -> Error
    end.

setup_monitor(Since) ->
    case dnsxd_couch_lib:get_db() of
	{ok, DbRef} -> setup_monitor(DbRef, Since);
	{error, _Reason} = Error -> Error
    end.

setup_monitor(DbRef, Since) when is_tuple(DbRef) ->
    Opts = [{since, Since},
	    {feed, "continuous"},
	    {heartbeat, true},
	    {filter, ?DNSXD_COUCH_DESIGNDOC "/dnsxd_couch_zone"}],
    case couchbeam:changes_wait(DbRef, self(), Opts) of
	{ok, Ref} -> {ok, Ref, Since};
	{error, _Reason} = Error -> Error
    end.

start_compact() -> spawn(fun compact/0).

compact() ->
    case dnsxd_couch_lib:get_db() of
	{ok, DbRef} ->
	    case couchbeam:compact(DbRef) of
		ok ->
		    ok = gen_server:call(?SERVER, compact_finished, 60 * 1000);
		{error, Error} ->
		    ?DNSXD_ERR("Error compacting db:~n~p", [Error])
	    end;
	{error, Error} ->
	    ?DNSXD_ERR("Error getting db for compaction:~n~p", [Error])
    end.

get_value(Key, List) -> {Key, Value} = lists:keyfind(Key, 1, List), Value.
