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
-module(dnsxd_couch_ds_server).
-include("dnsxd_couch.hrl").
-behaviour(gen_server).

%% API
-export([start_link/0]).

-export([dnsxd_admin_zone_list/0, dnsxd_admin_get_zone/1,
	 dnsxd_admin_change_zone/2, dnsxd_dns_update/6,
	 dnsxd_reload_zones/1]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3]).

-define(SERVER, ?MODULE).

-define(CHANGES_FILTER, <<?DNSXD_COUCH_DESIGNDOC "/dnsxd_couch_zone">>).

-record(state, {db_ref, db_seq, db_lost = false, reload = []}).

%%%===================================================================
%%% API
%%%===================================================================

start_link() ->
    DsOpts = dnsxd:datastore_opts(),
    Timeout = proplists:get_value(init_timeout, DsOpts, 60000),
    Opts = [{timeout, Timeout}],
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], Opts).

dnsxd_dns_update(MsgCtx, Key, ZoneName, ?DNS_CLASS_IN, PreReqs, Updates) ->
    DsOpts = dnsxd:datastore_opts(),
    Attempts = proplists:get_value(update_attempts, DsOpts, 10),
    update_zone_int(Attempts, MsgCtx, Key, ZoneName, PreReqs, Updates);
dnsxd_dns_update(_, _, _, _, _, _) -> refused.

dnsxd_admin_zone_list() ->
    case dnsxd_couch_lib:get_db() of
	{ok, DbRef} ->
	    ViewName = {?DNSXD_COUCH_DESIGNDOC, "dnsxd_couch_zone"},
	    Fun = fun({Props}, Acc) ->
			  ZoneName = get_value(<<"id">>, Props),
			  Enabled = get_value(<<"key">>, Props),
			  [{ZoneName, Enabled}|Acc]
		  end,
	    case couchbeam_view:fold(Fun, [], DbRef, ViewName) of
		Zones when is_list(Zones) -> {ok, Zones};
		{error, _Reason} = Error -> Error
	    end;
	{error, _Reason} = Error -> Error
    end.

dnsxd_admin_get_zone(ZoneName) ->
    case dnsxd_couch_zone:get(ZoneName) of
	{ok, #dnsxd_couch_zone{} = CouchZone} ->
	    Zone = to_dnsxd_zone(CouchZone, true),
	    {ok, Zone};
	{error, _Reason} = Error -> Error
    end.

dnsxd_admin_change_zone(ZoneName, [_|_] = Changes) when is_binary(ZoneName) ->
    dnsxd_couch_zone:change(ZoneName, Changes).

dnsxd_reload_zones(ZoneNames) ->
    FailFun = fun(ZoneName, Reason) ->
		      Fmt = "Failed to reload ~s after DB failure:~n~p",
		      lager:error(Fmt, [ZoneName, Reason]),
		      ok = dnsxd:delete_zone(ZoneName),
		      gen_server:cast(?SERVER, {reload, ZoneName})
	      end,
    case dnsxd_couch_lib:get_db() of
	{ok, DbRef} ->
	    Fun = fun(ZoneName) ->
			  case dnsxd_couch_zone:get(DbRef, ZoneName) of
			      {ok, #dnsxd_couch_zone{enabled = true} = Zone} ->
				  ok = insert_zone(Zone);
			      {ok, #dnsxd_couch_zone{enabled = false}} ->
				  ok = dnsxd:delete_zone(ZoneName);
			      {error, Reason} when Reason =:= deleted orelse
						   Reason =:= not_found orelse
						   Reason =:= not_zone ->
				  ok = dnsxd:delete_zone(ZoneName);
			      {error, Reason} -> FailFun(ZoneName, Reason)
			  end
		  end,
	    lists:foreach(Fun, ZoneNames);
	{error, Reason} ->
	    [ FailFun(ZoneName, Reason) || ZoneName <- ZoneNames ]
    end,
    ok.

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

init([]) ->
    {ok, DbRef, DbSeq} = dnsxd_couch_lib:setup_monitor(?CHANGES_FILTER),
    State = #state{db_ref = DbRef, db_seq = DbSeq},
    ok = init_load_zones(),
    {ok, State}.

handle_call(Request, _From, State) ->
    lager:notice("Stray call:~n~p~nState:~n~p~n", [Request, State]),
    {noreply, State}.

handle_cast({reload, ZoneName}, #state{db_lost = false} = State) ->
    ok = spawn_zone_reloader(ZoneName),
    {noreply, State};
handle_cast({reload, ZoneName}, #state{reload = List} = State) ->
    List0 = case lists:member(ZoneName, List) of
		true -> List;
		false -> [ZoneName|List]
	    end,
    NewState = State#state{reload = List0},
    {noreply, NewState};
handle_cast(Msg, State) ->
    lager:notice("Stray cast:~n~p~nState:~n~p~n", [Msg, State]),
    {noreply, State}.

handle_info({Ref, done} = Message, #state{db_ref = Ref, db_seq = Seq,
					  db_lost = Lost, reload = ReloadList
					 } = State) ->
    case dnsxd_couch_lib:setup_monitor(?CHANGES_FILTER, Seq) of
	{ok, NewRef, Seq} ->
	    if Lost -> lager:alert("Reconnected db poll");
	       true -> ok end,
	    ok = spawn_zone_reloader(ReloadList),
	    State0 = State#state{db_ref = NewRef, db_lost = false, reload = []},
	    {noreply, State0};
	{error, Error} ->
	    lager:alert("Unable to reconnect db poll:~n"
			"~p~n"
			"Retrying in 30 seconds", [Error]),
	    {ok, _} = timer:send_after(30000, self(), Message),
	    {noreply, State}
    end;
handle_info({error, Ref, _Seq, Error},
	    #state{db_ref = Ref, db_lost = false} = State) ->
    lager:alert("Lost db connection:~n~p", [Error]),
    {ok, _} = timer:send_after(0, self(), {Ref, done}),
    NewState = State#state{db_lost = true},
    {noreply, NewState};
handle_info({error, _Ref, _Seq, Error}, #state{db_lost = true} = State) ->
    Fmt = "Got db connection error when db connection already lost:~n~p",
    lager:error(Fmt, [Error]),
    {noreply, State};
handle_info({change, Ref, {Props}}, #state{db_ref = Ref} = State) ->
    Name = proplists:get_value(<<"id">>, Props),
    NewSeq = proplists:get_value(<<"seq">>, Props),
    NewState = State#state{db_seq = NewSeq},
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
    lager:info(Message, [Name]),
    {noreply, NewState};
handle_info(_Msg, State) -> {stop, stray_message, State}.

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

update_zone_int(Attempts, MsgCtx, Key, ZoneName, PreReqs, Updates) ->
    LockId = {{?MODULE, ZoneName}, self()},
    BeforeLock = now(),
    true = global:set_lock(LockId, [node()]),
    F = fun() ->
		dnsxd_couch_zone:update(MsgCtx, Key, ZoneName, PreReqs, Updates)
	end,
    Result = case timer:now_diff(now(), BeforeLock) < 2000000 of
		 true -> update_zone(F, Attempts);
		 false -> timeout
	     end,
    true = global:del_lock(LockId),
    Result.

update_zone(_Fun, 0) -> ?DNS_RCODE_SERVFAIL;
update_zone(Fun, Attempts) ->
    NewAttempts = Attempts - 1,
    case Fun() of
	{ok, Rcode} -> Rcode;
	{error, disabled} -> refused;
	{error, conflict} -> update_zone(Fun, NewAttempts);
	{error, _Error} ->
	    %% todo: log the error
	    update_zone(Fun, NewAttempts)
    end.

init_load_zones() ->
    {ok, DbRef} = dnsxd_couch_lib:get_db(),
    ViewName = {?DNSXD_COUCH_DESIGNDOC, "dnsxd_couch_zone"},
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
    Opts = [{<<"key">>, <<"true">>}],
    ok = couchbeam_view:foreach(Fun, DbRef, ViewName, Opts).

couch_tk_to_dnsxd_key(#dnsxd_couch_tk{id = Id,
				      name = Name,
				      secret = Secret,
				      enabled = Enabled,
				      dnssd_only = DnssdOnly}) ->
    #dnsxd_tsig_key{id = Id,
		    name = Name,
		    secret = base64:decode(Secret),
		    enabled = Enabled,
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
    #dnsxd_dnssec_key{id = Id, incept = Incept, expire = Expire, alg = Alg,
		      ksk = KSK, key = Key}.

to_dnsxd_zone(#dnsxd_couch_zone{} = Zone) -> to_dnsxd_zone(Zone, false).

to_dnsxd_zone(#dnsxd_couch_zone{name = Name,
				enabled = Enabled,
				rr = CouchRRs,
				axfr_enabled = AXFREnabled,
				axfr_hosts = AXFRHosts,
				tsig_keys = CouchTSIGKeys,
				soa_param = CouchSP,
				dnssec_enabled = DNSSEC,
				dnssec_keys = CouchDNSSECKeys,
				dnssec_nsec3_param = NSEC3Param,
				dnssec_siglife = SigLife}, KeepDisabled) ->
    RRs = [ to_dnsxd_rr(RR) || RR <- CouchRRs ],
    Serials = dnsxd_couch_lib:get_serials(CouchRRs),
    TSIGKeys = [ couch_tk_to_dnsxd_key(Key)
		 || Key <- CouchTSIGKeys,
		    Key#dnsxd_couch_tk.enabled orelse KeepDisabled,
		    not is_integer(Key#dnsxd_couch_tk.tombstone) ],
    DNSSECKeys = [ couch_dk_to_dnsxd_key(Key)
		   || Key <- CouchDNSSECKeys,
		      not is_integer(Key#dnsxd_couch_dk.tombstone) ],
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
    #dnsxd_zone{name = Name,
		enabled = Enabled,
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

get_value(Key, List) -> {Key, Value} = lists:keyfind(Key, 1, List), Value.

spawn_zone_reloader(ZoneName) when is_binary(ZoneName) ->
    spawn_zone_reloader([ZoneName]);
spawn_zone_reloader([_|_] = ZoneNames) ->
    spawn_link(fun() -> ?MODULE:dnsxd_reload_zones(ZoneNames) end),
    ok;
spawn_zone_reloader([]) -> ok.
