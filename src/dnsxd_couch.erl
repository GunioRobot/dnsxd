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

-export([update_zone/6]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3]).

-define(SERVER, ?DNSXD_COUCH_SERVER).

-define(APP_DEPS, [sasl, ibrowse, couchbeam]).

-record(state, {local_ref, local_seq, local_lost = false,
		import_ref, import_seq, import_lost = false,
		compact_ref, compact_finished, compact_pid}).

%%%===================================================================
%%% API
%%%===================================================================

start_link() ->
    {ok, DsOpts} = dnsxd:datastore_opts(),
    Timeout = proplists:get_value(init_timeout, DsOpts, 60000),
    case dnsxd_lib:ensure_apps_started(?APP_DEPS) of
	ok ->
	    Opts = [{timeout, Timeout}],
	    gen_server:start_link({local, ?SERVER}, ?MODULE, [], Opts);
	{error, Error} -> {error, Error}
    end.

update_zone(MsgCtx, Key, ZoneName, ?DNS_CLASS_IN, PreReqs, Updates) ->
    Now = os:timestamp(),
    update_zone(Now, 1, MsgCtx, Key, ZoneName, PreReqs, Updates);
update_zone(_, _, _, _, _, _) -> refused.

update_zone(_Started, Attempts, _MsgCtx, _Key, _ZoneName, _PreReq, _Updates)
  when Attempts > 10 -> servfail;
update_zone(Started, Attempts, MsgCtx, Key, ZoneName, PreReqs, Updates) ->
    ReqRunTime = timer:now_diff(os:timestamp(), Started),
    if ReqRunTime > 1000000 -> %% 1 second, make this a configurable option?
	    servfail;
       true ->
	    case
		dnsxd_couch_zone:update(MsgCtx, Key, ZoneName, PreReqs, Updates)
	    of
		{ok, Rcode} ->
		    Rcode;
		{error, conflict} ->
		    update_zone(Started, Attempts, MsgCtx, Key, ZoneName,
				PreReqs, Updates);
		{error, _Error} ->
		    %% todo: log the error
		    update_zone(Started, Attempts + 1, MsgCtx, Key, ZoneName,
				PreReqs, Updates)
	    end
    end.

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

init([]) ->
    {ok, LocalRef, LocalSeq} = setup_monitor(local),
    {ok, ImportRef, ImportSeq} = setup_monitor(import),
    State = #state{local_ref = LocalRef, import_ref = ImportRef,
		   local_seq = LocalSeq, import_seq = ImportSeq},
    ok = init_load_zones(local),
    ok = init_load_zones(import),
    {ok, State}.

handle_call(compact_finished, _From, #state{} = State) ->
    ?DNSXD_INFO("Database compact completed"),
    NewState = State#state{compact_pid = undefined,
			   compact_finished = dns:unix_time()},
    {reply, ok, NewState};
handle_call(Request, _From, State) ->
    ?DNSXD_ERR("Stray call:~n~p", [Request]),
    {noreply, State}.

handle_cast(Msg, State) ->
    ?DNSXD_ERR("Stray cast:~n~p", [Msg]),
    {noreply, State}.

handle_info(wrote_zone, #state{compact_ref = Ref,
			       compact_finished = Finished,
			       compact_pid = Pid} = State) ->
    Now = dns:unix_time(),
    ok = cancel_timer(Ref),
    Running = is_pid(Pid) andalso is_process_alive(Pid),
    RunRecently = is_integer(Finished) andalso (Now - Finished) < 60,
    if Running orelse RunRecently ->
	    {noreply, State};
       true ->
	    %% machines often register services in a flurry;
	    %% not compacting immediately following a write
	    %% should avoid running compact under load
	    NewRef = erlang:send_after(10 * 1000, self(), run_compact),
	    NewState = State#state{compact_ref = NewRef},
	    {noreply, NewState}
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
handle_info({Ref, {last_seq, NewSeq}}, #state{local_ref = Ref} = State) ->
    NewState = State#state{local_seq = NewSeq},
    {noreply, NewState};
handle_info({Ref, {last_seq, NewSeq}}, #state{import_ref = Ref} = State) ->
    NewState = State#state{import_seq = NewSeq},
    {noreply, NewState};
handle_info({Ref, done}, #state{local_ref = Ref, local_seq = Seq,
				local_lost = Lost} = State) ->
    case setup_monitor(local, Seq) of
	{ok, NewRef, Seq} ->
	    if Lost -> ?DNSXD_INFO("Reconnected local db poll");
	       true -> ok end,
	    {noreply, State#state{local_ref = NewRef, local_lost = false}};
	{error, Error} ->
	    ?DNSXD_ERR("Unable to reconnect local db poll:~n"
		       "~p~n"
		       "Retrying in 30 seconds", [Error]),
	    {ok, _} = timer:send_after(30000, self(), {Ref, done}),
	    {noreply, State}
    end;
handle_info({Ref, done}, #state{import_ref = Ref, import_seq = Seq,
				import_lost = Lost} = State) ->
    case setup_monitor(import, Seq) of
	{ok, NewRef, Seq} ->
	    if Lost -> ?DNSXD_INFO("Reconnected import db poll");
	       true -> ok end,
	    {noreply, State#state{import_ref = NewRef, import_lost = false}};
	{error, Error} ->
	    ?DNSXD_INFO("Unable to reconnect import db poll:~n"
			"~p~n"
			"Retrying in 30 seconds", [Error]),
	    {ok, _} = timer:send_after(30000, self(), {Ref, done}),
	    {noreply, State}
    end;
handle_info({Ref, {error, Error}}, #state{local_ref = Ref} = State) ->
    ?DNSXD_ERR("Lost local db connection:~n~p", [Error]),
    {ok, _} = timer:send_after(0, self(), {Ref, done}),
    NewState = State#state{local_lost = true},
    {noreply, NewState};
handle_info({Ref, {error, Error}}, #state{import_ref = Ref} = State) ->
    ?DNSXD_ERR("Lost import db connection:~n~p", [Error]),
    {ok, _} = timer:send_after(0, self(), {Ref, done}),
    NewState = State#state{import_lost = true},
    {noreply, NewState};
handle_info({Ref, {change, {Props}}}, #state{local_ref = Ref} = State) ->
    Name = proplists:get_value(<<"id">>, Props),
    Exists = dnsxd:zone_loaded(Name),
    Message = case load_zone(local, Name) of
		  {error, deleted} ->
		      dnsxd:delete_zone(Name),
		      "Local zone ~s deleted.";
		  {error, disabled} ->
		      case dnsxd:get_zone(Name) of
			  #dnsxd_zone{opaque_ds_id = {local, _}} ->
			      dnsxd:delete_zone(Name);
			  _ -> ok
		      end,
		      "Local zone ~s disabled.";
		  ok when Exists ->
		      "Local zone ~s reloaded.";
		  ok ->
		      "Local zone ~s loaded."
	      end,
    ?DNSXD_INFO(Message, [Name]),
    {noreply, State};
handle_info({Ref, {change, {Doc}}}, #state{import_ref = Ref} = State) ->
    Name = proplists:get_value(<<"_id">>, Doc),
    Exists = dnsxd:zone_loaded(Name),
    case load_zone(import, Name) of
	{error, deleted} ->
	    dnsxd:delete_zone(Name),
	    ?DNSXD_INFO("Import zone ~s deleted.", [Name]);
	{error, local_zone_exists} ->
	    ?DNSXD_ERR("Import zone ~s changed but cannot be loaded as "
		       "it conflicts with an existing local zone.", [Name]);
	ok ->
	    Msg = case Exists of
		      true -> "Import zone ~s reloaded.~n";
		      false -> "Import zone ~s loaded.~n"
		  end,
	    ?DNSXD_INFO(Msg, [Name])
    end,
    {noreply, State};
handle_info({Ref, Msg}, #state{local_ref = Ref} = State) ->
    ?DNSXD_ERR("Stray message concerning local_ref: ~n~p~n", [Msg]),
    {noreply, State};
handle_info({Ref, Msg}, #state{import_ref = Ref} = State) ->
    ?DNSXD_ERR("Stray message concerning import_ref: ~n~p~n", [Msg]),
    {noreply, State};
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

load_zone(DbAtom, ZoneName) ->
    case get_zone(DbAtom, ZoneName) of
	{ok, Zone} ->
	    case Zone of
		#dnsxd_couch_lz{export = true} ->
		    ExportZone = to_ez_zone(Zone),
		    ok = dnsxd_couch_zone:put(ExportZone),
		    insert_zone(Zone);
		#dnsxd_couch_lz{export = false} ->
		    ok = remove_export(ZoneName),
		    insert_zone(Zone);
		#dnsxd_couch_ez{} ->
		    insert_zone(Zone)
	    end;
	{error, Error} ->
	    {error, Error}
    end.

get_zone(DbAtom, ZoneName) ->
    case dnsxd_couch_zone:get(DbAtom, ZoneName) of
	{ok, Zone} ->
	    dnsxd_couch_zone:prepare(Zone);
	{error, Error} ->
	    {error, Error}
    end.

get_zone(DbAtom, DbRef, ZoneName) ->
    case dnsxd_couch_zone:get(DbAtom, DbRef, ZoneName) of
	{ok, Zone} ->
	    dnsxd_couch_zone:prepare(Zone);
	{error, Error} ->
	    {error, Error}
    end.

insert_zone(#dnsxd_couch_lz{} = CouchZone) ->
    Zone = to_dnsxd_zone(CouchZone),
    dnsxd:reload_zone(Zone);
insert_zone(#dnsxd_couch_ez{} = CouchZone) ->
    Zone = to_dnsxd_zone(CouchZone),
    case dnsxd:get_zone(Zone) of
	#dnsxd_zone{opaque_ds_id = {local, _}} ->
	    {error, conflict};
	_ ->
	    dnsxd:reload_zone(Zone)
    end.

init_load_zones(DbAtom) ->
    {ok, DbRef} = dnsxd_couch_lib:get_db(DbAtom),
    {ok, AllDocs} = couchbeam:all_docs(DbRef, []),
    init_load_zones(DbAtom, DbRef, AllDocs).

init_load_zones(local, LocalDbRef, LocalDocs) ->
    Fun0 = fun({Props}, Acc) ->
		   ZoneName = get_value(<<"id">>, Props),
		   {ok, Zone} = get_zone(local, LocalDbRef, ZoneName),
		   ok = insert_zone(Zone),
		   case Zone of
		       #dnsxd_couch_lz{export = true} -> [ZoneName|Acc];
		       #dnsxd_couch_lz{} -> Acc
		   end
	   end,
    ExportedNames = couchbeam_view:fold(LocalDocs, Fun0),
    {ok, ExportDbRef} = dnsxd_couch_lib:get_db(export),
    {ok, ExportDocs} = couchbeam:all_docs(ExportDbRef, [{include_docs, true}]),
    Fun1 = fun({Props}, Acc) ->
		   Id = get_value(<<"id">>, Props),
		   Doc = get_value(<<"doc">>, Props),
		   case lists:member(Id, ExportedNames) of
		       true -> Acc;
		       false -> [Doc|Acc]
		   end
	   end,
    DeleteDocs = couchbeam_view:fold(ExportDocs, Fun1),
    {ok, _} = couchbeam:delete_docs(ExportDbRef, DeleteDocs),
    ok;
init_load_zones(import, ImportDbRef, ImportDocs) ->
    Fun = fun({Props}) ->
		  ZoneName = get_value(<<"id">>, Props),
		  case get_zone(import, ImportDbRef, ZoneName) of
		      {ok, Zone} ->
			  case insert_zone(Zone) of
			      ok -> ok;
			      {error, conflict} ->
				  Fmt = ("Imported zone ~s not loaded "
					 "- zone name in use"),
				  ?DNSXD_INFO(Fmt, [ZoneName])
			  end;
		      {error, not_zone} ->
			  ?DNSXD_ERR("Import zone ~s is not valid", [ZoneName])
		  end
	  end,
    couchbeam_view:foreach(ImportDocs, Fun).

remove_export(ZoneName) ->
    {ok, DbRef} = dnsxd_couch_lib:get_db(export),
    case couchbeam:open_doc(DbRef, ZoneName) of
	{ok, Doc} ->
	    case couchbeam:delete_doc(DbRef, Doc) of
		{ok, _} ->
		    ok;
		{error, Error} ->
		    {error, Error}
	    end;
	{error, not_found} ->
	    ok;
	{error, Error} ->
	    {error, Error}
    end.

couch_tk_to_dnsxd_key(#dnsxd_couch_tk{id = Id,
				      name = Name,
				      secret = Secret,
				      dnssd_only = DnssdOnly}) ->
    #dnsxd_key{opaque_ds_id = Id,
	       name = Name,
	       secret = Secret,
	       dnssd_only = DnssdOnly}.

cancel_timer(Ref) when is_reference(Ref) ->
    _ = erlang:cancel_timer(Ref),
    ok;
cancel_timer(undefined) -> ok.

to_dnsxd_zone(#dnsxd_couch_lz{name = Name,
			      rr = CouchRRs,
			      axfr_enabled = AXFREnabled,
			      axfr_hosts = AXFRHosts,
			      tsig_keys = CouchKeys}) ->
    RRs = [ to_dnsxd_rr(RR) || RR <- CouchRRs ],
    Serials = dnsxd_couch_lib:get_serials(CouchRRs),
    Keys = [ couch_tk_to_dnsxd_key(Key)
	     || Key <- CouchKeys,
		Key#dnsxd_couch_tk.enabled,
		not is_integer(Key#dnsxd_couch_tk.tombstone) ],
    #dnsxd_zone{opaque_ds_id = {local, Name},
		name = Name,
		rr = RRs,
		serials = Serials,
		axfr_enabled = AXFREnabled,
		axfr_hosts = AXFRHosts,
		keys = Keys};
to_dnsxd_zone(#dnsxd_couch_ez{name = Name,
			      rr = CouchRRs,
			      axfr_enabled = AXFREnabled,
			      axfr_hosts = AXFRHosts}) ->
    RRs = [ to_dnsxd_rr(RR) || RR <- CouchRRs ],
    Serials = dnsxd_couch_lib:get_serials(CouchRRs),
    #dnsxd_zone{opaque_ds_id = {import, Name},
		name = Name,
		rr = RRs,
		serials = Serials,
		axfr_enabled = AXFREnabled,
		axfr_hosts = AXFRHosts}.

to_ez_zone(#dnsxd_couch_lz{name = Name,
			   rr = RRs,
			   axfr_enabled = AXFREnabled,
			   axfr_hosts = AXFRHosts,
			   soa_param = SOAParam}) ->
    #dnsxd_couch_ez{name = Name,
		    rr = RRs,
		    axfr_enabled = AXFREnabled,
		    axfr_hosts = AXFRHosts,
		    soa_param = SOAParam}.

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

setup_monitor(Db) ->
    case dnsxd_couch_lib:get_db(Db) of
	{ok, DbRef} ->
	    case couchbeam:db_info(DbRef) of
		{ok, {DbInfo}} ->
		    Since = get_value(<<"update_seq">>, DbInfo),
		    setup_monitor(DbRef, Since);
		{error, Error} ->
		    {error, Error}
	    end;
	{error, Error} ->
	    {error, Error}
    end.

setup_monitor(Db, Since) when is_atom(Db) ->
    case dnsxd_couch_lib:get_db(Db) of
	{ok, DbRef} ->
	    setup_monitor(DbRef, Since);
	{error, Error} ->
	    {error, Error}
    end;
setup_monitor(DbRef, Since) when is_tuple(DbRef) ->
    Opts = [{since, Since}, {feed, "continuous"}, {heartbeat, true}],
    case couchbeam:changes_wait(DbRef, self(), Opts) of
	{ok, Ref} -> {ok, Ref, Since};
	{error, Error} -> {error, Error}
    end.

start_compact() ->
    Fun = fun() -> compact([local, import, export]) end,
    spawn(Fun).

compact([]) ->
    ok = gen_server:call(?SERVER, compact_finished, 60 * 1000);
compact([Db|Dbs]) ->
    case dnsxd_couch_lib:get_db(Db) of
	{ok, DbRef} ->
	    case couchbeam:compact(DbRef) of
		ok ->
		    compact(Dbs);
		{error, Error} ->
		    ?DNSXD_ERR("Error compacting db ~p:~n~p", [Db, Error])
	    end;
	{error, Error} ->
	    ?DNSXD_ERR("Error getting db ~p for compaction:~n~p", [Db, Error])
    end.

get_value(Key, List) ->
    {Key, Value} = lists:keyfind(Key, 1, List),
    Value.
