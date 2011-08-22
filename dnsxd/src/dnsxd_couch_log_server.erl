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
-module(dnsxd_couch_log_server).
-include("dnsxd_couch.hrl").
-behaviour(gen_server).

%% API
-export([start_link/0, dnsxd_log/1]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3]).

-define(SERVER, ?MODULE).

-define(TAB_CONF, dnsxd_couch_log_config).
-define(TAB_LIVE, dnsxd_couch_log_active).
-define(TAB_DUMP, dnsxd_couch_log_inactive).

-define(ETS_INSERT_RETRY, 3).

-define(DOC_NAME_PREFIX_STR, "dnsxd_couch_log_").
-define(DOC_NAME_PREFIX, <<?DOC_NAME_PREFIX_STR>>).
-define(DOC_NAME_CONFIG, <<"dnsxd_couch_log_config">>).

-define(DOC_TYPE_LOG, <<"dnsxd_couch_log_entries">>).
-define(DOC_TYPE_CONFIG, ?DOC_NAME_CONFIG).

-define(DEFAULT_NUMBER_OF_LOGS, 72).
-define(DEFAULT_LOG_PERIOD, 1200).

-define(FLUSH_INTERVAL, 33333).

-define(CHANGES_FILTER, <<?DNSXD_COUCH_DESIGNDOC "/dnsxd_couch_log">>).

-record(state, {flush_ref, db_ref, db_seq, db_lost = false}).
-record(conf_entry, {key, value}).
-record(log_entry, {id = dnsxd_lib:new_id(), doc_no = 0, props = []}).

%%%===================================================================
%%% API
%%%===================================================================

start_link() -> gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

dnsxd_log(Props) -> log(Props, ?ETS_INSERT_RETRY).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

init([]) ->
    ok = create_live_ets_table(),
    ?TAB_CONF = ets:new(?TAB_CONF, [named_table, {keypos, #conf_entry.key}]),
    ok = update_conf(),
    {ok, Ref, Since} = dnsxd_couch_lib:setup_monitor(?CHANGES_FILTER),
    State = setup_flush_callback(#state{db_ref = Ref, db_seq = Since}),
    {ok, State}.

handle_call(Request, _From, State) ->
    ?DNSXD_ERR("Stray call:~n~p~nState:~n~p~n", [Request, State]),
    {noreply, State}.

handle_cast(Msg, State) ->
    ?DNSXD_ERR("Stray cast:~n~p~nState:~n~p~n", [Msg, State]),
    {noreply, State}.

handle_info(flush_table, #state{} = State) ->
    NewState = setup_flush_callback(State),
    ok = flush_to_couch(),
    {noreply, NewState};
handle_info({Ref, done} = Message,
	    #state{db_ref = Ref, db_seq = Seq, db_lost = Lost} = State) ->
    case dnsxd_couch_lib:setup_monitor(?CHANGES_FILTER, Seq) of
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
handle_info({error, Ref, _Seq, Error},
	    #state{db_ref = Ref, db_lost = false} = State) ->
    ?DNSXD_ERR("Lost db connection:~n~p", [Error]),
    {ok, _} = timer:send_after(0, self(), {Ref, done}),
    NewState = State#state{db_lost = true},
    {noreply, NewState};
handle_info({error, _Ref, _Seq, Error}, #state{db_lost = true} = State) ->
    Fmt = "Got db connection error when db connection already lost:~n~p",
    ?DNSXD_ERR(Fmt, [Error]),
    {noreply, State};
handle_info({change, Ref, {Props}}, #state{db_ref = Ref} = State) ->
    NewSeq = proplists:get_value(<<"seq">>, Props),
    NewState = State#state{db_seq = NewSeq},
    case proplists:get_value(<<"id">>, Props) of
	?DOC_NAME_CONFIG ->
	    ok = update_conf(),
	    ?DNSXD_INFO("Log configuration reloaded");
	<<?DOC_NAME_PREFIX_STR, _/binary>> = LogDocName ->
	    case get_log(LogDocName) of
		{ok, _} -> ?DNSXD_INFO("Resolved conflict in ~s");
		{error, Reason} ->
		    Fmt = "Failed to resolve conflict in ~s:~n~p",
		    Args = [LogDocName, Reason],
		    ?DNSXD_ERR(Fmt, Args)
	    end;
	Other ->
	    Fmt = "Not sure how to handle change in ~s detected by filter ~s",
	    Args = [Other, ?CHANGES_FILTER],
	    ?DNSXD_ERR(Fmt, Args)
    end,
    {noreply, NewState};
handle_info(_Msg, #state{flush_ref = Ref} = State) ->
    ok = dnsxd_lib:cancel_timer(Ref),
    _ = flush_to_couch(),
    {stop, stray_message, State}.

terminate(_Reason, #state{flush_ref = Ref}) ->
    ok = dnsxd_lib:cancel_timer(Ref),
    ok = flush_to_couch(),
    ok.

code_change(_OldVsn, State, _Extra) -> {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

log(_Props, 0) -> ?DNSXD_ERR("Log insert failed");
log(Props, Retries) ->
    Time = proplists:get_value(<<"time">>, Props, dns:unix_time()),
    DocNo = doc_number(Time),
    Entry = #log_entry{doc_no = DocNo, props = Props},
    Succeeded = try ets:insert_new(?TAB_LIVE, Entry)
		catch error:badarg -> false end,
    if Succeeded -> ok;
       true -> timer:sleep(10), log(Props, Retries - 1) end.

doc_name(LogNum) when is_integer(LogNum) andalso LogNum >= 0 ->
    NumBin = list_to_binary(integer_to_list(LogNum)),
    <<?DOC_NAME_PREFIX/binary, NumBin/binary>>.

doc_number(UnixTime) ->
    Period = log_period(),
    Number = number_of_logs(),
    doc_number(UnixTime, Number, Period).

doc_number(UnixTime, Number, Period) ->
    Total = Period * Number,
    Epoch = (UnixTime div Total) * Total,
    Time = UnixTime - Epoch,
    Time div Period.

doc_epoch(DocNo) ->
    Period = log_period(),
    Number = number_of_logs(),
    UnixTime = dns:unix_time(),
    doc_epoch(DocNo, Number, Period, UnixTime).

doc_epoch(DocNo, Number, Period, UnixTime) ->
    Total = Period * Number,
    Epoch = (UnixTime div Total) * Total,
    Time = UnixTime - Epoch,
    CurDocNo = Time div Period,
    case CurDocNo >= DocNo of
	true -> Epoch + (Period * DocNo);
	false -> (Epoch - Total) + (Period * DocNo)
    end.

number_of_logs() ->
    ets:lookup_element(?TAB_CONF, <<"number_of_logs">>, #conf_entry.value).

log_period() ->
    ets:lookup_element(?TAB_CONF, <<"log_period">>, #conf_entry.value).

update_conf() ->
    {ok, DbRef} = dnsxd_couch_lib:get_db(),
    update_conf(DbRef).

update_conf(DbRef) ->
    BaseProps = [{<<"_id">>, ?DOC_NAME_CONFIG},
		 {?DNSXD_COUCH_TAG, ?DOC_TYPE_CONFIG}],
    case couchbeam:open_doc(DbRef, ?DOC_NAME_CONFIG) of
	{ok, {Props}} ->
	    Deleted = proplists:get_bool(<<"_deleted">>, Props),
	    DocType = proplists:get_value(?DNSXD_COUCH_TAG, Props),
	    DocTypeCorrect = DocType =:= ?DOC_TYPE_CONFIG,
	    if Deleted or not DocTypeCorrect ->
		    case proplists:get_value(<<"_rev">>, Props) of
			undefined -> update_conf(DbRef, BaseProps);
			Rev when is_binary(Rev) ->
			    Props2 = [{<<"_rev">>, Rev}|BaseProps],
			    update_conf(DbRef, Props2)
		    end;
	       true -> update_conf(DbRef, Props)
	    end;
	{error, not_found} -> update_conf(DbRef, BaseProps);
	{error, _Reason} = Error -> Error
    end.

update_conf(DbRef, Props) ->
    Fun = fun(X) when is_integer(X) -> X > 0; (_) -> false end,
    {NumOfLogs, Props2} = check_pl_val(<<"number_of_logs">>, Fun,
				       ?DEFAULT_NUMBER_OF_LOGS, Props),
    NumEntry = #conf_entry{key = <<"number_of_logs">>, value = NumOfLogs},
    {LogPeriod, Props3} = check_pl_val(<<"log_period">>, Fun,
				       ?DEFAULT_LOG_PERIOD, Props2),
    PeriodEntry = #conf_entry{key = <<"log_period">>, value = LogPeriod},
    case Props =:= Props3 of
	true ->
	    true = ets:insert(?TAB_CONF, [NumEntry, PeriodEntry]),
	    ok;
	false ->
	    case couchbeam:save_doc(DbRef, {Props3}) of
		{ok, _} ->
		    true = ets:insert(?TAB_CONF, [NumEntry, PeriodEntry]),
		    ok;
		{error, _Reason} = Error -> Error
	    end
    end.

check_pl_val(Key, Fun, Default, Proplist) ->
    Current = proplists:get_value(Key, Proplist),
    case Fun(Current) of
	true -> {Current, Proplist};
	false ->
	    NewProp = {Key, Default},
	    NewProplist = [NewProp|[ KV || {K, _V} = KV <- Proplist,
					   K =/= Key ]],
	    {Default, NewProplist}
    end.

setup_flush_callback(#state{flush_ref = OldRef} = State) ->
    ok = dnsxd_lib:cancel_timer(OldRef),
    NewRef = erlang:send_after(?FLUSH_INTERVAL, self(), flush_table),
    State#state{flush_ref = NewRef}.

flush_to_couch() ->
    {ok, DbRef} = dnsxd_couch_lib:get_db(),
    ?TAB_DUMP = ets:rename(?TAB_LIVE, ?TAB_DUMP),
    ok = create_live_ets_table(),
    flush_to_couch(DbRef).

flush_to_couch(DbRef) ->
    case ets:first(?TAB_DUMP) of
	'$end_of_table' ->
	    true = ets:delete(?TAB_DUMP),
	    ok;
	Id ->
	    DocNo = ets:lookup_element(?TAB_DUMP, Id, #log_entry.doc_no),
	    MatchHead = #log_entry{doc_no = DocNo, _ = '_'},
	    Entries = ets:select(?TAB_DUMP, [{MatchHead, [], ['$_']}]),
	    ok = flush_to_couch(DbRef, DocNo, Entries, 5),
	    _ = ets:select_delete(?TAB_DUMP, [{MatchHead, [], [true]}]),
	    flush_to_couch(DbRef)
    end.

flush_to_couch(_DbRef, _DocNo, Entries, 0) ->
    ?DNSXD_ERR("Failed to save ~p log entries", [length(Entries)]);
flush_to_couch(DbRef, DocNo, Entries, Retries) ->
    DocName = doc_name(DocNo),
    DocEpoch = doc_epoch(DocNo),
    case get_log(DbRef, DocName) of
	{ok, {DProps}} ->
	    Cur = [ E ||
		      {P} = E <- proplists:get_value(<<"entries">>, DProps, []),
		      proplists:get_value(<<"time">>, P, 0) >= DocEpoch ],
	    NewUnsorted = lists:foldl(
			    fun(#log_entry{id = Id, props = Props}, Acc) ->
				    New = {sort_entry([{<<"id">>, Id}|Props])},
				    [New|Acc]
			    end, Cur, Entries),
	    NewSorted = {<<"entries">>, sort_entries(NewUnsorted)},
	    NewProps = [NewSorted|proplists:delete(<<"entries">>, DProps)],
	    NewDoc = {lists:keysort(1, NewProps)},
	    case couchbeam:save_doc(DbRef, NewDoc) of
		{ok, _} -> ok;
		{error, Reason} ->
		    ?DNSXD_ERR("Failed to write ~s:~n~p", [DocName, Reason]),
		    timer:sleep(10),
		    flush_to_couch(DbRef, DocNo, Entries, Retries - 1)
	    end;
	{error, Reason} ->
	    ?DNSXD_ERR("Failed to open ~s:~n~p", [DocName, Reason]),
	    timer:sleep(10),
	    flush_to_couch(DbRef, DocNo, Entries, Retries - 1)
    end.

get_log(DocName) ->
    {ok, DbRef} = dnsxd_couch_lib:get_db(),
    get_log(DbRef, DocName).

get_log(DbRef, DocName) ->
    BaseProps = [{<<"_id">>, DocName}, {?DNSXD_COUCH_TAG, ?DOC_TYPE_LOG}],
    case couchbeam:open_doc(DbRef, DocName) of
	{ok, {Props}} = Result ->
	    Deleted = proplists:get_bool(<<"_deleted">>, Props),
	    DocType = proplists:get_value(?DNSXD_COUCH_TAG, Props),
	    DocTypeCorrect = DocType =:= ?DOC_TYPE_LOG,
	    if Deleted orelse not DocTypeCorrect ->
		    Rev = proplists:get_value(<<"_rev">>, Props),
		    Doc = {[{<<"_rev">>, Rev}|BaseProps]},
		    couchbeam:save_doc(DbRef, Doc);
	       true ->
		    case dnsxd_couch_lib:get_conflicts(Props) of
			[] -> Result;
			Revs -> get_log(DbRef, DocName, Props, Revs)
		    end
	    end;
	{error, not_found} ->
	    couchbeam:save_doc(DbRef, {lists:keysort(1, BaseProps)});
	{error, _Reason} = Error -> Error
    end.

get_log(DbRef, _DocName, Props, []) -> couchbeam:save_doc(DbRef, {Props});
get_log(DbRef, DocName, Props, [Rev|Revs]) ->
    case couchbeam:open_doc(DbRef, DocName, [{rev, Rev}]) of
	{ok, {CProps}} ->
	    NewProps = merge_log_props(Props, CProps),
	    get_log(DbRef, DocName, NewProps, Revs);
	{error, _Reason} = Error -> Error
    end.

merge_log_props(PropsA, PropsB) ->
    EntriesA = proplists:get_value(<<"entries">>, PropsA, []),
    EntriesB = proplists:get_value(<<"entries">>, PropsB, []),
    Combined = merge_log_entries(EntriesA, EntriesB),
    NewEntries = {<<"entries">>, Combined},
    lists:keysort(1, [NewEntries|proplists:delete(<<"entries">>, PropsA)]).

merge_log_entries(A, B) ->
    SortedA = [ sort_entry(E) || E <- A ],
    SortedB = [ sort_entry(E) || E <- B ],
    sort_entries(lists:usort(SortedA ++ SortedB)).

sort_entries(Entries) when is_list(Entries) ->
    lists:sort(fun sort_entries/2, Entries).

sort_entries({A}, {B}) ->
    TimeA = proplists:get_value(<<"time">>, A, 0),
    TimeB = proplists:get_value(<<"time">>, B, 0),
    TimeA >= TimeB.

sort_entry({Props}) -> {sort_entry(Props)};
sort_entry(Props) when is_list(Props) -> lists:keysort(1, Props).

create_live_ets_table() ->
    EtsOpts = [public, named_table, {keypos, #log_entry.id}],
    ?TAB_LIVE = ets:new(?TAB_LIVE, EtsOpts),
    ok.
