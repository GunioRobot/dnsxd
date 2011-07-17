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
-module(dnsxd_disklog).
-include("dnsxd.hrl").

-behaviour(gen_server).

%% API
-export([start_link/0, dnsxd_log/1, each/1, fold/2]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3]).

-define(SERVER, ?MODULE).

-define(LOG_NAME, ?MODULE_STRING).

-record(state, {log}).

%%%===================================================================
%%% API
%%%===================================================================

start_link() -> gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

dnsxd_log(Props) -> disk_log:log(?LOG_NAME, Props).

each(Fun) when is_function(Fun, 1) ->
    {ok, Cont} = wrap_log_reader:open(file()),
    each(Fun, Cont).

fold(Fun, Acc) when is_function(Fun, 2) ->
    {ok, Cont} = wrap_log_reader:open(file()),
    fold(Fun, Acc, Cont).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

init([]) ->
    File = file(),
    Options = [{name, ?LOG_NAME}, {type, wrap}, {size, size()}, {file, File}],
    case disk_log:open(Options) of
	{ok, Log} -> {ok, #state{log = Log}};
	{repaired, Log, {recovered, Rec}, {badbytes, Bad}} ->
	    ?DNSXD_INFO("Repair triggered opening ~s. "
			"~p terms recovered ~p bytes lost.",
			[File, Rec, Bad]),
	    {ok, #state{log = Log}};
	{error, _Reason} = Error -> Error
    end.

handle_call(Request, _From, State) ->
    ?DNSXD_ERR("Stray call:~n~p~nState:~n~p~n", [Request, State]),
    {noreply, State}.

handle_cast(Msg, State) ->
    ?DNSXD_ERR("Stray cast:~n~p~nState:~n~p~n", [Msg, State]),
    {noreply, State}.

handle_info(Info, State) ->
    ?DNSXD_ERR("Stray message:~n~p~nState:~n~p~n", [Info, State]),
    {noreply, State}.

terminate(_Reason, #state{log = Log}) -> ok = disk_log:close(Log).

code_change(_OldVsn, State, _Extra) -> {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

each(Fun, Cont) ->
    case wrap_log_reader:chunk(Cont) of
	{NewCont, eof} ->
	    ok = wrap_log_reader:close(NewCont);
	{NewCont, Terms} ->
	    [ Fun(Term) || Term <- Terms],
	    each(Fun, NewCont);
	{NewCont, Terms, _Badbytes} ->
	    [ Fun(Term) || Term <- Terms],
	    each(Fun, NewCont)
    end.

fold(Fun, Acc, Cont) ->
    case wrap_log_reader:chunk(Cont) of
	{NewCont, eof} ->
	    ok = wrap_log_reader:close(NewCont),
	    Acc;
	{NewCont, Terms} ->
	    NewAcc = lists:foldl(Fun, Acc, Terms),
	    fold(Fun, NewAcc, NewCont);
	{NewCont, Terms, _Badbytes} ->
	    NewAcc = lists:foldl(Fun, Acc, Terms),
	    fold(Fun, NewAcc, NewCont)
    end.

file() ->
    Default = filename:join(["log","disklog", "log"]),
    Dir = get_opt(log_dir, Default),
    ok = filelib:ensure_dir(Dir),
    Dir.

size() ->
    MaxBytes = get_opt(max_bytes, 10485760),
    MaxFiles = get_opt(max_files, 5),
    {MaxBytes, MaxFiles}.

get_opt(Key, Default) -> proplists:get_value(Key, dnsxd:log_opts(), Default).
