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
-module(dnsxd_shell_disklog).
-include("dnsxd.hrl").

-export([main/4]).

main(NameArg, CookieArg, _EtcDir, Args) ->
    case getopt:parse(options(), Args) of
	{ok, {Opts, KeyValues}} ->
	    case proplists:get_bool(help, Opts) of
		true -> usage(0);
		false ->
		    {ok, Filters} = build_filters(Opts, KeyValues),
		    {ok, Node} = dnsxd_shell_lib:setup_dist(NameArg, CookieArg),
		    {ok, File} = get_file(Node),
		    {ok, Cont} = get_cont(File),
		    main(Cont, Filters)
	    end;
	Error ->
	    error = dnsxd_shell_lib:format_optparse_error(Error),
	    usage(1)
    end.

main(Cont, Filters) ->
    case wrap_log_reader:chunk(Cont) of
	{NewCont, eof} ->
	    ok = wrap_log_reader:close(NewCont);
	{NewCont, Proplists} ->
	    ok = show_matching_proplists(Proplists, Filters),
	    main(NewCont, Filters);
	{NewCont, Proplists, _Badbytes} ->
	    ok = show_matching_proplists(Proplists, Filters),
	    main(NewCont, Filters)
    end.

options() ->
    [{help, $h, "help", undefined, "Display these options"},
     {'after', $a, "after", integer,
      "Only include entries created after this timestamp"},
     {before, $b, "before", integer,
      "Only include entries created before this timestamp"}].

usage(ExitCode) ->
    OptionsTail = [{"key", "Filter log entries by supplying additional key"},
		   {"key=value", "and/or key=value arguments"}],
    getopt:usage(options(), "dnsxd-disklog", "key key=value", OptionsTail),
    dnsxd_shell_lib:halt(ExitCode).

get_cont(File) ->
    case wrap_log_reader:open(File) of
	{ok, _Cont} = Result -> Result;
	{error, _Reason} = Error ->
	    dnsxd_shell_lib:fail("Failed to open disk log:~n~p", [Error])
    end.

get_file(Node) when is_atom(Node) ->
    case rpc:call(Node, dnsxd_disklog, file, []) of
	File when is_list(File) -> {ok, File};
	{badrpc, _Reason} = Error ->
	    Fmt = "Failed to retrieve disk log file info:~n~p",
	    dnsxd_shell_lib:fail(Fmt, [Error])
    end.

show_matching_proplists([], _Filters) -> ok;
show_matching_proplists([Proplist|Proplists], Filters) ->
    case proplist_matches(Proplist, Filters) of
	true ->
	    Fun = fun(Int) when is_integer(Int) -> integer_to_list(Int);
		     (Term) -> Term end,
	    [ ok = io:format("~s ~s ", [K, Fun(V)]) || {K,V} <- Proplist ],
	    io:format("~n");
	false -> ok
    end,
    show_matching_proplists(Proplists, Filters).

proplist_matches(_Proplist, []) -> true;
proplist_matches(Proplist, [Filter|Filters]) ->
    Filter(Proplist) andalso proplist_matches(Proplist, Filters).

build_filters(Opts, Args) -> build_filters(Opts, Args, []).

build_filters([], [], Filters) -> {ok, Filters};
build_filters([{'after', Timestamp}|Opts], Args, Filters) ->
    Filter = fun(Proplist) ->
		     proplists:get_value(<<"time">>, Proplist) > Timestamp
	     end,
    build_filters(Opts, Args, [Filter|Filters]);
build_filters([{before, Timestamp}|Opts], Args, Filters) ->
    Filter = fun(Proplist) ->
		     proplists:get_value(<<"time">>, Proplist) < Timestamp
	     end,
    build_filters(Opts, Args, [Filter|Filters]);
build_filters([], [Arg|Args], Filters) ->
    case re:split(Arg, "=", [{return, list},{parts,2}]) of
	[KeyRaw, ValueRaw] ->
	    Key = list_to_binary(KeyRaw),
	    Value = case catch list_to_integer(ValueRaw) of
			Int when is_integer(Int) -> Int;
			_ -> list_to_binary(ValueRaw)
		    end,
	    Filter = fun(Proplist) ->
			     Value =:= proplists:get_value(Key, Proplist)
		     end,
	    build_filters([], Args, [Filter|Filters]);
	[KeyRaw] ->
	    Key = list_to_binary(KeyRaw),
	    Filter = fun(Proplist) -> proplists:is_defined(Key, Proplist) end,
	    build_filters([], Args, [Filter|Filters]);
	_ ->
	    dnsxd_shell_lib:fail("Bad arg: ~p~n", [Arg])
    end.
