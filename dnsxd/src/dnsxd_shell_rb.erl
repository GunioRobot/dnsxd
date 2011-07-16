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
-module(dnsxd_shell_rb).

-export([main/4]).

-define(DEFAULT_MAX, 20).
-define(EXIT_DELAY, receive after 500 -> ok end).

main(_NameArg, _CookieArg, EtcDir, Args) ->
    AppConfigFn = filename:join(EtcDir, "app.config"),
    case file:consult(AppConfigFn) of
	{ok, [Settings]} ->
	    SaslSettings = proplists:get_value(sasl, Settings, []),
	    LogDir = proplists:get_value(error_logger_mf_dir, SaslSettings),
	    case filelib:is_dir(LogDir) of
		true -> main(LogDir, Args);
		false ->
		    Msg = "SASL error_logger_mf_dir is not valid",
		    dnsxd_shell_lib:fail(Msg)
	    end;
	{ok, _} ->
	    Fmt = "Failed to load configuration from ~s: Bad term~n",
	    dnsxd_shell_lib:fail(Fmt, [AppConfigFn]);
	{error, Reason} ->
	    Fmt = "Failed to load configuration from ~s: ~s~n",
	    dnsxd_shell_lib:fail(Fmt, [AppConfigFn, file:format_error(Reason)])
    end.

main(LogDir, ShellArgs) ->
    application:set_env(sasl, errlog_type, error),
    application:set_env(sasl, sasl_error_logger, false),
    ok = application:start(sasl),
    case dnsxd_shell_lib:parse_opts(options(), ShellArgs) of
	{ok, Opts} ->
	    case proplists:get_bool(help, Opts) of
		true -> usage(0);
		false ->
		    case lists:keytake(max, 1, Opts) of
			{value, {max, MaxNum} = Max, []} when MaxNum > 0 ->
			    run_rb(LogDir, [Max]);
			{value, {max, MaxNum} = Max, Types} when MaxNum > 0 ->
			    case proplists:get_bool(all, Types) of
				true -> run_rb(LogDir, [Max]);
				false -> run_rb(LogDir, [Max,{type, Types}])
			    end;
			_ ->
			    dnsxd_shell_lib:fail(
			      "Maximum number of reports must be a number "
			      "greater than 0."
			     )
		    end
	    end;
	error -> usage(1)
    end.

run_rb(LogDir, Args) ->
    RBArgs = [{report_dir, LogDir}|Args],
    case rb:start(RBArgs) of
	{ok, _Pid} ->
	    ok = rb:show(),
	    io:format("\n"),
	    ?EXIT_DELAY;
	{error, {"cannot read the index file",_}} ->
	    dnsxd_shell_lib:fail("rb failed to start due to a bad or missing "
				 "index. This is normal if no logs have been "
				 "written to disk.");
	{error, Reason} ->
	    dnsxd_shell_lib:fail("rb failed to start:~n~p", [Reason])
    end.

options() ->
    MaxStr = integer_to_list(?DEFAULT_MAX),
    [{help, $h, "help", undefined, "Display these options"},
     {all, $a, "all", undefined, "Display all reports"},
     {crash_report, $c, "crash", undefined, "Include crash reports"},
     {supervisor_report, $s, "supervisor", undefined,
      "Include supervisor reports"},
     {error, $e, "error", undefined, "Include error reports"},
     {progress, $p, "progress", undefined, "Include progress reports"},
     {info_report, $i, "info_report", undefined, "Include info_reports"},
     {max, $m, "max", {integer, ?DEFAULT_MAX},
      "Maximum number of reports (default: " ++ MaxStr ++ ")"}].

usage(ExitCode) ->
    getopt:usage(options(), "dnsxd-rb"),
    dnsxd_shell_lib:halt(ExitCode).
