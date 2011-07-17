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
-module(dnsxd_shell_llq).
-include("dnsxd.hrl").

-export([main/4]).

main(NameArg, CookieArg, _EtcDir, Args) ->
    case dnsxd_shell_lib:parse_opts(options(), Args) of
	{ok, []} -> usage(0);
	{ok, Opts} ->
	    case proplists:get_bool(help, Opts) of
		true -> usage(0);
		false ->
		    {ok, Node} = dnsxd_shell_lib:setup_dist(NameArg, CookieArg),
		    main(Node, Opts)
	    end;
	error -> usage(1)
    end.

main(Node, Opts) ->
    Args = case proplists:get_bool(all, Opts) of
	       true -> [];
	       false -> [proplists:get_value(zonename, Opts)]
	   end,
    case rpc:call(Node, dnsxd_llq_manager, list_llq, Args) of
	[] when Args =:= [] ->
	    io:format("No LLQ running~n"),
	    dnsxd_shell_lib:halt(0);
	[] ->
	    Fmt = "No LLQ matching zone name ~s are running~n",
	    io:format(Fmt, Args),
	    dnsxd_shell_lib:halt(0);
	LLQs when is_list(LLQs) -> display_llqs(LLQs);
	Error ->
	    dnsxd_shell_lib:fail("Failed to retrieve LLQ:~n~p", [Error])
    end.

usage(ExitCode) ->
    getopt:usage(options(), "dnsxd-llq"),
    dnsxd_shell_lib:halt(ExitCode).

options() ->
    [{help, $h, "help", undefined, "Display these options"},
     {all, $a, "all", undefined, "List all LLQ"},
     {zonename, $z, "zone", binary, "List LLQ for the supplied zone"}].

display_llqs(LLQs) ->
    Heading = ["ID", "Query"],
    ColSizes = [20, 55],
    Data = [ [integer_to_list(ID), format_query(Query)]
	     || {ID, _ZoneName, #dns_query{} = Query} <- LLQs ],
    dnsxd_shell_lib:render_table(ColSizes, Heading, Data),
    dnsxd_shell_lib:halt(0).

format_query(#dns_query{name = Name, type = Type}) ->
    TypeBin = atom_to_binary(dns:type_to_atom(Type), latin1),
    <<Name/binary, $/, TypeBin/binary>>.
