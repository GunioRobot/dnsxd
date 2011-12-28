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
-module(dnsxd_shell_lib).

-export([setup_dist/2, fail/1, fail/2, halt/1, valid_dname/1, take_bool_opt/2,
	 bool_to_enabled/1, render_table/3, render_table/2, parse_opts/2,
	 format_optparse_error/1]).

-define(TAB_COL_MAX, 76).
-define(EXIT_DELAY, timer:sleep(500)).

%% distributed Erlang

setup_dist(NameArg, CookieArg) ->
    ok = start_epmd(),
    Cookie = list_to_atom(CookieArg),
    {ok, {LocalNode, RemoteNode, NameType}} = namearg_to_node_opts(NameArg),
    {ok, _} = net_kernel:start([LocalNode, NameType]),
    erlang:set_cookie(node(), Cookie),
    case net_adm:ping(RemoteNode) of
	pong -> {ok, RemoteNode};
	pang ->
	    dist_fail("Could not ping node ~s", [RemoteNode])
    end.

namearg_to_node_opts(RemoteNode) ->
    Atom = fun erlang:list_to_atom/1,
    case string:tokens(RemoteNode, "@") of
	[RemoteNode] ->
	    LocalNode = RemoteNode ++ "_dnsxd_admin_",
	    {ok, {Atom(LocalNode), Atom(RemoteNode), shortnames}};
	[RemoteNodeName, RemoteNodeHost] ->
	    LocalNode = RemoteNodeName ++ "_dnsxd_admin_@" ++ RemoteNodeHost,
	    {ok, {Atom(LocalNode), Atom(RemoteNode), longnames}};
	_ ->
	    dist_fail("Could not parse node name.")
    end.

start_epmd() -> _ = os:cmd(epmd_path() ++ " -daemon"), ok.

epmd_path() ->
    ErtsBinDir = filename:dirname(escript:script_name()),
    case os:find_executable("epmd", ErtsBinDir) of
        false ->
            case os:find_executable("epmd") of
                false -> dist_fail("Could not find epmd.");
                GlobalEpmd -> GlobalEpmd
            end;
        Epmd -> Epmd
    end.

dist_fail(Msg) -> dist_fail(Msg, []).
dist_fail(Fmt, Args) ->
    fail("Unable to setup distributed Erlang:~n" ++ Fmt, Args).

%% exiting the VM

fail(Msg) -> fail(Msg, []).
fail(Fmt, Args) ->
    io:format(Fmt ++ "~n", Args),
    ?MODULE:halt(1).

halt(ExitCode) ->
    case is_list(catch escript:script_name()) of
	true -> ?EXIT_DELAY, erlang:halt(ExitCode);
	false -> io:format("erlang:halt(~p)~n", [ExitCode])
    end.

%% validation

valid_dname(Name) when is_binary(Name) ->
    Size = byte_size(Name),
    case Size > 0 andalso Size < 254 of
	true ->
	    Labels = dns:dname_to_labels(Name),
	    valid_dname(Labels);
	false -> false
    end;
valid_dname([]) -> true;
valid_dname([Label|Labels]) -> valid_label(Label) andalso valid_dname(Labels).

valid_label(Label) ->
    Size = byte_size(Label),
    (Size > 0 andalso Size < 64) andalso no_uppercase(Label).

no_uppercase(<<>>) -> true;
no_uppercase(<<C, _/binary>>) when C >= $A andalso C =< $Z -> false;
no_uppercase(<<_, Rest/binary>>) -> no_uppercase(Rest).

%% table helper

render_table(MaxColSizes, Headings, Data) ->
    ok = tab_fits_col_max(MaxColSizes),
    ColSizes = calc_table_cols(MaxColSizes, [Headings|Data]),
    render_row(ColSizes, Headings),
    BorderLine = string:join([ lists:duplicate(N, $-)
			       || N <- ColSizes ], "+"),
    io:format("~s~n", [BorderLine]),
    render_rows(ColSizes, Data).

render_table(MaxColSizes, Data) ->
    ok = tab_fits_col_max(MaxColSizes),
    ColSizes = calc_table_cols(MaxColSizes, Data),
    render_rows(ColSizes, Data).

render_rows(_ColSizes, []) -> ok;
render_rows(ColSizes, [Row|Rows]) ->
    render_row(ColSizes, Row),
    render_rows(ColSizes, Rows).

render_row(ColSizes, Row) ->
    case [ C || C <- Row, C =/= "" ] of
	[] -> ok;
	_ ->
	    {Cur, Next} = truncate_cols(ColSizes, Row),
	    Fmt = build_fmt(ColSizes),
	    io:format(Fmt, Cur),
	    render_row(ColSizes, Next)
    end.

tab_fits_col_max(ColSizes) ->
    LostToBorders = (length(ColSizes) - 1),
    Cols = lists:foldl(fun(S, Acc) -> Acc + S end, LostToBorders, ColSizes),
    case ?TAB_COL_MAX >= Cols of
	true -> ok;
	false ->
	    io:format("~n~nTABLE IS LARGER THAN ~p COLS!~n~n~n", [?TAB_COL_MAX])
    end.

truncate_cols(ColSizes, Row) ->
    Fun = fun({Limit, Subject}) ->
		  case term_size(Subject) > Limit of
		      true -> lists:split(Limit, as_list(Subject));
		      false -> {Subject, ""}
		  end
	  end,
    lists:unzip(lists:map(Fun, lists:zip(ColSizes, Row))).

calc_table_cols(ColSizes, Rows) ->
    Result = [ 0 || _ <- ColSizes ],
    calc_table_cols(ColSizes, Result, Rows).

calc_table_cols(_ColSizes, Result, []) -> Result;
calc_table_cols(ColSizes, Result, [Row|Rows]) ->
    Fun = fun({SizeLimit, CurrentSize, Subject}) ->
		  SubjectSize = term_size(Subject),
		  if SubjectSize =< CurrentSize -> CurrentSize;
		     SubjectSize >= SizeLimit -> SizeLimit;
		     SubjectSize >= CurrentSize -> SubjectSize;
		     true -> CurrentSize end
	  end,
    NewResult = lists:map(Fun, lists:zip3(ColSizes, Result, Row)),
    calc_table_cols(ColSizes, NewResult, Rows).

build_fmt(ColSizes) ->
    string:join([ "~" ++ integer_to_list(S) ++ "s"
		  || S <- ColSizes ], "|") ++ "~n".

term_size(List) when is_list(List) -> length(List);
term_size(Bin) when is_binary(Bin) -> byte_size(Bin);
term_size(Atom) when is_atom(Atom) -> term_size(as_list(Atom)).

as_list(List) when is_list(List) -> List;
as_list(Bin) when is_binary(Bin) -> binary_to_list(Bin);
as_list(Atom) when is_atom(Atom) -> atom_to_list(Atom).

%% other helpers

take_bool_opt(Key, List) ->
    Result = proplists:get_bool(Key, List),
    Fun = fun({Term, _}) -> Term =/= Key; (Term) -> Term =/= Key end,
    NewList = [ Term || Term <- List, Fun(Term) ],
    {Result, NewList}.

bool_to_enabled(true) -> "enabled";
bool_to_enabled(false) -> "disabled".

parse_opts(Options, Args) ->
    case getopt:parse(Options, Args) of
	{ok, {ParsedOptions, []}} -> {ok, ParsedOptions};
	Error -> format_optparse_error(Error)
    end.

format_optparse_error({error, {missing_option_arg, ArgName}}) ->
    io:format("'~s' option requires an argument:~n~n", [ArgName]),
    error;
format_optparse_error({error, {invalid_option_arg, {ArgName, ArgValue}}}) ->
    Fmt = "~p is not a valid argument to option '~s':~n~n",
    FmtArgs = [ArgValue, ArgName],
    io:format(Fmt, FmtArgs),
    error;
format_optparse_error(_) -> error.
