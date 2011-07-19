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
-module(dnsxd_shell_admin_zone).
-include("dnsxd.hrl").

-export([main/3]).

main(NameArg, CookieArg, Args)
  when is_list(NameArg) andalso is_list(CookieArg) andalso is_list(Args) ->
    case dnsxd_shell_lib:parse_opts(options(), Args) of
	{ok, Opts0} ->
	    case proplists:get_bool(help, Opts0) of
		true -> usage(0);
		false ->
		    {ok, ZoneName, Opts1} = process_opts(Opts0),
		    {ok, Node} = dnsxd_shell_lib:setup_dist(NameArg, CookieArg),
		    main(Node, ZoneName, Opts1)
	    end;
	error -> usage(1)
    end;
main(Node, ZoneName, [_|_] = Opts0) when is_atom(Node) ->
    {DisplayList, Opts1} = dnsxd_shell_lib:take_bool_opt(list, Opts0),
    {DisplayStatus, Opts2} = dnsxd_shell_lib:take_bool_opt(status, Opts1),
    if Opts2 =/= [] ->
	    case dnsxd_shell_admin_lib:change_zone(Node, ZoneName, Opts2) of
		ok -> ok;
		{display_error, {Fmt0, Args0}} ->
		    dnsxd_shell_lib:fail(Fmt0, Args0);
		{error, exists} ->
		    dnsxd_shell_lib:fail("Zone ~s exists", [ZoneName]);
		{error, not_found} ->
		    dnsxd_shell_lib:fail("Zone ~s does not exist", [ZoneName]);
		Error0 ->
		    dnsxd_shell_lib:fail("Error changing zone:~n~p", [Error0])
	    end;
       true -> true
    end,
    if DisplayList -> display_list(Node);
       DisplayStatus orelse Opts2 =/= [] -> display_zone(Node, ZoneName);
       true -> ok end.

display_list(Node) ->
    case dnsxd_shell_admin_lib:zone_list(Node) of
	{ok, Zones} ->
	    SortedZones = lists:keysort(1, Zones),
	    MaxColSizes = [68, 7],
	    Headings = ["Name", "Enabled"],
	    Data = [ [Name, Enabled] || {Name, Enabled} <- SortedZones ],
	    dnsxd_shell_lib:render_table(MaxColSizes, Headings, Data);
	{display_error, {Fmt, Args}} -> dnsxd_shell_lib:fail(Fmt, Args);
	Error -> dnsxd_shell_lib:fail("~p~n", [Error])
    end.

display_zone(Node, ZoneName) ->
    case dnsxd_shell_admin_lib:get_zone(Node, ZoneName) of
	{ok, #dnsxd_zone{} = Zone} -> display_zone(Zone);
	{display_error, {Fmt, Args}} -> dnsxd_shell_lib:fail(Fmt, Args);
	Error -> dnsxd_shell_lib:fail("Error retrieving zone:~n~p~n", [Error])
    end.

display_zone(#dnsxd_zone{name = Name,
			 enabled = Enabled,
			 dnssec_enabled = DNSSECEnabled,
			 dnssec_keys = DK,
			 tsig_keys = TK,
			 soa_param = #dnsxd_soa_param{mname = Mname,
						      rname = Rname,
						      refresh = Refresh,
						      retry = Retry,
						      expire = Expire,
						      minimum = Min}}) ->
    {KC, KSKC} = lists:foldl(fun(#dnsxd_dnssec_key{ksk = Bool}, {KCA, KSKA}) ->
				     if Bool -> {KCA, KSKA + 1};
					true -> {KCA + 1, KSKA} end
			     end, {0,0}, DK),
    DKSummary = lists:flatten(io_lib:format(" ~p (~p KSK)", [KC + KSKC, KSKC])),
    TKCount = integer_to_list(length(TK)),
    ColSizes = [20, 50],
    io:format("~s~n~s~n", [Name, lists:duplicate(80, $-)]),
    Rows = [ ["Enabled", Enabled],
	     ["DNSSEC Enabled", DNSSECEnabled],
	     ["DNSSEC Keys", DKSummary],
	     ["TSIG Keys", TKCount],
	     ["SOA MName", Mname],
	     ["SOA RName", Rname],
	     ["SOA Refresh", integer_to_list(Refresh) ],
	     ["SOA Retry", integer_to_list(Retry) ],
	     ["SOA Expire", integer_to_list(Expire) ],
	     ["SOA Minimum", integer_to_list(Min) ]
	   ],
    dnsxd_shell_lib:render_table(ColSizes, Rows).

usage(ExitCode) ->
    getopt:usage(options(), "dnsxd-admin zone"),
    dnsxd_shell_lib:halt(ExitCode).

options() ->
    [{help, $h, "help", undefined, "Display these options"},
     {list, $l, "list", undefined, "List zones"},
     {zonename, undefined, undefined, binary,
      "Zone name (required for options below)"},
     {status, $s, "status", undefined,
      "Show zone status (implied if only zone name is supplied)"},
     {create, $c, "create", undefined, "Create zone"},
     {delete, undefined, "delete", undefined, "Delete zone"},
     {enable, $e, "enable", undefined, "Enable zone"},
     {disable, $d, "disable", undefined, "Disable zone"},
     {mname, undefined, "mname", binary, "Set SOA mname"},
     {rname, undefined, "rname", binary, "Set SOA rname"},
     {refresh, undefined, "refresh", integer, "Set SOA refresh"},
     {retry, undefined, "retry", integer, "Set SOA retry"},
     {expire, undefined, "expire", integer, "Set SOA expire"},
     {minimum, undefined, "minimum", integer, "Set SOA minimum"}].

process_opts(Opts0) ->
    case lists:keytake(zonename, 1, Opts0) of
	{value, {zonename, ZoneName}, Opts1} ->
	    case dnsxd_shell_lib:valid_dname(ZoneName) of
		true when Opts1 =:= [] -> {ok, ZoneName, [status]};
		true ->
		    {ok, Requests} = process_opts(Opts1, []),
		    {ok, ZoneName, Requests};
		false ->
		    Msg = "~s is not a valid zonename.",
		    dnsxd_shell_lib:fail(Msg, [ZoneName])
	    end;
	_ ->
	    case proplists:get_bool(list, Opts0) of
		true -> {ok, undefined, [list]};
		false -> usage(1)
	    end
    end.

process_opts([], Requests) -> {ok, Requests};
process_opts([{Key, Value}|Opts], Requests)
  when Key =:= mname orelse Key =:= rname andalso is_binary(Value) ->
    case dnsxd_shell_lib:valid_dname(Value) of
	true ->
	    Req = {Key, normalise_dname(Value)},
	    process_opts(Opts, [Req|Requests]);
	false ->
	    Msg = "The value for ~s must be valid domain name",
	    dnsxd_shell_lib:fail(Msg, [Key])
    end;
process_opts([{Key, Value} = Req|Opts], Requests)
  when Key =:= refresh; Key =:= retry; Key =:= expire; Key =:= minimum ->
    case is_integer(Value) andalso Value >= 0 of
	true -> process_opts(Opts, [Req|Requests]);
	false ->
	    Msg = "The value for ~s must be a number greater than 0.",
	    dnsxd_shell_lib:fail(Msg, [Key])
    end;
process_opts([status|Opts], Requests) -> process_opts(Opts, [status|Requests]);
process_opts([list|Opts], Requests) -> process_opts(Opts, [list|Requests]);
process_opts([Cmd|Opts], Requests)
  when Cmd =:= create orelse Cmd =:= delete orelse Cmd =:= enable orelse
       Cmd =:= disable ->
    Alt = case Cmd of
	      create -> delete;
	      delete -> create;
	      enable -> disable;
	      disable -> enable
	  end,
    Req = case Cmd of
	      create -> create_zone;
	      delete -> delete_zone;
	      disable -> {zone_enabled, false};
	      enable -> {zone_enabled, true}
	  end,
    case proplists:is_defined(Alt, Opts) of
	true ->
	    Msg = "The ~s and ~s options are mutually exclusive.",
	    dnsxd_shell_lib:fail(Msg, [Cmd, Alt]);
	false -> process_opts(Opts, [Req|Requests])
    end.

normalise_dname(Dname) ->
    SizeLess1 = byte_size(Dname) - 1,
    case Dname of
	<<NewDname:SizeLess1/binary, $.>> -> NewDname;
	Dname -> Dname
    end.
