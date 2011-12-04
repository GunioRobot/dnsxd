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
-module(dnsxd_shell_admin_tsig).
-include("dnsxd_internal.hrl").

-export([main/3]).

main(NameArg, CookieArg, Args)
  when is_list(NameArg) andalso is_list(CookieArg) andalso is_list(Args) ->
    case dnsxd_shell_lib:parse_opts(options(), Args) of
	{ok, Opts} ->
	    case proplists:get_bool(help, Opts) of
		true -> usage(0);
		false ->
		    {ok, ZoneName, Request} = process_opts(Opts),
		    {ok, Node} = dnsxd_shell_lib:setup_dist(NameArg, CookieArg),
		    main(Node, ZoneName, Request)
	    end;
	error -> usage(1)
    end;
main(Node, ZoneName, Opts0) when is_atom(Node) andalso is_binary(ZoneName) ->
    {List, Opts1} = dnsxd_shell_lib:take_bool_opt(list, Opts0),
    if Opts1 =/= [] ->
	    case dnsxd_shell_admin_lib:change_zone(Node, ZoneName, Opts1) of
		ok -> display_changes(ZoneName, Opts1);
		{display_error, {Fmt, Args}} -> dnsxd_shell_lib:fail(Fmt, Args);
		Error0 ->
		    dnsxd_shell_lib:fail("Error changing zone:~n~p~n", [Error0])
	    end;
       true -> true
    end,
    if List ->
	    case dnsxd_shell_admin_lib:get_zone(Node, ZoneName) of
		{ok, #dnsxd_zone{tsig_keys = Keys0}} ->
		    Keys1 = lists:keysort(#dnsxd_tsig_key.name, Keys0),
		    ColSizes = [25, 7, 10, 30],
		    Heading = ["Name", "Enabled", "DNSSD Only", "Secret"],
		    Data = [ [Name, Enabled, DNSSDOnly, base64:encode(Secret)]
			     || #dnsxd_tsig_key{name = Name,
						enabled = Enabled,
						dnssd_only = DNSSDOnly,
						secret = Secret} <- Keys1 ],
		    dnsxd_shell_lib:render_table(ColSizes, Heading, Data);
		Error1 ->
		    dnsxd_shell_lib:fail("Error changing zone:~n~p~n", [Error1])
	    end;
       true -> true
    end.

display_changes(_ZoneName, []) -> ok;
display_changes(ZoneName, [{tsig_key_enabled, {Name, Bool}}|Changes]) ->
    io:format("TSIG key ~s.~s is now ~s~n",
	      [Name,  ZoneName, dnsxd_shell_lib:bool_to_enabled(Bool)]),
    display_changes(ZoneName, Changes);
display_changes(ZoneName, [{tsig_key_dnssdonly, {Name, Bool}}|Changes]) ->
    io:format("TSIG key ~s.~s's DNSSD lock status is now ~s~n",
	      [Name,  ZoneName, dnsxd_shell_lib:bool_to_enabled(Bool)]),
    display_changes(ZoneName, Changes);
display_changes(ZoneName, [{tsig_key_secret, {Name, Secret}}|Changes]) ->
    io:format("TSIG key ~s.~s's secret is now ~s~n",
	      [Name, ZoneName, base64:encode(Secret)]),
    display_changes(ZoneName, Changes);
display_changes(ZoneName, [{delete_tsig_key, Name}|Changes]) ->
    io:format("TSIG key ~s.~s has been deleted~n", [Name, ZoneName]),
    display_changes(ZoneName, Changes);
display_changes(ZoneName, [{add_tsig_key, #dnsxd_tsig_key{name = Name,
							  secret = Secret,
							  enabled = Enabled,
							  dnssd_only = DNSSDOnly
							 }}|Changes]) ->
    Fmt = "TSIG ~s.~s added with status ~s, DNSSD lock ~s and secret ~s~n",
    Args = [Name, ZoneName, dnsxd_shell_lib:bool_to_enabled(Enabled),
	    dnsxd_shell_lib:bool_to_enabled(DNSSDOnly), base64:encode(Secret)],
    io:format(Fmt, Args),
    display_changes(ZoneName, Changes).

usage(ExitCode) ->
    getopt:usage(options(), "dnsxd-admin tsig"),
    dnsxd_shell_lib:halt(ExitCode).

options() ->
    [{help, $h, "help", undefined, "Display these options"},
     {zonename, undefined, undefined, binary,
      "Zone name (required for options below)"},
     {list, $l, "list", undefined, "List TSIG keys"},
     {create, $c, "create", binary, "Create a TSIG key"},
     {enable, $e, "enable", binary, "Enable a TSIG key"},
     {disable, $d, "disable", binary, "Disable a TSIG key"},
     {secret, $s, "secret", binary, "Set a new secret for a TSIG key"},
     {lock_dnssd, undefined, "lock", binary,
      "Lock a TSIG key to manipulating DNSSD records"},
     {unlock_dnssd, undefined, "unlock", binary,
      "Let a TSIG key manipulate all DNS records"},
     {delete, undefined, "delete", binary, "Delete a TSIG key"}].

process_opts(Opts0) ->
    case lists:keytake(zonename, 1, Opts0) of
	{value, {zonename, _Zonename}, []} -> usage(1);
	{value, {zonename, ZoneName}, Opts1} ->
	    case dnsxd_shell_lib:valid_dname(ZoneName) of
		true ->
		    {ok, Requests} = process_opts(Opts1, []),
		    {ok, ZoneName, Requests};
		false ->
		    Msg = "~s is not a valid zonename.",
		    dnsxd_shell_lib:fail(Msg, [ZoneName])
	    end;
	_ -> usage(1)
    end.

process_opts([], Requests) -> {ok, lists:reverse(Requests)};
process_opts([list|Opts], Requests) ->
    process_opts(Opts, [list|Requests]);
process_opts([{create, Arg}|Opts], Requests) ->
    case parse_name(Arg) of
	{ok, Name, Secret} ->
	    NewTSIG = #dnsxd_tsig_key{id = dnsxd_lib:new_id(),
				      name = Name,
				      secret = Secret,
				      enabled = false,
				      dnssd_only = false},
	    Req = {add_tsig_key, NewTSIG},
	    process_opts(Opts, [Req|Requests]);
	{ok, Name} ->
	    NewTSIG = #dnsxd_tsig_key{id = dnsxd_lib:new_id(),
				      name = Name,
				      secret = crypto:rand_bytes(20),
				      enabled = false,
				      dnssd_only = false},
	    Req = {add_tsig_key, NewTSIG},
	    process_opts(Opts, [Req|Requests])
    end;
process_opts([{SetEnable, Name}|Opts], Requests)
  when SetEnable =:= disable orelse SetEnable =:= enable ->
    ok = check_name(Name),
    Req = {tsig_key_enabled, {Name, SetEnable =:= enable}},
    process_opts(Opts, [Req|Requests]);
process_opts([{secret, Arg}|Opts], Requests) ->
    case parse_name(Arg) of
	{ok, Name, Secret} ->
	    Req = {tsig_key_secret, {Name, Secret}},
	    process_opts(Opts, [Req|Requests]);
	{ok, Name} ->
	    Req = {tsig_key_secret, {Name, crypto:rand_bytes(20)}},
	    process_opts(Opts, [Req|Requests])
    end;
process_opts([{SetDNSSDLock, Name}|Opts], Requests)
  when SetDNSSDLock =:= lock_dnssd orelse SetDNSSDLock =:= unlock_dnssd ->
    ok = check_name(Name),
    Req = {tsig_key_dnssdonly, {Name, SetDNSSDLock =:= lock_dnssd}},
    process_opts(Opts, [Req|Requests]);
process_opts([{delete, Name}|Opts], Requests) ->
    ok = check_name(Name),
    Req = {delete_tsig_key, Name},
    process_opts(Opts, [Req|Requests]);
process_opts([Opt|_], _Requests) -> dnsxd_shell_lib:fail("Failed on ~p", [Opt]).

parse_name(Arg) ->
    case re:split(Arg, "=", [{return, binary},{parts,2}]) of
	[Name, Secret] ->
	    ok = check_name(Name),
	    case catch base64:decode(Secret) of
		Bin when is_binary(Bin) andalso byte_size(Bin) > 15 ->
		    {ok, Name, Bin};
		_ ->
		    case catch list_to_integer(binary_to_list(Secret)) of
			Int when Int > 15 -> {ok, Name, crypto:rand_bytes(Int)};
			_ -> fail_name(Arg)
		    end
	    end;
	[Name] ->
	    ok = check_name(Name),
	    {ok, Name};
	_ -> fail_name(Arg)
    end.

check_name(<<C, _/binary>> = Name) when C >= $a andalso C =< $z ->
    Size = byte_size(Name),
    case Size >= 0 andalso Size =< 64 of
	true ->
	    case name_chars_valid(Name) of
		true -> ok;
		false -> fail_name(Name)
	    end;
	false -> fail_name(Name)
    end;
check_name(Name) -> fail_name(Name).

name_chars_valid(<<>>) -> true;
name_chars_valid(<<C, Rest/binary>>)
  when (C >= $a andalso C =< $z) orelse
       (C >= $0 andalso C =< $9) orelse
       (C =:= $-) ->
    name_chars_valid(Rest);
name_chars_valid(_) -> false.

fail_name(Name) -> dnsxd_shell_lib:fail("Bad TSIG name: ~s~n", [Name]).
