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
-module(dnsxd_shell_admin_dnssec).
-include("dnsxd_internal.hrl").

-export([main/3]).

main(NameArg, CookieArg, Args)
  when is_list(NameArg) andalso is_list(CookieArg) andalso is_list(Args) ->
    ok = application:start(cutkey),
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
main(Node, ZoneName, [_|_] = Changes)
  when is_atom(Node) andalso is_binary(ZoneName) ->
    {DisplayStatus, Changes0} = dnsxd_shell_lib:take_bool_opt(status, Changes),
    {DisplayKeys, Changes1} = dnsxd_shell_lib:take_bool_opt(list, Changes0),
    case Changes1 of
	[] -> ok;
	Changes1 ->
	    case dnsxd_shell_admin_lib:change_zone(Node, ZoneName, Changes1) of
		ok -> display_changes(ZoneName, Changes1);
		{display_error, {Fmt, Args}} -> dnsxd_shell_lib:fail(Fmt, Args);
		Error0 ->
		    dnsxd_shell_lib:fail("Error changing zone:~n~p~n", [Error0])
	    end
    end,
    case dnsxd_shell_admin_lib:get_zone(Node, ZoneName) of
	{ok, #dnsxd_zone{} = Zone} ->
	    ok = display_status(DisplayStatus, Zone),
	    ok = display_keys(DisplayKeys, Zone);
	Error1 ->
	    dnsxd_shell_lib:fail("Failed to retrieve zone:~n~p~n", [Error1])
    end.

display_changes(_ZoneName, []) -> ok;
display_changes(ZoneName, [{add_dnssec_key,
			    #dnsxd_dnssec_key{id = Id, ksk = KSK}}|Changes]) ->
    Fmt = case KSK of
	      true ->
		  "Added DNSSEC key ~s~nQuery ~s._dnsxd-ds.~s for keytag~n";
	      false ->
		  "Added DNSSEC key ~s.~i~i~n"
	  end,
    Args = [Id, Id, ZoneName],
    io:format(Fmt, Args),
    display_changes(ZoneName, Changes);
display_changes(ZoneName, [{delete_dnssec_key, Id}|Changes]) ->
    io:format("DNSSEC key ~s has been deleted~n", [Id]),
    display_changes(ZoneName, Changes);
display_changes(ZoneName, [{dnssec_enabled, Bool}|Changes]) ->
    Status = dnsxd_shell_lib:bool_to_enabled(Bool),
    io:format("DNSSEC is now ~s for ~s~n", [Status, ZoneName]),
    display_changes(ZoneName, Changes);
display_changes(ZoneName, [{Key, Value}|Changes]) ->
    KeyString = case Key of
		    nsec3salt -> "NSEC3 salt";
		    nsec3iter -> "NSEC3 iterations";
		    dnssec_siglife -> "Signature life"
		end,
    io:format("~s now ~p~n", [KeyString, Value]),
    display_changes(ZoneName, Changes).

display_status(false, _) -> ok;
display_status(true, #dnsxd_zone{name = Name,
				 dnssec_enabled = DNSSECEnabled,
				 dnssec_siglife = SigLife,
				 nsec3 = #dnsxd_nsec3_param{hash = Hash,
							    salt = Salt,
							    iter = Iter}}) ->
    io:format("~s DNSSEC status:~n"
	      "Enabled: ~s~n"
	      "Signature Life: ~p~n"
	      "NSEC3 Parameters:~n"
	      " Hash: ~p~n"
	      " Salt: ~p~n"
	      " Iter: ~p~n", [Name, DNSSECEnabled, SigLife, Hash, Salt, Iter]).

display_keys(false, _) -> ok;
display_keys(true, #dnsxd_zone{dnssec_keys = Keys}) ->
    SortedKeys = lists:keysort(#dnsxd_dnssec_key.id, Keys),
    MaxColSizes = [35, 5, 10, 10],
    Headings = ["Id", "Alg", "Incept", "Expire"],
    IntToList = fun erlang:integer_to_list/1,
    Data = [ [Id, IntToList(Alg), IntToList(Incept), IntToList(Expire)]
		     || #dnsxd_dnssec_key{id = Id,
					  alg = Alg,
					  incept = Incept,
					  expire = Expire} <- SortedKeys ],
    dnsxd_shell_lib:render_table(MaxColSizes, Headings, Data).

usage(ExitCode) ->
    getopt:usage(options(), "dnsxd-admin dnssec"),
    dnsxd_shell_lib:halt(ExitCode).

options() ->
    [{help, $h, "help", undefined, "Display these options"},
     {zonename, undefined, undefined, binary,
      "Zone name (required for options below)"},
     {status, $s, "status", undefined, "DNSSEC status and NSEC3 params"},
     {list, $l, "list", undefined, "List DNSSEC keys"},
     {enable, undefined, "enable", undefined, "Enable DNSSEC"},
     {disable, undefined, "disable", undefined, "Disable DNSSEC"},
     {create, $c, "create", undefined, "New RSA DNSSEC key"},
     {ksk, $k, "ksk", boolean, "New key is a KSK (default: false)"},
     {bits, $b, "bits", integer, "New key bits"},
     {incept, $i, "incept", {integer, 0},
      "Days before new key inception (default: 0)"},
     {expire, $e, "expire", integer,
      "Days before new key expires (default: 365)"},
     {siglife, undefined, "siglife", integer, "Set signature life"},
     {nsec3_salt, undefined, "salt", binary, "Set NSEC3 salt"},
     {nsec3_iterations, undefined, "iterations", integer,
      "Set NSEC3 iterations"},
     {delete, undefined, "delete", binary, "Delete a DNSSEC key"}].

process_opts(Opts0) ->
    case lists:keytake(zonename, 1, Opts0) of
	{value, {zonename, _Zonename}, []} -> usage(1);
	{value, {zonename, ZoneName}, Opts1} ->
	    case dnsxd_shell_lib:valid_dname(ZoneName) of
		true ->
		    {ok, Requests} = build_requests(Opts1),
		    {ok, ZoneName, Requests};
		false ->
		    Msg = "~s is not a valid zonename.",
		    dnsxd_shell_lib:fail(Msg, [ZoneName])
	    end;
	_ -> usage(1)
    end.

build_requests(MixedOpts) -> build_requests(MixedOpts, []).

build_requests([], []) -> usage(1);
build_requests([], Requests) -> {ok, Requests};
build_requests([Cmd|Opts], Requests)
  when Cmd =:= enable orelse Cmd =:= disable ->
    Alt = case Cmd of
	      enable -> disable;
	      disable -> enable
	  end,
    case proplists:is_defined(Alt, Opts) of
	true ->
	    Msg = "The ~s and ~s options are mutually exclusive.",
	    dnsxd_shell_lib:fail(Msg, [Cmd, Alt]);
	false ->
	    Req = {dnssec_enabled, Cmd =:= enable},
	    build_requests(Opts, [Req|Requests])
    end;
build_requests([create|Opts0], Requests) ->
    {KSK, Opts1} = get_key_gen_param(ksk, Opts0),
    {Bits0, Opts2} = get_key_gen_param(bits, Opts1),
    Bits1 = case is_integer(Bits0) of
		true -> Bits0;
		false when KSK -> 2048;
		false -> 1024
	    end,
    {Incept0, Opts3} = get_key_gen_param(incept, Opts2),
    Incept1 = Incept0 * 86400,
    {Expire0, Opts4} = get_key_gen_param(expire, Opts3),
    Expire1 = Expire0 * 86400,
    case catch cutkey:rsa(Bits1, 65537) of
	{ok, PKey} ->
	    Now = dns:unix_time(),
	    NewKey = #dnsxd_dnssec_key{
	      id = dnsxd_lib:new_id(),
	      incept = Now + Incept1,
	      expire = Now + Expire1,
	      alg = 7,
	      ksk = KSK,
	      key = PKey},
	    Req = {add_dnssec_key, NewKey},
	    build_requests(Opts4, [Req|Requests]);
	Reason ->
	    dnsxd_shell_lib:fail("Failed to generate RSA key:~n~p", [Reason])
    end;
build_requests([{nsec3_salt, Salt}|Opts], Requests)
  when is_binary(Salt) ->
    case byte_size(Salt) =< 255 of
	true ->
	    Req = {nsec3salt, Salt},
	    build_requests(Opts, [Req|Requests]);
	false ->
	    dnsxd_shell_lib:fail("Salt must be less than 255 bytes")
    end;
build_requests([{nsec3_iterations, Iter}|Opts], Requests)
  when is_integer(Iter) ->
       case Iter >= 0 of
	   true ->
	       Req = {nsec3iter, Iter},
	       build_requests(Opts, [Req|Requests]);
	   false ->
	       dnsxd_shell_lib:fail("Salt must be less than 255 bytes")
       end;
build_requests([{delete, Id}|Opts], Requests) ->
    Req = {delete_dnssec_key, Id},
    build_requests(Opts, [Req|Requests]);
build_requests([{siglife, Siglife}|Opts], Requests)
  when is_integer(Siglife) ->
    case Siglife >= 0 of
	true ->
	    Req = {dnssec_siglife, Siglife},
	    build_requests(Opts, [Req|Requests]);
	false ->
	    Msg = "Signature life must be a number greater than 0",
	    dnsxd_shell_lib:fail(Msg)
    end;
build_requests([Action|Opts], Requests)
  when Action =:= list orelse Action =:= status->
    Req = {Action, true},
    build_requests(Opts, [Req|Requests]).

get_key_gen_param(Key, List) -> get_key_gen_param(Key, List, []).

get_key_gen_param(Key, [], Past) ->
    {default_key_gen_param(Key), lists:reverse(Past)};
get_key_gen_param(Key, [Key|Rest], Past) ->
    {true, lists:reverse(Past) ++ Rest};
get_key_gen_param(Key, [{Key, Value}|Rest], Past) ->
    {Value, lists:reverse(Past) ++ Rest};
get_key_gen_param(Key, [Subject|Rest] = Current, Past) ->
    SubjectKey = case Subject of
		     Atom when is_atom(Atom) -> Atom;
		     {Atom, _} when is_atom(Atom) -> Atom
		 end,
    case lists:member(SubjectKey, [ksk, bits, incept, expire]) of
	true ->
	    NewPast = [Subject|Past],
	    get_key_gen_param(Key, Rest, NewPast);
	false -> {default_key_gen_param(Key), lists:reverse(Past) ++ Current}
    end.

default_key_gen_param(ksk) -> false;
default_key_gen_param(bits) -> undefined;
default_key_gen_param(incept) -> 0;
default_key_gen_param(expire) -> 0.
