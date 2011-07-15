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
-module(dnsxd_shell_admin).

-export([main/4]).

-define(MOD_PREFIX, ?MODULE_STRING "_").
-define(MOD_SUFFIXES, ["zone", "dnssec", "tsig"]).

main(_NameArg, _CookieArg, _EtcDir, []) -> usage(0);
main(NameArg, CookieArg, _EtcDir, [ModSuffix|Args]) ->
    case lists:member(ModSuffix, ?MOD_SUFFIXES) of
	true ->
	    Mod = list_to_atom(?MOD_PREFIX ++ ModSuffix),
	    Mod:main(NameArg, CookieArg, Args);
	false -> usage(1)
    end.

usage(ExitCode) ->
    Commands = string:join(?MOD_SUFFIXES, "|"),
    io:format("Usage: dnsxd-admin [~s] [-h] [...]~n~n"
	      "  -h, --help		Display help options~n~n"
	      "Run dnsxd-admin [~s] -h for more options.~n",
	      [Commands, Commands]),
    dnsxd_shell_lib:halt(ExitCode).
