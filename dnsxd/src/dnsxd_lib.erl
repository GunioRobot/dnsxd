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
-module(dnsxd_lib).
-include("dnsxd_internal.hrl").

%% API
-export([ensure_apps_started/1, new_id/0,
	 active_rr_fun/0, active_rr_fun/1, active_rr/2,
	 to_dns_rr/1, to_dns_rr/2, is_dnssd_rr/2,
	 use_procket/0, procket_open/4, cancel_timer/1,
	 ip_to_txt/1]).

%%%===================================================================
%%% API
%%%===================================================================

ensure_apps_started([]) -> ok;
ensure_apps_started([App|Apps]) ->
    case application:start(App) of
	ok -> ensure_apps_started(Apps);
	{error, {already_started, _}} -> ensure_apps_started(Apps);
	{error, _Reason} = Error -> Error
    end.

new_id() ->
    Bin = crypto:sha(term_to_binary({make_ref(), os:timestamp()})),
    new_id(Bin).
new_id(Bin) when is_binary(Bin) ->
    << <<(new_id(I))>> || <<I:5>> <= Bin >>;
new_id(Int)
  when is_integer(Int) andalso Int >= 0 andalso Int =< 9 -> Int + 48;
new_id(Int)
  when is_integer(Int) andalso Int >= 10 andalso Int =< 31 -> Int + 87.

active_rr_fun() -> Now = dns:unix_time(), active_rr_fun(Now).

active_rr_fun(Now) when is_integer(Now) ->
    fun(RR) -> ?MODULE:active_rr(Now, RR) end.

active_rr(Now, RRs) when is_list(RRs) ->
    [ RR || RR <- RRs, active_rr(Now, RR) ];
active_rr(Now, #dnsxd_rr{incept = Incept})
  when is_integer(Incept) andalso Incept > Now -> false; %% not yet active
active_rr(Now, #dnsxd_rr{expire = Expire})
  when is_integer(Expire) andalso Expire =< Now -> false; %% expired
active_rr(_Now, #dnsxd_rr{}) -> true.

to_dns_rr(RRs) when is_list(RRs) -> [ to_dns_rr(RR) || RR <- RRs ];
to_dns_rr(#dnsxd_rr{name = Name, class = Class, type = Type, ttl = TTL,
		    data = Data}) ->
    #dns_rr{name = Name, class = Class, type = Type, ttl = TTL, data = Data}.

to_dns_rr(Now, RRs) when is_integer(Now) andalso is_list(RRs) ->
    {DnsRR, TTLs} = lists:mapfoldl(fun(RR, Acc) -> to_dns_rr(Now, RR, Acc) end,
				   gb_trees:empty(), RRs),
    GetTTL = fun(#dns_rr{} = RR) ->
		     Hash = hash(RR),
		     gb_trees:get(Hash, TTLs)
	     end,
    [ RR#dns_rr{ttl = GetTTL(RR)} || RR <- DnsRR ].

to_dns_rr(Now, #dnsxd_rr{name = Name, class = Class, type = Type,
			 ttl = TTL, data = Data, expire = Expire} = RR, TTLs)
  when is_integer(Now) ->
    DynTTL = case is_integer(Expire) of
		 true ->
		     TTE = Expire - Now,
		     if TTE =< 0 -> 0;
			TTE < TTL -> TTE;
			true -> TTL end;
		 false -> TTL
	     end,
    Hash = hash(RR),
    NewTTLs = case gb_trees:lookup(Hash, TTLs) of
		  {value, Value} when Value < DynTTL -> TTLs;
		  {value, _} -> gb_trees:update(Hash, DynTTL, TTLs);
		  none -> gb_trees:insert(Hash, DynTTL, TTLs)
	      end,
    NewRR = #dns_rr{name = Name, class = Class, type = Type, data = Data},
    {NewRR, NewTTLs}.

is_dnssd_rr(ZoneName, #dns_rr{name = Name, type = Type}) ->
    is_dnssd_rr(ZoneName, Name, Type);
is_dnssd_rr(ZoneName, #dnsxd_rr{name = Name, type = Type}) ->
    is_dnssd_rr(ZoneName, Name, Type).

is_dnssd_rr(ZoneName, Name, Type) when is_atom(Type) ->
    NewType = dns:type_to_int(Type),
    is_dnssd_rr(ZoneName, Name, NewType);
is_dnssd_rr(ZoneName, Name, Type) when is_binary(ZoneName) ->
    ZoneNameLabels = dns:dname_to_labels(ZoneName),
    is_dnssd_rr(ZoneNameLabels, Name, Type);
is_dnssd_rr(ZoneNameLabels, Name, ?DNS_TYPE_PTR) ->
    case dns:dname_to_labels(dns:dname_to_lower(Name)) of
	[<<$_, _/binary>>, <<"_sub">>, <<$_, _/binary>>, Proto|ZoneNameLabels]
	  when Proto =:= <<"_tcp">> orelse Proto =:= <<"_udp">> -> true;
	[<<$_, _/binary>>, Proto|ZoneNameLabels]
	  when Proto =:= <<"_tcp">> orelse Proto =:= <<"_udp">> -> true;
	[<<"_services">>, <<"_dns-sd">>, <<"_udp">>|ZoneNameLabels] -> true;
	_ -> false
    end;
is_dnssd_rr(ZoneNameLabels, Name, Type)
  when Type =:= ?DNS_TYPE_SRV orelse Type =:= ?DNS_TYPE_TXT ->
    case dns:dname_to_labels(dns:dname_to_lower(Name)) of
	[_, <<$_, _/binary>>, Proto|ZoneNameLabels] ->
	    Proto =:= <<"_tcp">> orelse Proto =:= <<"_udp">>;
	_ -> false
    end;
is_dnssd_rr(_ZoneNameLabels, _Name, _Type) -> false.

use_procket() ->
    case dnsxd:get_env(procket) of
	{ok, Props} when is_list(Props) -> proplists:get_bool(enabled, Props);
	_ -> false
    end.

procket_open(IP, Port, Protocol, Type) ->
    {ok, Props} = dnsxd:get_env(procket),
    Progname = proplists:get_value(progname, Props, "procket"),
    Family = case tuple_size(IP) of
		 4 -> inet;
		 8 -> inet6
	     end,
    Opts = [{progname, Progname}, {protocol, Protocol}, {type, Type},
	    {family, Family}],
    case procket:open(Port, Opts) of
	{ok, Fd} = Result ->
	    Parent = self(),
	    Fun = fun() ->
			  process_flag(trap_exit, true),
			  receive {'EXIT', Parent, _} -> ok end,
			  ok = procket:close(Fd)
		  end,
	    spawn_link(Fun),
	    Result;
	Result -> Result
    end.

cancel_timer(Ref) when is_reference(Ref) -> _ = erlang:cancel_timer(Ref), ok;
cancel_timer(_) -> ok.

ip_to_txt(IP)
  when is_tuple(IP) andalso tuple_size(IP) =:= 4 orelse tuple_size(IP) =:= 8 ->
    case list_to_binary(inet_parse:ntoa(IP)) of
	<<"::FFFF:", Bin/binary>> -> Bin;
	Bin -> Bin
    end.

%%%===================================================================
%%% Internal functions
%%%===================================================================

hash(#dns_rr{name = Name, class = Class, type = Type, data = Data}) ->
    hash(Name, Class, Type, Data);
hash(#dnsxd_rr{name = Name, class = Class, type = Type, data = Data}) ->
    hash(Name, Class, Type, Data).

hash(Name, Class, ?DNS_TYPE_RRSIG,
	       #dns_rrdata_rrsig{type_covered = Type}) when is_integer(Class) ->
    hash(Name, Class, Type, undefined);
hash(Name, Class, Type, Data) when is_atom(Type) ->
    NewType = dns:type_to_int(Type),
    hash(Name, Class, NewType, Data);
hash(Name, Class, Type, Data) when is_atom(Class) ->
    NewClass = dns:class_to_int(Class),
    hash(Name, NewClass, Type, Data);
hash(Name, Class, Type, _Data)
  when is_integer(Class) andalso is_integer(Type) ->
    erlang:phash2({Name, Class, Type}).
