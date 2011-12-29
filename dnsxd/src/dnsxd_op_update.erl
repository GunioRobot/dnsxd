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
-module(dnsxd_op_update).
-include("dnsxd_internal.hrl").

%% API
-export([handle/2]).

%%%===================================================================
%%% API
%%%===================================================================

handle(MsgCtx, #dns_message{questions = [#dns_query{name = ZoneNameM,
						    class = ?DNS_CLASS_IN,
						    type = ?DNS_TYPE_SOA}]
			   } = ReqMsg) ->
    ZoneName = dns:dname_to_lower(ZoneNameM),
    case dnsxd_op_ctx:tsig(MsgCtx) of
	#dnsxd_tsig_ctx{zonename = ZoneName, keyname = KeyName} ->
	    {ZoneName, Key} = dnsxd:get_key(KeyName),
	    LogProps = [{op, update}, {zone, ZoneName}, {keyname, KeyName}],
	    case run(MsgCtx, ReqMsg, Key) of
		{RC, undefined} ->
		    dnsxd:log(MsgCtx, [{rc, RC}|LogProps]),
		    dnsxd_op_ctx:reply(MsgCtx, ReqMsg, [{rc, RC}]);
		{RC, Lease} when is_integer(Lease) ->
		    ReplyProps = [{rc, RC}],
		    LogPropsRC = [{rc, RC}|LogProps],
		    case has_ul(ReqMsg) of
			true ->
			    dnsxd:log(MsgCtx, [{lease, Lease}|LogPropsRC]),
			    UL = #dns_opt_ul{lease = Lease},
			    dnsxd_op_ctx:reply(MsgCtx, ReqMsg, [UL|ReplyProps]);
			false ->
			    dnsxd:log(MsgCtx, LogPropsRC),
			    dnsxd_op_ctx:reply(MsgCtx, ReqMsg, ReplyProps)
		    end
	    end;
	_ ->
	    dnsxd:log(MsgCtx, [{zone, ZoneName},
			       {rc, ?DNS_RCODE_NOTAUTH},
			       {op, ?DNS_OPCODE_UPDATE}]),
	    dnsxd_op_ctx:reply(MsgCtx, ReqMsg, [{rc, ?DNS_RCODE_NOTAUTH}])
    end;
handle(MsgCtx, #dns_message{} = ReqMsg) ->
    dnsxd_op_ctx:reply(MsgCtx, ReqMsg, [{rc, ?DNS_RCODE_FORMERR}]).

%%%===================================================================
%%% Internal functions
%%%===================================================================

run(MsgCtx,
    #dns_message{questions = [#dns_query{name = ZoneNameM}],
		 answers = PreReqs, authority = Updates} = ReqMsg,
    #dnsxd_tsig_key{name = KeyName, dnssd_only = DNSSDOnly} = Key) ->
    ZoneName = dns:dname_to_lower(ZoneNameM),
    ZoneNameLabels = dns:dname_to_labels(ZoneName),
    KeyNameSize = byte_size(KeyName),
    FullKeyName = <<KeyName:KeyNameSize/binary, $., ZoneName/binary>>,
    Fun = fun(RR) -> is_dnssd_rr(ZoneNameLabels, FullKeyName, RR) end,
    case prescan(ZoneName, Updates) of
	ok when DNSSDOnly ->
	    case lists:all(Fun, PreReqs) of
		true ->
		    case lists:all(Fun, Updates) of
			true -> update(MsgCtx, ReqMsg, Key);
			false -> {refused, undefined}
		    end;
		false -> {refused, undefined}
	    end;
	ok -> update(MsgCtx, ReqMsg, Key);
	RC -> {RC, undefined}
    end.

update(MsgCtx,
       #dns_message{questions = [#dns_query{name = ZoneName,
					    class = ZoneClass}],
		    answers = PreReqRR, authority = UpdateRR} = ReqMsg,
       #dnsxd_tsig_key{} = Key) ->
    LeaseLength = get_ull(ReqMsg),
    PreReqFun = fun(RR) -> rr_to_prereq(ZoneClass, RR) end,
    UpdateFun = fun(RR) -> rr_to_update(ZoneClass, LeaseLength, RR) end,
    try
	PreReqTuple = lists:map(PreReqFun, PreReqRR),
	UpdateTuple = lists:map(UpdateFun, UpdateRR),
	Datastore = dnsxd:datastore(),
	RC = Datastore:dnsxd_dns_update(MsgCtx, Key, ZoneName, ZoneClass,
					PreReqTuple, UpdateTuple),
	{RC, LeaseLength}
    catch throw:formerr ->
	    {?DNS_RCODE_FORMERR, undefined}
    end.

rr_to_prereq(_, #dns_rr{name = Name,
			class = ?DNS_CLASS_NONE,
			type = ?DNS_TYPE_ANY,
			data = <<>>}) ->
    {not_exist, dns:dname_to_lower(Name)};
rr_to_prereq(_, #dns_rr{name = Name,
			class = ?DNS_CLASS_NONE,
			type = Type,
			data = <<>>}) ->
    {not_exist, dns:dname_to_lower(Name), Type};
rr_to_prereq(_, #dns_rr{name = Name,
			class = ?DNS_CLASS_ANY,
			type = ?DNS_CLASS_ANY,
			data = <<>>}) ->
    {exist, dns:dname_to_lower(Name)};
rr_to_prereq(_, #dns_rr{name = Name,
			class = ?DNS_CLASS_ANY,
			type = Type,
			data = <<>>}) ->
    {exist, dns:dname_to_lower(Name), Type};
rr_to_prereq(Class, #dns_rr{name = Name,
			    class = Class,
			    type = Type,
			    data = Data}) ->
    {exist, dns:dname_to_lower(Name), Type, Data};
rr_to_prereq(_, _) -> throw(formerr).

rr_to_update(Class, LeaseLength, #dns_rr{name = Name,
					 class = Class,
					 type = Type,
					 ttl = TTL,
					 data = Data}) ->
    {add, dns:dname_to_lower(Name), Type, TTL, Data, LeaseLength};
rr_to_update(_Class, _LeaseLength,
	     #dns_rr{name = Name,
		     class = ?DNS_CLASS_ANY,
		     type = ?DNS_TYPE_ANY,
		     data = <<>>}) ->
    {delete, dns:dname_to_lower(Name)};
rr_to_update(_Class, _LeaseLength,
	     #dns_rr{name = Name,
		     class = ?DNS_CLASS_ANY,
		     type = Type,
		     data = <<>>}) ->
    {delete, dns:dname_to_lower(Name), Type};
rr_to_update(_Class, _LeaseLength,
	     #dns_rr{name = Name,
		     class = ?DNS_CLASS_NONE,
		     type = Type,
		     data = Data}) ->
    {delete, dns:dname_to_lower(Name), Type, Data};
rr_to_update(_Class, _LeaseLength, _RR) -> throw(formerr).

is_dnssd_rr(_ZoneNameLabels, KeyName, #dns_rr{type = Type, name = KeyName})
  when Type =:= aaaa orelse Type =:= a -> true;
is_dnssd_rr(_ZoneNameLabels, KeyName, #dns_rr{type = Type, name = Name})
  when Type =:= ?DNS_TYPE_AAAA orelse Type =:= ?DNS_TYPE_A ->
    dns:dname_to_lower(Name) =:= dns:dname_to_lower(KeyName);
is_dnssd_rr(ZoneNameLabels, _KeyName, #dns_rr{} = RR) ->
    dnsxd_lib:is_dnssd_rr(ZoneNameLabels, RR).

get_ull(#dns_message{additional = [#dns_optrr{data = Data}|_]}) ->
    Opts = dnsxd:update_opts(),
    MinLease = proplists:get_value(min_lease, Opts, 600),
    MaxLease = proplists:get_value(max_lease, Opts, 1200),
    Default = case proplists:get_value(default_lease, Opts, undefined) of
		  min_lease -> MinLease;
		  max_lease -> MaxLease;
		  Other -> Other
	      end,
    case lists:keyfind(dns_opt_ul, 1, Data) of
	#dns_opt_ul{lease = Lease}
	  when is_integer(Lease) andalso Lease > 0 ->
	    if Lease < MinLease -> MinLease;
	       Lease > MaxLease -> MaxLease;
	       true -> Lease end;
	false -> Default
    end;
get_ull(_) ->
    Opts = dnsxd:update_opts(),
    MinLease = proplists:get_value(min_lease, Opts, 600),
    MaxLease = proplists:get_value(max_lease, Opts, 1800),
    case proplists:get_value(default_lease, Opts, undefined) of
	min_lease -> MinLease;
	max_lease -> MaxLease;
	Other -> Other
    end.

prescan(_ZoneName, []) -> ok;
prescan(_ZoneName, [#dns_rr{type = Type}|_])
  when Type =:= axfr orelse
       Type =:= maila orelse
       Type =:= mailb -> formerr;
prescan(_ZoneName, [#dns_rr{class = Class, type = ?DNS_TYPE_ANY}|_])
  when Class =:= in orelse Class =:= none -> formerr;
prescan(_ZoneName, [#dns_rr{class = ?DNS_CLASS_ANY, ttl = TTL, data = Data}|_])
  when TTL =/= 0 orelse Data =/= <<>> -> formerr;
prescan(_ZoneName, [#dns_rr{class = ?DNS_CLASS_NONE, ttl = TTL}|_])
  when TTL =/= 0 -> formerr;
prescan(ZoneName, [#dns_rr{name = ZoneName}|RRs]) -> prescan(ZoneName, RRs);
prescan(ZoneName, [#dns_rr{name = NameM}|RRs]) ->
    Name = dns:dname_to_lower(NameM),
    NameSize = byte_size(Name),
    ZoneNameSize = byte_size(ZoneName),
    ChildLabelsSize = NameSize - ZoneNameSize - 1,
    case Name of
	ZoneName -> prescan(ZoneName, RRs);
	<<_:ChildLabelsSize/binary, $., ZoneName/binary>> ->
	    prescan(ZoneName, RRs);
	_ -> notzone
    end.

has_ul(#dns_message{additional = [#dns_optrr{data = Data}|_]}) ->
    lists:keymember(dns_opt_ul, 1, Data);
has_ul(_) -> false.
