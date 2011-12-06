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
-module(dnsxd_op_ctx).
-include("dnsxd_internal.hrl").

%% API
-export([new_udp/5, new_tcp/3]).
-export([protocol/1,
	 src/1, dst/1,
	 src_ip/1, src_port/1,
	 dst_ip/1, dst_port/1,
	 send/2,
	 tsig/1, tsig/2,
	 max_size/1, max_size/2,
	 to_wire/2, to_wire/3, reply/3]).

-record(dnsxd_op_ctx, {protocol,
		       socket,
		       src_ip,
		       src_port,
		       dst_ip,
		       dst_port,
		       tsig,
		       max_size = 512
		      }).

%%%===================================================================
%%% API
%%%===================================================================

new_udp(Socket, SrcIP, SrcPort, DstIP, DstPort) ->
    Ctx = #dnsxd_op_ctx{protocol = udp, src_ip = SrcIP, src_port = SrcPort},
    new(Ctx, Socket, DstIP, DstPort).

new_tcp(Socket, DstIP, DstPort) ->
    Ctx = #dnsxd_op_ctx{protocol = tcp, socket = Socket},
    new(Ctx, Socket, DstIP, DstPort).

new(#dnsxd_op_ctx{} = Ctx, Socket, DstIP, DstPort) ->
    Ctx#dnsxd_op_ctx{socket = Socket, dst_ip = DstIP, dst_port = DstPort}.

protocol(#dnsxd_op_ctx{protocol = Protocol}) -> Protocol.

src(#dnsxd_op_ctx{protocol = udp, src_port = SrcPort, src_ip = SrcIP}) ->
    {SrcIP, SrcPort};
src(#dnsxd_op_ctx{protocol = tcp, socket = Socket}) ->
    {ok, {_SrcIP, _SrcPort} = Src} = inet:peername(Socket),
    Src.

src_ip(#dnsxd_op_ctx{} = Ctx) -> {SrcIP, _SrcPort} = src(Ctx), SrcIP.

src_port(#dnsxd_op_ctx{} = Ctx) -> {_SrcIP, SrcPort} = src(Ctx), SrcPort.

dst(#dnsxd_op_ctx{dst_ip = DstIP, dst_port = DstPort}) -> {DstIP, DstPort}.

dst_ip(#dnsxd_op_ctx{dst_ip = DstIP}) -> DstIP.

dst_port(#dnsxd_op_ctx{dst_port = DstPort}) -> DstPort.

send(#dnsxd_op_ctx{protocol = udp,
		   socket = Socket,
		   src_ip = SrcIP,
		   src_port = SrcPort}, Message) ->
    gen_udp:send(Socket, SrcIP, SrcPort, Message);
send(#dnsxd_op_ctx{protocol = tcp, socket = Socket}, Message) ->
    gen_tcp:send(Socket, Message).

tsig(#dnsxd_op_ctx{tsig = TSIG}) -> TSIG.

tsig(#dnsxd_op_ctx{} = Ctx, NewTSIG) -> Ctx#dnsxd_op_ctx{tsig = NewTSIG}.

max_size(#dnsxd_op_ctx{max_size = MaxSize}) -> MaxSize.

max_size(#dnsxd_op_ctx{} = Ctx, NewMaxSize) ->
    Ctx#dnsxd_op_ctx{max_size = NewMaxSize}.

to_wire(MsgCtx, #dns_message{} = Message) -> to_wire(MsgCtx, Message, true).

to_wire(MsgCtx, #dns_message{} = Message, AutoTC) when is_boolean(AutoTC) ->
    to_wire_internal(MsgCtx, Message, AutoTC, dict:new()).

reply(MsgCtx,
      #dns_message{additional = [#dns_optrr{} = OptRR|_]} = Msg, Props) ->
    NewOptRR = build_optrr(MsgCtx, OptRR, Props),
    NewProps = case lists:keytake(ad, 1, Props) of
		   {value, {ad, Additional}, Props0}
		     when is_list(Additional) ->
		       NewAdditional = [NewOptRR|Additional],
		       [{ad, NewAdditional}|Props0];
		   false ->
		       [{ad, [NewOptRR]}|Props]
	       end,
    reply_body(MsgCtx, Msg, NewProps);
reply(MsgCtx, #dns_message{} = Msg, Props) ->
    reply_body(MsgCtx, Msg, Props).

%%%===================================================================
%%% Internal functions
%%%===================================================================

reply_body(MsgCtx, Msg, Props) ->
    Now = dns:unix_time(),
    RC = proplists:get_value(rc, Props, noerror),
    AA = proplists:get_bool(aa, Props),
    DNSSEC = proplists:get_bool(dnssec, Props),
    An = to_rr(Now, DNSSEC, proplists:get_value(an, Props, [])),
    AnLen = length(An),
    Au = to_rr(Now, DNSSEC, proplists:get_value(au, Props, [])),
    AuLen = length(Au),
    Ad = to_rr(Now, DNSSEC, proplists:get_value(ad, Props, [])),
    AdLen = length(Ad),
    RespMsg = Msg#dns_message{qr = true, rc = RC, aa = AA,
			      anc = AnLen, answers = An,
			      auc = AuLen, authority = Au,
			      adc = AdLen, additional = Ad},
    to_wire(MsgCtx, RespMsg).

to_rr(Now, DNSSEC, RRs) when is_list(RRs) ->
    lists:foldr(fun(#dns_rr{} = RR, Acc) -> [RR|Acc];
		   (#dnsxd_rr{name = Name,
			      class = Class,
			      type = Type,
			      data = Data} = RR, Acc) ->
			[#dns_rr{name = Name,
				 class = Class,
				 type = Type,
				 ttl = ttl(Now, RR),
				 data = Data}|Acc];
		   (#rrset{} = Set, Acc) -> to_rr(Now, DNSSEC, Set, Acc);
		   (Other, Acc) -> [Other|Acc]
		end, [], RRs).

to_rr(Now, false, #rrset{name = Name, class = Class, type = Type,
			 data = Datas} = Set, Acc) ->
    TTL = ttl(Now, Set),
    lists:foldr(fun(Data, Acc0) ->
			[#dns_rr{name = Name,
				 class = Class,
				 type = Type,
				 ttl = TTL,
				 data = Data}|Acc0]
		end, Acc, Datas);
to_rr(Now, true, #rrset{name = Name, class = Class, sig = Sigs} = Set, Acc) ->
    TTL = ttl(Now, Set),
    Acc1 = lists:foldr(fun(Sig, Acc0) ->
			       [#dns_rr{name = Name,
					class = Class,
					type = ?DNS_TYPE_RRSIG,
					ttl = TTL,
					data = Sig}|Acc0]
		       end, Acc, Sigs),
    to_rr(Now, false, Set, Acc1).

ttl(Now, #dnsxd_rr{incept = Incept,
		   expire = Expire,
		   ttl = TTL}) -> ttl(Now, Incept, Expire, TTL);
ttl(Now, #rrset{incept = Incept, expire = Expire, ttl = TTL}) ->
    ttl(Now, Incept, Expire, TTL).

ttl(Now, Incept, Expire, NaturalTTL) ->
    case is_integer(Expire) of
	true ->
	    MinTTL = 0,
	    MaxTTL = 24 * 60 * 60, % config opts... or another way?
	    TTL = lists:min([Expire - Incept, Expire - Now, NaturalTTL]),
	    case TTL of
		TTL when TTL < MinTTL -> MinTTL;
		TTL when TTL > MaxTTL -> MaxTTL;
		TTL -> TTL
	    end;
	false -> NaturalTTL
    end.

build_optrr(MsgCtx, #dns_optrr{}, Props) ->
    PayloadSize = dnsxd_op_ctx:max_size(MsgCtx),
    DNSSEC = proplists:get_bool(dnssec, Props),
    Datas = [ EOpt || EOpt <- Props, is_eopt(EOpt) ],
    #dns_optrr{udp_payload_size = PayloadSize,
	       dnssec = DNSSEC,
	       data = Datas}.

is_eopt(#dns_opt_llq{}) -> true;
is_eopt(#dns_opt_ul{}) -> true;
is_eopt(#dns_opt_nsid{}) -> true;
is_eopt(_) -> false.

to_wire_internal(MsgCtx, #dns_message{} = Msg, AutoTC, Truncated) ->
    Protocol = protocol(MsgCtx),
    TC = Protocol =/= tcp andalso AutoTC,
    case to_wire_internal(MsgCtx, Msg, TC) of
	truncate when AutoTC =:= false -> truncate;
	truncate ->
	    {NewMsg, NewTruncated} = strip_rr(Msg, Truncated),
	    to_wire_internal(MsgCtx, NewMsg, AutoTC, NewTruncated);
	ok when Protocol =:= tcp ->
	    case dict:to_list(Truncated) of
		[] -> ok;
		Items ->
		    An = lists:reverse(proplists:get_value(an, Items, [])),
		    AnC = length(An),
		    Au = lists:reverse(proplists:get_value(au, Items, [])),
		    AuC = length(Au),
		    Ad = lists:reverse(proplists:get_value(ad, Items, [])),
		    AdC = length(Ad),
		    NewMsg = Msg#dns_message{anc = AnC, auc = AuC, adc = AdC,
					     answers = An,
					     authority = Au,
					     additional = Ad},
		    to_wire_internal(MsgCtx, NewMsg, AutoTC, dict:new())
	    end;
	Other -> Other
    end.

to_wire_internal(MsgCtx, #dns_message{additional = Add} = RespMsg0, TC) ->
    MaxSize = dnsxd_op_ctx:max_size(MsgCtx),
    RespMsg1 = case Add of
		   [#dns_optrr{} = OptRR|AddRest] ->
		       NewOptRR = OptRR#dns_optrr{udp_payload_size = MaxSize},
		       NewAdd = [NewOptRR|AddRest],
		       RespMsg0#dns_message{additional = NewAdd};
		   _ ->
		       RespMsg0
	       end,
    RespMsgBin = dns:encode_message(maybe_add_tsig(MsgCtx, RespMsg1)),
    if MaxSize >= byte_size(RespMsgBin) ->
	    dnsxd_op_ctx:send(MsgCtx, RespMsgBin);
       TC =:= false -> truncate;
       true ->
	    RespMsg2 = RespMsg1#dns_message{tc = true, anc = 0, adc = 0,
					    auc = 0, answers = [],
					    additional = [],
					    authority = []},
	    RespMsgBin1 = dns:encode_message(maybe_add_tsig(MsgCtx, RespMsg2)),
	    dnsxd_op_ctx:send(MsgCtx, RespMsgBin1)
    end.

maybe_add_tsig(MsgCtx, #dns_message{id = MsgId} = Msg0) ->
    case dnsxd_op_ctx:tsig(MsgCtx) of
	#dnsxd_tsig_ctx{keyname = KeyName,
			alg = Alg,
			secret = Secret,
			mac = MAC,
			msgid = OrigMsgId} ->
	    Opts = [{mac, MAC}],
	    Msg1 = Msg0#dns_message{id = OrigMsgId},
	    Msg2 = dns:add_tsig(Msg1, Alg, KeyName, Secret, noerror, Opts),
	    Msg2#dns_message{id = MsgId};
	undefined -> Msg0
    end.

strip_rr(#dns_message{anc = C, answers = RR, authority = [], additional = []
		     } = Msg, Truncated) when is_list(RR) andalso RR =/= [] ->
    NewC = C - 1,
    {NewRR, [PoppedRR]} = lists:split(NewC, RR),
    NewMessage = Msg#dns_message{anc = NewC, answers = NewRR},
    NewTruncated = dict:append(an, PoppedRR, Truncated),
    {NewMessage, NewTruncated};
strip_rr(#dns_message{auc = C, authority = RR, additional = []} = Msg,
	 Truncated) when is_list(RR) andalso RR =/= [] ->
    NewC = C - 1,
    {NewRR, [PoppedRR]} = lists:split(NewC, RR),
    NewMessage = Msg#dns_message{auc = NewC, authority = NewRR},
    NewTruncated = dict:append(au, PoppedRR, Truncated),
    {NewMessage, NewTruncated};
strip_rr(#dns_message{adc = C, additional = RR} = Msg, Truncated)
  when is_list(RR) andalso RR =/= [] ->
    NewC = C - 1,
    {NewRR, [PoppedRR]} = lists:split(NewC, RR),
    NewMessage = Msg#dns_message{adc = NewC, additional = NewRR},
    NewTruncated = dict:append(ad, PoppedRR, Truncated),
    {NewMessage, NewTruncated}.
