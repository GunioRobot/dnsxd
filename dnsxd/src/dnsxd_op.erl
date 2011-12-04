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
-module(dnsxd_op).
-include("dnsxd_internal.hrl").

%% API
-export([dispatch/2]).

%%%===================================================================
%%% API
%%%===================================================================

dispatch(MsgCtx, ReqMsgBin) when is_binary(ReqMsgBin) ->
    try dns:decode_message(ReqMsgBin) of
	#dns_message{} = ReqMsg ->
	    MsgCtx0 = set_max_size(MsgCtx, ReqMsg),
	    case get_tsig(ReqMsg) of
		#dns_rr{} = TSIG ->
		    verify_tsig(MsgCtx0, ReqMsg, TSIG, ReqMsgBin);
		undefined -> dispatch(MsgCtx0, ReqMsg)
	    end;
	{Error, #dns_message{} = ReqMsg, _RemainingBin} ->
	    Proto = dnsxd_op_ctx:protocol(MsgCtx),
	    if Error =:= truncated andalso Proto =:= udp ->
		    ?DNSXD_ERR("Partial message received. "
			       "Larger udp_recbuf_size may be needed.");
	       true -> dnsxd_op_ctx:reply(MsgCtx, ReqMsg, [{rc, formerr}]) end;
	{_Error, undefined, _RemainingBin} -> ok
    catch Class:Exception ->
	    ?DNSXD_ERR(
	       "Error decoding message.~n"
	       "Class: ~p Exception: ~p Stack Trace:~n~p~n",
	       [Class, Exception, erlang:get_stacktrace()]
	      )
    end;
dispatch(MsgCtx, #dns_message{} = ReqMsg) ->
    Handler = handler(ReqMsg),
    try ok = Handler(MsgCtx, ReqMsg)
    catch Class:Exception ->
	    ?DNSXD_ERR(
	       "Error calling ~p.~n"
	       "Class: ~p Exception: ~p Stack Trace:~n~p~n"
	       "dnsxd_msg context:~n~p",
	       [Handler, Class, Exception, erlang:get_stacktrace(), MsgCtx]
	      ),
	    ok = try_send_servfail(MsgCtx, ReqMsg)
    end.

%%%===================================================================
%%% Internal functions
%%%===================================================================

handler(#dns_message{oc = 'query',
		     qc = 1,
		     questions = [#dns_query{type = ?DNS_TYPE_MAILA}]}) ->
    fun dnsxd_op_notimp:handle/2;
handler(#dns_message{oc = 'query', qc = 1,
		     questions = [#dns_query{type = ?DNS_TYPE_MAILB}]}) ->
    fun dnsxd_op_notimp:handle/2;
handler(#dns_message{oc = 'query', qc = 1,
		     questions = [#dns_query{type = ?DNS_TYPE_AXFR}]}) ->
    fun dnsxd_op_axfr:handle/2;
handler(#dns_message{oc = 'query', qc = 1} = Msg) ->
    case has_llq(Msg) of
	true -> fun dnsxd_op_llq:handle/2;
	false -> fun dnsxd_op_query:handle/2
    end;
handler(#dns_message{oc = 'update', qc = 1}) -> fun dnsxd_op_update:handle/2;
handler(_) -> fun dnsxd_op_notimp:handle/2.

set_max_size(MsgCtx, #dns_message{additional = Additional}) ->
    case dnsxd_op_ctx:protocol(MsgCtx) of
	udp ->
	    MaxSize = max_udp_payload(),
	    case Additional of
		[#dns_optrr{udp_payload_size = ClientSize}|_]
		  when is_integer(ClientSize) ->
		    Size = if ClientSize =< 512 -> 512;
			      ClientSize >= MaxSize -> MaxSize;
			      true -> ClientSize end,
		    dnsxd_op_ctx:max_size(MsgCtx, Size);
		_ ->
		    dnsxd_op_ctx:max_size(MsgCtx, 512)
	    end;
	_ -> dnsxd_op_ctx:max_size(MsgCtx, 65535)
    end.

get_tsig(#dns_message{additional = []}) -> undefined;
get_tsig(#dns_message{additional = Additional}) ->
    case hd(lists:reverse(Additional)) of
	#dns_rr{type = ?DNS_TYPE_TSIG, data = #dns_rrdata_tsig{}} = TSIG ->
	    TSIG;
	_ -> undefined
    end.

verify_tsig(MsgCtx, #dns_message{oc = OC} = ReqMsg,
	    #dns_rr{name = KeyNameM, data = Data}, ReqMsgBin) ->
    #dns_rrdata_tsig{alg = AlgM, msgid = MsgId} = Data,
    Alg = dns:dname_to_lower(AlgM),
    KeyName = dns:dname_to_lower(KeyNameM),
    Reply = ReqMsg#dns_message{qr = true, rc = notauth,
			       anc = 0, answers = [],
			       auc = 0, authority = [],
			       adc = 0, additional = []},
    LogProps = [{op, OC}, {rc, notauth}, {keyname, KeyName}],
    case dnsxd:get_key(KeyName) of
	{ZoneName, #dnsxd_tsig_key{secret = Secret}} ->
	    LogPropsZone = [{zone, ZoneName}|LogProps],
	    case dns:verify_tsig(ReqMsgBin, KeyName, Secret) of
		{ok, MAC} when is_binary(MAC) ->
		    TSIGCtx = #dnsxd_tsig_ctx{zonename = ZoneName,
					      keyname = KeyName,
					      alg = Alg,
					      secret = Secret,
					      mac = MAC,
					      msgid = MsgId},
		    NewMsgCtx = dnsxd_op_ctx:tsig(MsgCtx, TSIGCtx),
		    dispatch(NewMsgCtx, ReqMsg);
		{ok, badtime} ->
		    RespMsg = dns:add_tsig(Reply, Alg, <<>>, <<>>, badtime,
					   [{other, <<(dns:unix_time()):32>>}]),
		    dnsxd:log(MsgCtx, [{tsig_err, badtime}|LogPropsZone]),
		    dnsxd_op_ctx:to_wire(MsgCtx, RespMsg);
		{ok, TSIGRC} ->
		    RespMsg = dns:add_tsig(Reply, Alg, <<>>, <<>>, TSIGRC),
		    dnsxd:log(MsgCtx, [{tsig_err, TSIGRC}|LogPropsZone]),
		    dnsxd_op_ctx:to_wire(MsgCtx, RespMsg);
		{error, bad_alg} ->
		    RespMsg = dns:add_tsig(Reply, Alg, <<>>, <<>>, badsig),
		    dnsxd:log(MsgCtx, [{tsig_err, badalg}|LogPropsZone]),
		    dnsxd_op_ctx:to_wire(MsgCtx, RespMsg)
	    end;
	undefined ->
	    case dnsxd_ds_server:zone_for_name(KeyName) of
		undefined -> ok;
		ZoneName ->
		    dnsxd:log(MsgCtx, [{zone, ZoneName},
				       {tsig_err, badkey}|LogProps])
	    end,
	    RespMsg = dns:add_tsig(Reply, Alg, <<>>, <<>>, badkey),
	    dnsxd_op_ctx:to_wire(MsgCtx, RespMsg)
    end.

has_llq(#dns_message{additional = [#dns_optrr{data = Data}|_]}) ->
    lists:keymember(dns_opt_llq, 1, Data);
has_llq(_) -> false.

try_send_servfail(Ctx, #dns_message{} = ReqMsg) ->
    try
	RespMsg = ReqMsg#dns_message{qr = true, rc = servfail},
	RespMsgBin = dns:encode_message(RespMsg),
	ok = dnsxd_op_ctx:send(Ctx, RespMsgBin)
    catch Class:Exception ->
	    ?DNSXD_INFO(
	       "unable to reply with servfail.~nClass: ~p Exception: ~p~n~p",
	       [Class, Exception, erlang:get_stacktrace()]
	      )
    end.

max_udp_payload() ->
    case dnsxd:get_env(udp_payload_size) of
	{ok, PayloadSize}
	  when is_integer(PayloadSize) andalso PayloadSize >= 512 ->
	    PayloadSize;
	_ -> 1440
    end.
