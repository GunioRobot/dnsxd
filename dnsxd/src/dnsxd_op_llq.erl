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
-module(dnsxd_op_llq).
-include("dnsxd_internal.hrl").

%% API
-export([handle/2]).

%%%===================================================================
%%% API
%%%===================================================================

handle(MsgCtx,
       #dns_message{questions = [#dns_query{} = Query],
		    additional = [#dns_optrr{
				     data = [#dns_opt_llq{
						opcode = ?DNS_LLQOPCODE_SETUP,
						id = 0} = LLQ]
				    }]} = ReqMsg) ->
    case query_ok(Query) of
	true ->
	    case dnsxd:new_llq(self(), MsgCtx, ReqMsg) of
		ok -> ok;
		{ok, servfull} ->
		    Props = [LLQ#dns_opt_llq{
			       errorcode = ?DNS_LLQERRCODE_SERVFULL,
			       leaselife = 300}],
		    dnsxd_op_ctx:reply(MsgCtx, ReqMsg, Props);
		{ok, bad_zone} ->
		    Props = [LLQ#dns_opt_llq{
			       errorcode = ?DNS_LLQERRCODE_STATIC},
			     {rc, ?DNS_RCODE_REFUSED}],
		    dnsxd_op_ctx:reply(MsgCtx, ReqMsg, Props)
	    end;
	false ->
	    Props = [LLQ#dns_opt_llq{errorcode = ?DNS_LLQERRCODE_STATIC},
		     {rc, ?DNS_RCODE_REFUSED}],
	    dnsxd_op_ctx:reply(MsgCtx, ReqMsg, Props)
    end;
handle(MsgCtx, #dns_message{
	 additional = [#dns_optrr{data = [#dns_opt_llq{} = LLQ]} = OptRR]
	} = ReqMsg) ->
    case dnsxd:msg_llq(MsgCtx, ReqMsg) of
	ok -> ok;
	{error, ErrorCode} ->
	    RespLLQ = LLQ#dns_opt_llq{errorcode = ErrorCode},
	    RespOptRR = OptRR#dns_optrr{data = [RespLLQ]},
	    dnsxd_op_ctx:reply(MsgCtx, ReqMsg, [RespOptRR])
    end.

%%%===================================================================
%%% Internal functions
%%%===================================================================

query_ok(#dns_query{class = ?DNS_CLASS_ANY}) -> false;
query_ok(#dns_query{type = ?DNS_TYPE_ANY}) -> false;
query_ok(#dns_query{class = ?DNS_CLASS_NONE}) -> false;
query_ok(_) -> true.
