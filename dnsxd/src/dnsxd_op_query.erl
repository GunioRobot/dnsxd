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
-module(dnsxd_op_query).
-include("dnsxd_internal.hrl").

%% API
-export([handle/2]).

%%%===================================================================
%%% API
%%%===================================================================

handle(MsgCtx, #dns_message{qc = 1,
			    questions = [#dns_query{name = QName} = Q]
			   } = ReqMsg) ->
    case dnsxd:find_zone(QName) of
	#dnsxd_zone{dnssec_enabled = ZoneDNSSEC} = Zone ->
	    ClientDNSSEC = do_dnssec(ReqMsg),
	    DNSSEC = ClientDNSSEC andalso ZoneDNSSEC,
	    {RC, An, Au, Ad} = dnsxd_query:answer(Zone, Q, DNSSEC),
	    Props = [{rc, RC}, {dnssec, DNSSEC}, aa,
		     {an, An}, {au, Au}, {ad, Ad}],
	    dnsxd_op_ctx:reply(MsgCtx, ReqMsg, Props);
	_ -> dnsxd_op_ctx:reply(MsgCtx, ReqMsg, [{rc, refused}])
    end.

do_dnssec(#dns_message{additional=[#dns_optrr{dnssec = DNSSEC}|_]}) -> DNSSEC;
do_dnssec(#dns_message{}) -> false.
