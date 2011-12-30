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
			    questions = [#dns_query{name = QName,
						    class = ?DNS_CLASS_IN,
						    type = Type}]
			   } = ReqMsg) ->
    Name = dns:dname_to_lower(QName),
    Props0 = case dnsxd_ds_server:zone_ref_for_name(Name) of
		 undefined -> [{rc, ?DNS_RCODE_REFUSED}];
		 Ref ->
		     DNSSEC = do_dnssec(ReqMsg, Ref),
		     Props = [{aa, true}, {ad, []}, {an, []}, {au, []},
			      {dnssec, DNSSEC}, {rc, ?DNS_RCODE_NXDOMAIN}],
		     answer(QName, Name, Type, Ref, Props)
	     end,
    dnsxd_op_ctx:reply(MsgCtx, ReqMsg, Props0);
handle(MsgCtx, #dns_message{} = ReqMsg) ->
    dnsxd_op_ctx:reply(MsgCtx, ReqMsg, [{rc, ?DNS_RCODE_REFUSED}]).

do_dnssec(#dns_message{additional=[#dns_optrr{dnssec = DNSSEC}|_]}, Ref) ->
    DNSSEC andalso dnsxd_ds_server:is_dnssec_zone(Ref);
do_dnssec(#dns_message{}, _Ref) -> false.

answer(QName, Name, ?DNS_TYPE_ANY, Ref, Props) ->
    DNSSEC = orddict:fetch(dnssec, Props),
    case dnsxd_ds_server:lookup_rrname(Ref, Name) of
	{found, Name} ->
	    Props0 = orddict:store(rc, ?DNS_RCODE_NOERROR, Props),
	    case dnsxd_ds_server:lookup_sets(Ref, QName, Name) of
		{match, Sets} ->
		    Props1 = orddict:append_list(an, Sets, Props0),
		    authority(Ref, Props1);
		{cut, CutSet, Sets} ->
		    Props1 = orddict:append(au, CutSet, Props0),
		    orddict:append_list(ad, Sets, Props1)
	    end;
	{found_wild, _LastName, PlainName, WildName} ->
	    Props0 = orddict:store(rc, ?DNS_RCODE_NOERROR, Props),
	    Props1 = append_nsec3_cover(Ref, PlainName, Props0, DNSSEC),
	    case dnsxd_ds_server:lookup_sets(Ref, QName, WildName) of
		{match, Sets} ->
		    Props2 = orddict:append_list(an, Sets, Props1),
		    authority(Ref, Props2);
		{cut, CutSet, Sets} ->
		    Props2 = orddict:append_list(au, CutSet, Props1),
		    Props3 = orddict:append_list(ad, Sets, Props2),
		    orddict:append_list(ad, Sets, Props3)
	    end;
	{no_name, LastName, PlainName, WildName} ->
	    case dnsxd_ds_server:get_cutters_set(Ref, LastName) of
		undefined ->
		    Cover = [LastName, PlainName, WildName],
		    Props0 = append_nsec3_cover(Ref, Cover, Props, DNSSEC),
		    authority(Ref, Props0);
		CutRR ->
		    Props0 = orddict:append(au, CutRR, Props),
		    Cover = case parent(LastName) of
				undefined -> [LastName];
				ParentName -> [ParentName, LastName]
			    end,
		    Props1 = append_nsec3_cover(Ref, Cover, Props0, DNSSEC),
		    authority(Ref, Props1)
	    end
    end;
answer(QName, Name, Type, Ref, Props) ->
    DNSSEC = orddict:fetch(dnssec, Props),
    case dnsxd_ds_server:lookup_rrname(Ref, Name) of
	{found, Name} ->
	    Props0 = orddict:store(rc, ?DNS_RCODE_NOERROR, Props),
	    case dnsxd_ds_server:lookup_set(Ref, QName, Name, Type) of
		nodata ->
		    Props1 = append_nsec3_cover(Ref, Name, Props0, DNSSEC),
		    authority(Ref, Props1);
		{match, RR} ->
		    Props1 = orddict:append(an, RR, Props0),
		    authority(Ref, Props1);
		{match, NewQName, RR} ->
		    Props1 = orddict:append(an, RR, Props0),
		    case follow_cname(Ref, Props1, NewQName) of
			true -> answer(NewQName, NewQName, Type, Ref, Props1);
			false -> authority(Ref, Props1)
		    end;
		{referral, CutRR, AdRR} ->
		    Props1 = case CutRR of
				 undefined -> Props0;
				 CutRR -> orddict:append(au, CutRR, Props0)
			     end,
		    Props2 = add_ds(Ref, CutRR, Props1, DNSSEC),
		    Props3 = case AdRR of
				 undefined -> Props2;
				 AdRR -> orddict:append(ad, AdRR, Props2)
			     end,
		    additional(Ref, Props3)
	    end;
	{found_wild, LastName, PlainName, WildName} ->
	    Props0 = orddict:store(rc, ?DNS_RCODE_NOERROR, Props),
	    Props1 = append_nsec3_cover(Ref, PlainName, Props0, DNSSEC),
	    case dnsxd_ds_server:lookup_set(Ref, QName, WildName, Type) of
		nodata ->
		    Cover = [WildName, LastName],
		    Props2 = append_nsec3_cover(Ref, Cover, Props1, DNSSEC),
		    authority(Ref, Props2);
		{match, RR} ->
		    Props2 = orddict:append(an, RR, Props1),
		    authority(Ref, Props2);
		{match, NewQName, RR} ->
		    Props2 = orddict:append_list(an, RR, Props1),
		    case follow_cname(Ref, Props2, NewQName) of
			true -> answer(NewQName, NewQName, Type, Ref, Props2);
			false -> authority(Ref, Props2)
		    end;
		{referral, CutRR, AdRR} ->
		    Props2 = orddict:append_list(au, CutRR, Props1),
		    Props3 = add_ds(Ref, CutRR, Props2, DNSSEC),
		    Props4 = case AdRR of
				 undefined -> Props3;
				 AdRR -> orddict:append(ad, AdRR, Props3)
			     end,
		    additional(Ref, Props4)
	    end;
	{no_name, LastName, PlainName, WildName} ->
	    case dnsxd_ds_server:get_cutters_set(Ref, LastName) of
		undefined ->
		    Cover = [LastName, PlainName, WildName],
		    Props0 = append_nsec3_cover(Ref, Cover, Props, DNSSEC),
		    authority(Ref, Props0);
		CutRR ->
		    Props0 = orddict:append(au, CutRR, Props),
		    Cover = case parent(LastName) of
				undefined -> [LastName];
				ParentName -> [ParentName, LastName]
			    end,
		    Props1 = append_nsec3_cover(Ref, Cover, Props0, DNSSEC),
		    authority(Ref, Props1)
	    end
    end.

authority(Ref, Props) ->
    Name = dnsxd_ds_server:zonename_from_ref(Ref),
    An = orddict:fetch(an, Props),
    Type = case An =:= [] of
	       true -> ?DNS_TYPE_SOA;
	       false -> ?DNS_TYPE_NS
	   end,
    case dnsxd_ds_server:lookup_set(Ref, Name, Name, Type) of
	{match, RRSet} ->
	    case lists:member(RRSet, An) of
		true -> additional(Ref, Props);
		false ->
		    Au = orddict:fetch(au, Props),
		    NewAu = [RRSet|Au],
		    Props0 = orddict:store(au, NewAu, Props),
		    additional(Ref, Props0)
	    end;
	nodata -> additional(Ref, Props)
    end.

additional(_Ref, Props) -> Props.

append_nsec3_cover(_Ref, _Names, Props, false) -> Props;
append_nsec3_cover(Ref, Name, Props, true) when is_binary(Name) ->
    append_nsec3_cover(Ref, [Name], Props, []);
append_nsec3_cover(Ref, Names, Props, true) when is_list(Names) ->
    append_nsec3_cover(Ref, Names, Props, []);
append_nsec3_cover(Ref, [Name|Names], Props, Collected) ->
    Cover = dnsxd_ds_server:get_nsec3_cover(Ref, Name),
    case lists:member(Cover, Collected) of
	true -> append_nsec3_cover(Ref, Names, Props, Collected);
	false ->
	    Collected0 = [Cover|Collected],
	    append_nsec3_cover(Ref, Names, Props, Collected0)
    end;
append_nsec3_cover(_Ref, [], Props, Collected) ->
    orddict:append_list(au, Collected, Props).

follow_cname(Ref, Results, NameM) ->
    An = orddict:fetch(an, Results),
    case lists:keymember(NameM, #rrset.name, An) of
	true -> false;
	false ->
	    Name = dns:dname_to_lower(NameM),
	    case dnsxd_ds_server:zonename_from_ref(Ref) of
		NameM -> true;
		ZoneName ->
		    NameSize = byte_size(Name),
		    ZoneNameSize = byte_size(Name),
		    if (ZoneNameSize + 1) >= NameSize -> false;
		       true ->
			    Pre = NameSize - ZoneNameSize - 1,
			    case Name of
				<<_:Pre/binary, $., ZoneName/binary>> -> true;
				_ -> false
			    end
		    end
	    end
    end.

parent(<<$., Name/binary>>) -> Name;
parent(<<"\\.", Name/binary>>) -> parent(Name);
parent(<<_, Name/binary>>) -> parent(Name);
parent(<<>>) -> undefined.

add_ds(Ref, #rrset{name = Name, type = ?DNS_TYPE_NS} = NSSet, Props, true) ->
    case dnsxd_ds_server:lookup_set(Ref, Name, Name, ?DNS_TYPE_DS) of
	{referral, NSSet, DSSet} -> orddict:append(au, DSSet, Props);
	_ -> Props
    end;
add_ds(_Ref, _RR, Props, _DNSSEC) -> Props.
