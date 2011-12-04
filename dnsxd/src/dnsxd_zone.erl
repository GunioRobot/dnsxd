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
-module(dnsxd_zone).

-export([prepare/1]).

prepare(#dnsxd_zone{} = Zone) ->
    Funs = [fun add_ds/1, fun pad_rr/1, fun add_serials_to_zone/1,
	    fun add_soa/1, fun order_rr/1, fun rmv_disabled_tk/1],
    #dnsxd_zone{} = lists:foldl(fun(Fun, Z) -> Fun(Z) end, Zone, Funs).

add_serials_to_zone(#dnsxd_zone{rr = RR} = Zone) ->
    NewSerials = get_serials(RR),
    Zone#dnsxd_zone{serials = NewSerials}.

add_ds(#dnsxd_zone{name = Name, dnssec_keys = Keys, soa_param = SOA,
		   rr = RR} = Zone) ->
    TTL = SOA#dnsxd_soa_param.expire,
    {DSRR, TaggedKeys} = add_ds(Name, TTL, Keys),
    NewRR = DSRR ++ RR,
    Zone#dnsxd_zone{rr = NewRR, dnssec_keys = TaggedKeys}.

add_ds(ZoneName, TTL, Keys) ->
    add_ds(ZoneName, TTL, Keys, [], []).

add_ds(_ZoneName, _TTL, [], DSRR, TaggedKeys) ->
    {DSRR, TaggedKeys};
add_ds(ZoneName, TTL, [#dnsxd_dnssec_key{alg = Alg} = Key|Keys],
       DSRR, TaggedKeys) when Alg =:= ?DNS_ALG_NSEC3RSASHA1 ->
    #dnsxd_dnssec_key{incept = Incept, expire = Expire} = Key,
    #dnsxd_dnssec_key{id = Id, ksk = KSK} = Key,
    PKBin = build_ds_publickey(Key),
    Flags = case KSK of
		true -> 257;
		false -> 256
	    end,
    DNSKeyData0 = #dns_rrdata_dnskey{flags = Flags, protocol = 3, alg = Alg,
				     public_key = PKBin},
    DNSKeyDataBin = dns:encode_rrdata(?DNS_CLASS_IN, DNSKeyData0),
    DNSKeyData = dns:decode_rrdata(?DNS_CLASS_IN, ?DNS_TYPE_DNSKEY,
				   DNSKeyDataBin),
    DNSKeyRR = #dnsxd_rr{name = ZoneName,
			 class = ?DNS_CLASS_IN,
			 type = ?DNS_TYPE_DNSKEY,
			 ttl = TTL,
			 data = DNSKeyData,
			 incept = Incept,
			 expire = Expire},
    DSKeyDigest = crypto:sha([dns:encode_dname(ZoneName), DNSKeyDataBin]),
    KeyTag = DNSKeyData#dns_rrdata_dnskey.key_tag,
-include("dnsxd_internal.hrl").
    DSKeyData = #dns_rrdata_ds{keytag = KeyTag,
			       alg = Alg,
			       digest_type = 1,
			       digest = DSKeyDigest},
    DSKeyRRName = <<Id/binary, "._dnsxd-ds.", ZoneName/binary>>,
    DSKeyRR = #dnsxd_rr{name = DSKeyRRName,
			class = ?DNS_CLASS_IN,
			type = ?DNS_TYPE_DS,
			ttl = TTL,
			data = DSKeyData,
			incept = Incept,
			expire = Expire},
    PTRRR = #dnsxd_rr{name = <<"_dnsxd-ds.", ZoneName/binary>>,
		      class = ?DNS_CLASS_IN,
		      type = ?DNS_TYPE_PTR,
		      ttl = TTL,
		      data = #dns_rrdata_ptr{dname = DSKeyRRName},
		      incept = Incept,
		      expire = Expire},
    NewDSRR = case KSK of
		  true -> [PTRRR, DSKeyRR, DNSKeyRR|DSRR];
		  false -> [DNSKeyRR|DSRR]
	      end,
    NewKey = Key#dnsxd_dnssec_key{keytag = KeyTag},
    NewTaggedKeys = [NewKey|TaggedKeys],
    add_ds(ZoneName, TTL, Keys, NewDSRR, NewTaggedKeys);
add_ds(ZoneName, TTL, [#dnsxd_dnssec_key{} = Key|Keys], DSRR, TaggedKeys) ->
    NewTaggedKeys = [Key|TaggedKeys],
    add_ds(ZoneName, TTL, Keys, DSRR, NewTaggedKeys).

build_ds_publickey(#dnsxd_dnssec_key{key = [<<ESize:32, E/binary>>,
					    <<_NSize:32, N/binary>>,
					    <<_DSize:32, _D/binary>>]}) ->
    case ESize > 255 of
	true -> <<0, ESize:16, E/binary, N/binary>>;
	false -> <<ESize:8, E/binary, N/binary>>
    end.

pad_rr(#dnsxd_zone{rr = RRs} = Zone) ->
    RRSets = to_rrsets(RRs),
    RRSigLife = case Zone of
		    #dnsxd_zone{dnssec_enabled = true,
				dnssec_siglife = Int}
		      when is_integer(Int) andalso Int > 0 ->
			Int;
		    _ ->
			undefined
		end,
    NewRRs = dict:fold(fun({_Name, _Class, _Type}, RRSetRRs, Acc) ->
			       Serials = get_active_serials(RRSetRRs),
			       SigSerials = pad_serials(RRSigLife, Serials),
			       pad_rr(SigSerials, RRSetRRs, Acc)
		       end, [], RRSets),
    Zone#dnsxd_zone{rr = NewRRs}.

pad_serials(SigLife, [FirstSerial|Serials])
  when is_integer(SigLife) andalso SigLife > 0 ->
    pad_serials(SigLife, [FirstSerial], Serials);
pad_serials(_, Serials) ->
    Serials.

pad_serials(_SigLife, Processed, []) ->
    lists:reverse(Processed);
pad_serials(SigLife, [LastSerial|_] = Processed, [NextSerial|Serials])
  when (NextSerial - LastSerial) =< SigLife ->
    pad_serials(SigLife, [NextSerial|Processed], Serials);
pad_serials(SigLife, [LastSerial|_] = Processed, Serials) ->
    NewSerial  = LastSerial + SigLife,
    pad_serials(SigLife, [NewSerial|Processed], Serials).

pad_rr(_Serials, [], PaddedRRs) -> PaddedRRs;
pad_rr(Serials, [RR|RRs], PaddedRRs) ->
    NewPaddedRRs = pad_rr(Serials, RR, PaddedRRs),
    pad_rr(Serials, RRs, NewPaddedRRs);
pad_rr([], #dnsxd_rr{}, PaddedRRs) -> PaddedRRs;
pad_rr([Serial|Serials], #dnsxd_rr{incept = Incept, expire = Expire} = RR,
       PaddedRRs) ->
    if is_integer(Expire) andalso Serial >= Expire ->
	    pad_rr(Serials, RR, PaddedRRs);
       is_integer(Incept) andalso Serial >= Incept ->
	    SIncept = Serial,
	    SExpire = case Serials of
			  [NextSerial|_] -> NextSerial;
			  _ -> undefined
		      end,
	    NewRR = RR#dnsxd_rr{incept = SIncept, expire = SExpire},
	    NewPaddedRRs = [NewRR|PaddedRRs],
	    pad_rr(Serials, RR, NewPaddedRRs);
       true -> pad_rr(Serials, RR, PaddedRRs)
    end.

to_rrsets(RRs) -> to_rrsets(RRs, dict:new()).

to_rrsets([], Dict) -> Dict;
to_rrsets([#dnsxd_rr{name = Name,
			   class = Class,
			   type = Type} = RR|RRs], Acc) ->
    NewAcc = dict:append({Name, Class, Type}, RR, Acc),
    to_rrsets(RRs, NewAcc).

get_active_serials([]) -> [];
get_active_serials(RR) ->
    Serials = get_serials(RR),
    Now = dns:unix_time(),
    get_active_serials(Now, Serials).

get_active_serials(_Now, [_] = Serials) -> Serials;
get_active_serials(Now, [_, Serial|_] = Serials) when Now < Serial -> Serials;
get_active_serials(Now, [_|Serials]) -> get_active_serials(Now, Serials).

%%% ADD SOA + RELATED %%%

add_soa(#dnsxd_zone{soa_param = #dnsxd_soa_param{mname = MName,
						 rname = RName,
						 refresh = Ref,
						 retry = Ret,
						 expire = Exp,
						 minimum = Min},
		    serials = Serials} = Zone) ->
    Data = #dns_rrdata_soa{mname = MName,
			   rname = RName,
			   refresh = Ref,
			   retry = Ret,
			   expire = Exp,
			   minimum = Min},
    add_soa(Zone, Serials, Data).

%% clause only for empty zones
add_soa(#dnsxd_zone{name = Name, rr = RRs} = Zone, [],
	#dns_rrdata_soa{minimum = TTL} = Data) ->
    RR = #dnsxd_rr{incept = dns:unix_time(),
		   expire = undefined,
		   name = Name,
		   class = ?DNS_CLASS_IN,
		   type = ?DNS_TYPE_SOA,
		   ttl = TTL,
		   data = Data#dns_rrdata_soa{serial = 0}},
    NewRRs = [RR|RRs],
    Zone#dnsxd_zone{rr = NewRRs};
%% clauses for non-empty zones
add_soa(#dnsxd_zone{name = Name, rr = RRs} = Zone,
	[Serial], #dns_rrdata_soa{minimum = TTL} = Data) ->
    RR = #dnsxd_rr{incept = Serial,
		   expire = undefined,
		   name = Name,
		   class = ?DNS_CLASS_IN,
		   type = ?DNS_TYPE_SOA,
		   ttl = TTL,
		   data = Data#dns_rrdata_soa{serial = Serial}},
    NewRRs = [RR|RRs],
    Zone#dnsxd_zone{rr = NewRRs};
add_soa(#dnsxd_zone{name = Name, rr = RRs} = Zone,
	[Serial|[Next|_] = Serials], #dns_rrdata_soa{minimum = TTL} = Data) ->
    RR = #dnsxd_rr{incept = Serial,
		   expire = Next,
		   name = Name,
		   class = ?DNS_CLASS_IN,
		   type = ?DNS_TYPE_SOA,
		   ttl = TTL,
		   data = Data#dns_rrdata_soa{serial = Serial}},
    NewRRs = [RR|RRs],
    NewZone = Zone#dnsxd_zone{rr = NewRRs},
    add_soa(NewZone, Serials, Data).

order_rr(#dnsxd_zone{rr = RR} = Zone) ->
    NewRR = lists:sort(fun order_rr/2, RR),
    Zone#dnsxd_zone{rr = NewRR}.

order_rr(#dnsxd_rr{name = Name, class = Class, type = Type, data = DataA},
	 #dnsxd_rr{name = Name, class = Class, type = Type, data = DataB}) ->
    DataABin = dns:encode_rrdata(Class, dnssec:canonical_rrdata_form(DataA)),
    DataBBin = dns:encode_rrdata(Class, dnssec:canonical_rrdata_form(DataB)),
    DataABin =< DataBBin;
order_rr(#dnsxd_rr{name = Name, class = Class, type = TypeA},
	 #dnsxd_rr{name = Name, class = Class, type = TypeB}) ->
    TypeA =< TypeB;
order_rr(#dnsxd_rr{name = Name, class = ClassA},
	 #dnsxd_rr{name = Name, class = ClassB}) ->
    ClassA =< ClassB;
order_rr(#dnsxd_rr{name = NameA}, #dnsxd_rr{name = NameB}) ->
    LabelsA = lists:reverse(dns:dname_to_labels(NameA)),
    LabelsB = lists:reverse(dns:dname_to_labels(NameB)),
    order_rr_name(LabelsA, LabelsB).

order_rr_name([X|A], [X|B]) -> order_rr_name(A, B);
order_rr_name([], [_|_]) -> true;
order_rr_name([_|_], []) -> false;
order_rr_name([X|_], [Y|_]) -> X =< Y.

rmv_disabled_tk(#dnsxd_zone{tsig_keys = Keys} = Zone) ->
    NewKeys = [ Key || #dnsxd_tsig_key{enabled = true} = Key <- Keys ],
    Zone#dnsxd_zone{tsig_keys = NewKeys}.

get_serials(RR) ->
    All = lists:foldl(fun get_serials/2, sets:new(), RR),
    lists:sort(sets:to_list(All)).

get_serials(#dnsxd_rr{incept = Incept, expire = Expire}, Acc)
  when is_integer(Incept) andalso is_integer(Expire) ->
    sets:add_element(Expire, sets:add_element(Incept, Acc));
get_serials(#dnsxd_rr{incept = Incept}, Acc)
  when is_integer(Incept) -> sets:add_element(Incept, Acc);
get_serials(#dnsxd_rr{expire = Expire}, Acc)
  when is_integer(Expire) -> sets:add_element(Expire, Acc);
get_serials(#dnsxd_rr{}, Acc) -> Acc.
