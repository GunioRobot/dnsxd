-ifndef('__dnsxd.hrl__').
-define('__dnsxd.hrl__', ok).

-include_lib("dns/include/dns.hrl").

-define(DNSXD_EL(MOD, FMT, ARGS), error_logger:MOD(?MODULE_STRING " ~p:~n" ++
						   FMT ++ "~n", [self()|ARGS])).
-define(DNSXD_INFO(FMT, ARGS), ?DNSXD_EL(info_msg, FMT, ARGS)).
-define(DNSXD_INFO(FMT), ?DNSXD_INFO(FMT, [])).

-define(DNSXD_ERR(FMT, ARGS), ?DNSXD_EL(error_msg, FMT, ARGS)).
-define(DNSXD_ERR(FMT), ?DNSXD_ERR(FMT, [])).

-record(dnsxd_if_spec, {ip, port, protocol}).

-record(dnsxd_tsig_ctx, {zonename, keyname, alg, secret, mac, msgid}).

-record(dnsxd_zone, {name,
		     enabled = false,
		     rr,
		     serials,
		     axfr_enabled,
		     axfr_hosts,
		     tsig_keys = [],
		     soa_param,
		     dnssec_enabled = false,
		     dnssec_keys = [],
		     dnssec_siglife = 1250000,
		     nsec3}).

-record(dnsxd_soa_param, {mname, rname, refresh, retry, expire, minimum}).
-record(dnsxd_nsec3_param, {hash, salt, iter}).

-record(dnsxd_rr, {incept,
		   expire,
		   name,
		   class,
		   type,
		   ttl,
		   data}).

-record(dnsxd_tsig_key, {id, name, secret, enabled, dnssd_only}).
-record(dnsxd_dnssec_key, {id, incept, expire, alg, ksk, key, keytag}).

-endif.
