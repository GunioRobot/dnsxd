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

-record(dnsxd_zone, {opaque_ds_id,
		     name,
		     rr,
		     serials,
		     axfr_enabled,
		     axfr_hosts,
		     keys = []}).

-record(dnsxd_rr, {incept,
		   expire,
		   name,
		   class,
		   type,
		   ttl,
		   data}).

-record(dnsxd_key, {opaque_ds_id, name, secret, dnssd_only}).

-endif.
