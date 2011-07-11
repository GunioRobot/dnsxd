-ifndef('__dnsxd_couch.hrl__').
-define('__dnsxd_couch.hrl__', ok).

-include("dnsxd.hrl").

-define(DNSXD_COUCH_SERVER, dnsxd_couch).
-define(DNSXD_COUCH_DESIGNDOC, "app").

%% zone
-record(dnsxd_couch_zone, {name,
			   enabled = false,
			   enabled_set = dns:unix_time(),
			   rev,
			   tombstone_period = 86400,
			   rr = [],
			   axfr_enabled = false,
			   axfr_enabled_set = dns:unix_time(),
			   axfr_hosts = [],
			   tsig_keys = [],
			   soa_param,
			   soa_param_set = dns:unix_time(),
			   dnssec_enabled = false,
			   dnssec_enabled_set = dns:unix_time(),
			   dnssec_keys = [],
			   dnssec_nsec3_param,
			   dnssec_nsec3_param_set = dns:unix_time(),
			   dnssec_siglife = 1250000,
			   dnssec_siglife_set = dns:unix_time()
			  }).

%% soa param
-record(dnsxd_couch_sp, {set = dns:unix_time(),
			 mname,
			 rname,
			 refresh,
			 retry,
			 expire,
			 minimum}).

%% tsig key
-record(dnsxd_couch_tk, {id = dnsxd_lib:new_id(),
			 name,
			 secret,
			 created = dns:unix_time(),
			 set = dns:unix_time(),
			 enabled = true,
			 dnssd_only = false,
			 tombstone = null}).

%% rr
-record(dnsxd_couch_rr, {id = dnsxd_lib:new_id(),
			 incept,
			 expire = null,
			 set = dns:unix_time(),
			 name,
			 class,
			 type,
			 ttl,
			 data,
			 tombstone = null}).

%% dnssec
-record(dnsxd_couch_dk, {id = dnsxd_lib:new_id(),
			 incept = dns:unix_time(),
			 expire = dns:unix_time() + 883593927,
			 set = dns:unix_time(),
			 alg,
			 ksk = false,
			 data}).
-record(dnsxd_couch_dk_rsa, {e, n, d}).
-record(dnsxd_couch_nsec3param, {salt, iter, alg}).

-endif.
