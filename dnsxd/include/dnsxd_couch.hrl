-ifndef('__dnsxd_couch.hrl__').
-define('__dnsxd_couch.hrl__', ok).

-include("dnsxd.hrl").

-define(DNSXD_COUCH_SERVER, dnsxd_couch).

%% local zone
-record(dnsxd_couch_lz, {name,
			 enabled = false,
			 enabled_set = dns:unix_time(),
			 rev,
			 rr = [],
			 axfr_enabled = false,
			 axfr_enabled_set = dns:unix_time(),
			 axfr_hosts = [],
			 tsig_keys = [],
			 export = false,
			 export_set = dns:unix_time(),
			 history = [],
			 soa_param,
			 soa_param_set = dns:unix_time()}).

%% exported zone
-record(dnsxd_couch_ez, {name,
			 rev,
			 rr = [],
			 axfr_enabled = false,
			 axfr_hosts = [],
			 soa_param}).

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

%% history entry
-record(dnsxd_couch_he, {id = dnsxd_lib:new_id(),
			 time = dns:unix_time(),
			 event,
			 actor = null,
			 entry}).

-endif.
