-ifndef('__dnsxd_internal.hrl__').
-define('__dnsxd_internal.hrl__', ok).

-define(FPROF(X), fun() ->
		      _FPROF_FN_PREFIX = ?MODULE_STRING "-" ++
			  integer_to_list(dns:unix_time()) ++ "-" ++
			  integer_to_list(erlang:phash2(self())),
		      _FPROF_FN_TRACE = _FPROF_FN_PREFIX ++ ".trace",
		      _FPROF_FN_ANALYSIS = _FPROF_FN_PREFIX ++ ".analysis",
		      ok = fprof:trace(start, _FPROF_FN_TRACE),
		      _FPROF_RESULT = X,
		      ok = fprof:trace(stop),
		      ok = fprof:profile([{file, _FPROF_FN_TRACE}]),
		      ok = fprof:analyse([totals, {dest, _FPROF_FN_ANALYSIS}]),
		      _FPROF_RESULT
		  end()).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

-include("dnsxd.hrl").

-record(zone_ref, {name :: binary(), ref :: reference()}).
-record(serial_ref, {zone_ref :: #zone_ref{}, serial :: pos_integer()}).
-record(rrname_ref, {serial_ref :: #serial_ref{}, name :: binary()}).
-record(rrset_ref, {rrname_ref :: #rrname_ref{}, type :: integer()}).

-record(nsec3, {name :: binary(), hash :: binary(), hashdn :: binary()}).

-record(rrmap, {serial_ref :: #serial_ref{},
		names = [] :: [binary()],
		tree = dict:new(),
		sets = [] :: [{binary(),[integer()]}],
		nsec3 = [] :: [#nsec3{}]}).
-record(rrname, {ref :: #rrname_ref{},
		 name :: binary(),
		 cutby :: 'undefined' | binary(),
		 types = [] :: [pos_integer()],
		 coveredby :: binary()}).
-record(rrset, {ref :: #rrset_ref{},
		name :: binary(),
		cutby :: 'undefined' | binary(),
		class = ?DNS_CLASS_IN :: pos_integer(),
		type :: pos_integer(),
		incept :: pos_integer(),
		expire :: pos_integer(),
		ttl :: non_neg_integer(),
		data = [] :: [tuple()],
		sig = [] :: [tuple()]}).
-record(tsig, {zone_ref :: #zone_ref{}, keys = [] :: [tuple()]}).
-record(zone, {labels :: [binary()],
	       name :: binary(),
	       soa = undefined :: 'undefined' | tuple(),
	       cuts = 0 :: non_neg_integer(),
	       ref :: reference(),
	       serials = [] :: [pos_integer()],
	       axfr = false :: 'false' | [binary()],
	       nsec3}).

-endif.
