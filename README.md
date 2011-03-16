# dnsxd

**License: [Apache 2](LICENSE)**

dnsxd is an authoritative DNS server that supports the [DNS Long Lived Queries](http://files.dns-sd.org/draft-sekar-dns-llq.txt) and [DNS Update Leases](http://files.dns-sd.org/draft-sekar-dns-ul.txt) extensions created by Apple to enhance wide-area [DNS Service Discovery](http://www.dns-sd.org/) with real-time updates and garbage collection of stale services respectively.

dnsxd requires DNS update messages to be TSIG signed and optionally restricts clients to manipulating only their own DNSSD records. Where possible record TTLs are reduced automatically in anticipation of record changes. Presently [Apache CouchDB](http://couchdb.apache.org/) is used for data storage though provisions for other data stores has been made.

There is no documentation, admin tools or a release package available so familiarity with Erlang is required to make use of the codebase at the moment. If you'd like to use dnsxd (or if you do) drop me an [email](http://andrew.tj.id.au/email/) to let me know.

**Todo**

 * Tests
 * DNSSEC support (RSA/SHA-1, RSASHA1-NSEC3-SHA1, RSA/SHA-256 and RSA/SHA-512)
 * Logging and stats collection
 * [CouchApp](http://couchapp.org) admin interface
 * Documentation