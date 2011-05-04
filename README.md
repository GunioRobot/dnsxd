# dnsxd

**License: Apache 2**

dnsxd is an authoritative DNS server written in Erlang.

### Features

* **DNSSEC** - Implements NSEC3 "white lies" inspired by [Phreebird](http://dankaminsky.com/phreebird/). Currently supports RSA SHA1 signatures with SHA2 coming shortly.
* **Wide-Area Bonjour DNS Extensions** - Implements both the [DNS Long Lived Queries](http://files.dns-sd.org/draft-sekar-dns-llq.txt) and [DNS Update Leases](http://files.dns-sd.org/draft-sekar-dns-ul.txt) extensions created by Apple to enhance wide-area [DNS Service Discovery](http://www.dns-sd.org/) with real-time updates and garbage collection of stale services.
* **TSIG signed DNS Updates** - Requires DNS Update messages to be TSIG signed and optionally restricts clients to manipulating only their own DNSSD records. 
* **Modular Backend** - Replaceable via a configuration option. Bundled backend supports [CouchDB](http://couchdb.apache.org/).
* **Predictable Changes** - Where possible record TTLs are reduced automatically in anticipation of record changes.

### Getting started

Unfortunately there is no documentation, admin tools or a release package at present so your best bet is to clone this repository and take a look at [app.config](https://github.com/andrewtj/dnsxd/blob/master/rel/files/app.config) and [example.json](https://github.com/andrewtj/dnsxd/blob/master/example.json). Feel free to drop me an [email](http://andrew.tj.id.au/email/) with any questions and let me know how you get on.

###Todo

 * Tests
 * Documentation
 * Logging and stats collection
 * [CouchApp](http://couchapp.org) admin interface