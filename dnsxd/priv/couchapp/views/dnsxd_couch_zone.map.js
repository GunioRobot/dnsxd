function(doc) {
    if (doc.dnsxd_couch_rec && doc.dnsxd_couch_rec == "dnsxd_couch_zone") {
        emit(doc.enabled, null);
    }
}