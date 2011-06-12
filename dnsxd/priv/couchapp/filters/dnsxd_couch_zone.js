function(doc, req) {
    return doc.dnsxd_couch_rec && doc.dnsxd_couch_rec == "dnsxd_couch_zone";
}