function(doc, req) {
    if (!doc.dnsxd_couch_rec) return false;
    if (!doc.dnsxd_couch_rec.indexOf("dnsxd_couch_log_") == 0) return false;
    return (doc._id == "dnsxd_couch_log_config" || !!doc._conflicts);
}