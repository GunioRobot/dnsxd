function(doc) {
  var doc_prefix = "dnsxd_couch_log_";
  if (doc._id.substring(0, doc_prefix.length) != doc_prefix) return;
  if (doc.dnsxd_couch_rec != "dnsxd_couch_log_entries") return;
  var doc_num = parseInt(doc._id.substring(doc_prefix.length, doc._id.length));
  if (doc_num == NaN) return;
  if (doc.entries) emit(doc_num, doc.entries.length);
}