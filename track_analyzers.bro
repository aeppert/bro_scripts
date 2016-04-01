#
# Aaron Eppert - 2016
#
# Track analyzers attached to a connection in a general manner.
#
# This could be used with https://github.com/JustinAzoff/bro-react/blob/master/conn-bulk.bro
# to shunt traffic over thresholds.
#

module TrackAnalyzers;

export {
  ## Set of Analyzer::Tag that should NOT be shunted
  const ignorelist: set[Analyzer::Tag] = {} &redef;
}

redef record connection += {
  analyzers: table[Analyzer::Tag] of count &optional;
};

event protocol_confirmation(c: connection, atype: Analyzer::Tag, aid: count) &priority=30
{
  if ( atype !in ignorelist ) {
    if ( ! c?$analyzers ) {
      c$analyzers = table();
    }
    
    c$analyzers[atype] = aid;
  }
}
