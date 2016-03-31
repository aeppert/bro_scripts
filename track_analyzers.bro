#
# Aaron Eppert - 2016
#
# Track analyzers attached to a connection in a general manner.
#
# This could be used with https://github.com/JustinAzoff/bro-react/blob/master/conn-bulk.bro
# to shunt traffic over thresholds.
#
const analyzerTagToString: table[Analyzer::Tag] of string = {
	[Analyzer::ANALYZER_AYIYA] = "AYIYA",
	[Analyzer::ANALYZER_BITTORRENT] = "BITTORRENT",
	[Analyzer::ANALYZER_DHCP]	= "DHCP",
	[Analyzer::ANALYZER_DNP3_TCP]	= "DNP3_TCP",
	[Analyzer::ANALYZER_DNS] = "DNS",
	[Analyzer::ANALYZER_DTLS]	= "DTLS",
	[Analyzer::ANALYZER_FTP] = "FTP",
	[Analyzer::ANALYZER_FTP_DATA]	= "FTP_DATA",
	[Analyzer::ANALYZER_GTPV1] = "GTPV1",
	[Analyzer::ANALYZER_HTTP]	= "HTTP",
	[Analyzer::ANALYZER_IRC]	= "IRC",
	[Analyzer::ANALYZER_IRC_DATA] = "IRC_DATA",
	[Analyzer::ANALYZER_KRB] = "KRB",
	[Analyzer::ANALYZER_KRB_TCP] = "KRB_TCP",
	[Analyzer::ANALYZER_MODBUS] = "MODBUS",
	[Analyzer::ANALYZER_MYSQL] = "MYSQL",
	[Analyzer::ANALYZER_NTP] = "NTP",
	[Analyzer::ANALYZER_POP3] = "POP3",
	[Analyzer::ANALYZER_RADIUS]	= "RADIUS",
	[Analyzer::ANALYZER_RDP] = "RDP",
	[Analyzer::ANALYZER_SIP] = "SIP",
	[Analyzer::ANALYZER_SMB] = "SMB",
	[Analyzer::ANALYZER_SMTP] = "SMTP",
	[Analyzer::ANALYZER_SNMP] = "SNMP",
	[Analyzer::ANALYZER_SOCKS] = "SOCKS",
	[Analyzer::ANALYZER_SSH] = "SSH",
	[Analyzer::ANALYZER_SSL] = "SSL",
	[Analyzer::ANALYZER_SYSLOG] = "SYSLOG",
	[Analyzer::ANALYZER_TEREDO]	= "TEREDO",
#	[Analyzer::ANALYZER_XMPP]	= "XMPP",
};

redef record connection += {
	analyzers: table[Analyzer::Tag] of count &optional;
};

event protocol_confirmation(c: connection, atype: Analyzer::Tag, aid: count) &priority=30
{
	if ( atype in analyzerTagToString) {
		if ( ! c?$analyzers ) {
	        c$analyzers = table();
		}
		
		c$analyzers[atype] = aid;
	}
}
