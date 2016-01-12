redef record HTTP::Info += {
	version: string &log &optional;
};

event http_reply(c: connection, version: string, code: count, reason: string) &priority=20
{
	if ( c?$http ) {
		c$http$version = version;
	}
}
