#
# Aaron Eppert
#

@load base/protocols/http/main
@load base/protocols/http/utils

module HTTP;

redef record Info += {
	cookies: set[string] &optional &log;
};

event http_header(c: connection, is_orig: bool, name: string, value: string) &priority=10
{
	if ( is_orig && name == "COOKIE" ) {
		if ( ! c$http?$cookies ) {
			c$http$cookies = set();
		}

		local cookie_vec = split_string(value, /;[[:blank:]]*/);

		for (i in cookie_vec) {
			add c$http$cookies[cookie_vec[i]];
		}
	}
}
