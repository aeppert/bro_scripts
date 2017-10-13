# TrickBot Webinar - October 13, 2017
# Aaron Eppert 

module CTYPE_V_MTYPE;

export {
    redef enum Notice::Type += {
        TYPE_MISMATCH
    };
}

redef record HTTP::Info += {
    orig_content_type: string &optional;
};

# Helper function to split any complex Content-Type across semicolon 
# boundaries and return the first entry
function get_single_mime_type(s: string): string {
    local ret = split_string_all(s, /;/);
    return ret[0];
}

# Find the CONTENT-TYPE header entry and populate the redefined HTTP::Info record
event http_header(c: connection, is_orig: bool, name: string, value: string) &priority=20
{
    if ( name == "CONTENT-TYPE" ) {
        c$http$orig_content_type = value;
    }
}

# Comparison between the previously found CONTENT-TYPE with the MIME-Type
event file_sniff(f: fa_file, meta: fa_metadata)
{
	if ( f$source != "HTTP" )
		return;

    for ( c in f$conns ) {
       
        if ( meta?$mime_type && f$conns[c]$http?$orig_content_type ) {
            for ( m in f$conns[c]$http$resp_mime_types ) {
                local o_type = get_single_mime_type(f$conns[c]$http$orig_content_type);

                if ( f$conns[c]$http$resp_mime_types[m] != o_type ) {
                    NOTICE([$note=CTYPE_V_MTYPE::TYPE_MISMATCH,
                            $msg=fmt("Content-Type (%s) does not match MIME Type of Body (%s) for %s:%d to %s:%d",
                                    o_type,
                                    f$conns[c]$http$resp_mime_types[m],
                                    c$orig_h, c$orig_p,
                                    c$resp_h, c$resp_p),
                            $conn=f$conns[c],
                            $identifier=cat(c$resp_h)]);
                }
            }
        }
    }
}
