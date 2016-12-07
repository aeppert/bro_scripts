
@load base/frameworks/files
@load base/frameworks/notice
@load frameworks/files/hash-all-files

module FileAnalytics;

export {

	type Info: record {
		uid:      string  &log;
		id:		  conn_id &log;
		fuid:     string  &log;
		md5:   	  string  &log;
  		ts:		  time    &log;
		src_geo:  string  &log &default="lo";
    	dest_geo: string  &log &default="lo";
  		filebuf:  string  &log &optional;
  };

  redef enum Log::ID += { LOG };

  # Define a hook event. By convention, this is called
  # "log_<stream>".
  global log_file_analytics: event(rec: Info);

	## Define whether or not to extract a filebuf for insertion into the log
	const extract_filebuf = T &redef;
	## Define the number of bytes to extract from the bof_buffer
  const bytes_to_extract = 50 &redef;
}

global analysis_allowed_mime_types: set[string] = {
  "application/x-dosexec",
  "application/x-executable",
  "application/x-msdownload",
  "application/octet-stream",
  "application/x-shockwave-flash",
  "application/pdf",
  "application/x-director",
  "application/vnd.ms-cab-compressed",
  "application/x-java-applet",
  "application/jar",
};

event bro_init() {
	Log::create_stream(FileAnalytics::LOG, [$columns=Info, $ev=log_file_analytics]);
}

event file_state_remove(f: fa_file) {
	if ( f$info?$md5 ) {
		if ( f$info?$mime_type ) {
			if ( f$info$mime_type in analysis_allowed_mime_types ) {
				for ( conn in f$conns )  {
					local id: conn_id;
					local uid: string;
					local _src_geo: string = "lo";
					local _dest_geo: string = "lo";
					local _filebuf: string = "";

					id = conn;
					uid = f$conns[conn]$uid;

					if( Site::is_local_addr(id$orig_h) ) {
						_src_geo = "lo";
					} else {
						local orig_loc = lookup_location(id$orig_h);
						if ( orig_loc?$country_code ) {
							_src_geo = orig_loc$country_code;
						}
					}

					if( Site::is_local_addr(id$resp_h) ) {
						_dest_geo = "lo";
					} else {
						local resp_loc = lookup_location(id$resp_h);
						if ( resp_loc?$country_code ) {
							_dest_geo = resp_loc$country_code;
						}
					}

					if ( extract_filebuf ) {
						if ( f?$bof_buffer && |f$bof_buffer| >= bytes_to_extract ) {
							_filebuf = string_to_ascii_hex(f$bof_buffer[:bytes_to_extract]);
						}
					}

					local tmp: Info = [	$uid=uid,
										$id=id,
										$ts=f$info$ts,
										$fuid=f$info$fuid,
										$md5=f$info$md5,
										$src_geo=_src_geo,
										$dest_geo=_dest_geo,
										$filebuf=_filebuf ];

					Log::write(FileAnalytics::LOG, tmp);
				}
			}
		}
	}
}
