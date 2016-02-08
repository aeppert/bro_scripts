# bro_scripts
## Overview
Scripts I have pulled together for various reasons for use with Bro 2.4+

* netstats_log.bro - Pull the same data as broctl netstats in a redef'able interval
* http_cookies.bro - Extract and log HTTP cookie KV pairs and add them to HTTP::Info
* http_version.bro - Extract the HTTP version and add it to HTTP::Info
* filter_files_log.bro - Prevent anything not in the analyzers whitelist from writing to files.log
* filter_smb_from_files_log.bro - Prevent anything from f$source == SMB writing to files.log
