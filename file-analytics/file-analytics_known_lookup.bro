#!
#! Aaron Eppert - File Analytics
#!
#! Lookup against the KNOWN database. This will process lookups globally against
#! KNOWN whether they are new or existing via the file-analytics_to_db module,
#! so that all lookups and processing occur in a single location.
#!

@load frameworks/files/hash-all-files

module FileAnalytics;

global query_finish: bool = F;

export {
  type Info: record {
    ts:           time    &log;
    status:       string  &log;
    family_name:  string  &log;
    platform:     string  &log;
    threat_name:  string  &log;
    threat_level: int     &log;
    trust_factor: int     &log;
    id:           conn_id &log;
    uid:          string  &log;
    fuid:         string  &log;
    filebuf:      string  &log &optional;
  };

  redef enum Log::ID += { LOG };

  # Define a hook event. By convention, this is called
  # "log_<stream>".
  global log_file_analytics: event(rec: Info);

  ## Timeout interval to retry the known.sqlite database for the hash entry
  const query_interval = 30sec &redef;
  ## Maximum retry interval to query the known.sqlite database before removing
  ## it regardless of a known result. Helps garbage collect memory for Bro, in
  ## the worst case.
  const query_max_retry_count = 5 &redef;
}

global known_db = "/opt/db/known";

type KNOWN_db_Val: record {
  hash:         string;
  status:       string;
  family_name:  string;
  _type:        string;
  platform:     string;
  threat_name:  string;
  threat_level: int;
  trust_factor: int;
  details_url:  string;
  severity:     int;
  filebuf:      string;
  last_updated: time;
};

event process_known_hash(description: Input::EventDescription, tpe: Input::Event, r: KNOWN_db_Val) {
  for( c in FileAnalytics_DB::db_monitor ) {
    if ( c$md5 == r$hash ) {
      if ( r?$status ) {
        if ( r$status == "MALICIOUS" ) {
          local tmp: Info = [ $ts=c$ts,
                              $status=r$status,
                              $family_name=r$family_name,
                              $platform=r$platform,
                              $threat_name=r$threat_name,
                              $threat_level=r$threat_level,
                              $trust_factor=r$trust_factor,
                              $id=FileAnalytics_DB::db_monitor[c]$id,
                              $uid=c$uid,
                              $fuid=FileAnalytics_DB::db_monitor[c]$fuid,
                              $filebuf=r$filebuf ];

          Log::write(FileAnalytics::LOG, tmp);
        }
      }

      delete FileAnalytics_DB::db_monitor[c];
    }

    if ( c in FileAnalytics_DB::db_monitor && FileAnalytics_DB::db_monitor[c]?$retry_count ) {
      if ( FileAnalytics_DB::db_monitor[c]$retry_count > query_max_retry_count ) {
        delete FileAnalytics_DB::db_monitor[c];
      } else {
        FileAnalytics_DB::db_monitor[c]$retry_count += 1;
      }
    }
  }
}

event Input::end_of_data(name: string, source:string) {
  if ( source == known_db ) {
    Input::remove(name);
  }
}

function do_known_query(key: FileAnalytics_DB::db_monitor_key) {

  Input::add_event(
    [
    $source=known_db,
    $name=fmt("%s_%s_%s", key$uid, key$ts, key$md5),
    $fields=KNOWN_db_Val,
    $ev=process_known_hash,
    $want_record=T,
    $config=table(["query"] = fmt("SELECT * FROM known WHERE hash='%s';", key$md5)),
    $reader=Input::READER_SQLITE
    ]);
}

function run_known_query() {
  for( c in FileAnalytics_DB::db_monitor ) {
    if ( c?$md5 ) {
      do_known_query(c);
    }
  }
}

event try_known_query() {
  run_known_query();

  if ( !query_finish ) {
    schedule query_interval { try_known_query() };
  }
}

event bro_init() {

  #
  # Disabled this - thus set it to T, since it did not appear
  # that the workers were sending data to the manager as originally
  # assumed. We really need just the MANAGER to have the database
  # open and the workers to send results back.
  #
  local run_known_lookup = T;
  if ( Cluster::is_enabled() ) {
    if ( Cluster::local_node_type() == Cluster::MANAGER ) {
      run_known_lookup = T;
    }
  } else {
    run_known_lookup = T;
  }

  if ( run_known_lookup ) {
    Log::create_stream(FileAnalytics::LOG, [$columns=Info, $ev=log_file_analytics]);

    run_known_query();
    schedule query_interval { try_known_query() };
  }
}

event bro_done() {
  query_finish = T;
}
