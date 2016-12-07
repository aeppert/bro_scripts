#!/bin/sh

echo "CREATE TABLE if not exists request ('uid' text,'fuid' text,'md5' text, 'ts' double precision, 'filebuf' text);" | /usr/bin/sqlite3 /opt/db/request.sqlite
echo "CREATE TABLE if not exists known('hash' text PRIMARY KEY NOT NULL,'status' text,'family_name' text,'_type' text,'platform' text,'threat_name' text,'threat_level' int,'trust_factor' int,'details_url' text,'severity' int,'filebuf' text,'last_updated' TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL);" | /usr/bin/sqlite3 /opt/db/known.sqlite
