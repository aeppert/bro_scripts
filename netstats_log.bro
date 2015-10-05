##
# Aaron Eppert
# October 2015
##

module netstats;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		## Timestamp
		ts:				time		&log;
		## Packets received by Bro.
		pkts_recvd: count &log &optional;
		## Packets reported dropped by the system.
		pkts_dropped: count &log &optional;
		## Packets seen on the link. Note that this may differ from pkts_recvd because of a potential capture_filter.
		## See base/frameworks/packet-filter/main.bro. Depending on the packet capture system, this value may not be
		## available and will then be always set to zero.
		pkts_link: count &log &optional;
 		## Bytes received by Bro.
		bytes_recvd: count &log &optional;
	};

	## This is the interval between individual netstats collection.
    const netstats_collection_interval = 1min;

	global log_netstats: event(rec: Info);
}

event net_stats_update(last_stat: NetStats)
{
	local info: Info;
	local ns = net_stats();
	info$ts        		= network_time();
	info$pkts_recvd 	= ns$pkts_recvd;
	info$pkts_dropped 	= ns$pkts_dropped;
	info$pkts_link 		= ns$pkts_link;
	info$bytes_recvd	= ns$bytes_recvd;

	Log::write(netstats::LOG, info);

	schedule netstats_collection_interval { net_stats_update(ns) };
}

event bro_init()
{
    Log::create_stream(netstats::LOG, [$columns=Info, $ev=log_netstats]);

    schedule netstats_collection_interval { net_stats_update(net_stats()) };
}
