# @TEST-DOC: Smoke test running a manager and a worker
#
# @TEST-PORT: NATS_PORT
#
# @TEST-REQUIRES: nats-server --version
#
# @TEST-EXEC: cp $FILES/nats-bootstrap.zeek .
#
# @TEST-EXEC: zeek -b --parse-only manager.zeek
# @TEST-EXEC: zeek -b --parse-only worker.zeek
#
# @TEST-EXEC: btest-bg-run nats-server "run-nats-server"
# @TEST-EXEC: btest-bg-run manager "ZEEKPATH=$ZEEKPATH:$PACKAGE:.. && CLUSTER_NODE=manager zeek -b ../manager.zeek"
# @TEST-EXEC: btest-bg-run worker-1 "ZEEKPATH=$ZEEKPATH:$PACKAGE:.. && CLUSTER_NODE=worker-1 zeek -b ../worker.zeek"
#
# @TEST-EXEC: btest-bg-wait 30
# @TEST-EXEC: btest-diff ./manager/.stdout
# @TEST-EXEC: btest-diff ./manager/.stderr
# @TEST-EXEC: btest-diff ./worker-1/.stdout
# @TEST-EXEC: btest-diff ./worker-1/.stderr

# @TEST-START-FILE cluster-layout.zeek
redef Cluster::manager_is_logger = T;

redef Cluster::nodes = {
	["manager"] = [$node_type=Cluster::MANAGER, $ip=127.0.0.1],
	["worker-1"] = [$node_type=Cluster::WORKER, $ip=127.0.0.1, $manager="manager"],
};
# @TEST-END-FILE


# @TEST-START-FILE common.zeek
redef Log::default_rotation_interval = 0sec;
redef Log::flush_interval = 0.01sec;

@load ./nats-bootstrap.zeek

global finish: event(name: string);
# @TEST-END-FILE

# @TEST-START-FILE manager.zeek
@load ./common.zeek
# If a node comes up, send it a finish event.
event Cluster::node_up(name: string, id: string) {
	print "node_up", name;
	Cluster::publish(Cluster::nodeid_topic(id), finish, Cluster::node);
}

# If workers vanished, finish the test.
event Cluster::node_down(name: string, id: string) {
	print "node_down", name;
	NATS_Server::terminate();
	terminate();
}
# @TEST-END-FILE

# @TEST-START-FILE worker.zeek
@load ./common.zeek

event Cluster::node_up(name: string, id: string) {
	print "node_up", name;
}

event finish(name: string) &is_used {
	terminate();
}
# @TEST-END-FILE
