@load-plugin Zeek::Cluster_Backend_NATS
@load frameworks/cluster/backend/nats/connect

global nats_port = port_to_count(to_port(getenv("NATS_PORT")));
redef Cluster::Backend::NATS::url = fmt("http://127.0.0.1:%s", nats_port);


module NATS_Server;

export {
	## Terminate the nats server
	global terminate: function(pid_file: string &default="../nats.pid");
}

function terminate(pid_file: string) {
	# Assume nats.pid is located in parent directory, the
	# run-nats-server helper script should ensure this is
	# the case.
	local cmd = fmt("kill $(cat %s)", safe_shell_quote(pid_file));
	piped_exec(cmd, "");
}
