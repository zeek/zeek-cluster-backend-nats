# @TEST-EXEC: zeek -NN Zeek::Cluster_Backend_NATS |sed -e 's/version.*)/version)/g' >output
# @TEST-EXEC: btest-diff output
