#include "Plugin.h"

#include "zeek/cluster/Component.h"

#include "NATS.h"
#include "config.h"

using namespace zeek::plugin::Zeek_Cluster_Backend_NATS;

zeek::plugin::Configuration Plugin::Configure() {
    AddComponent(new cluster::BackendComponent("NATS", zeek::cluster::nats::NATSBackend::Instantiate));

    zeek::plugin::Configuration config;
    config.name = "Zeek::Cluster_Backend_NATS";
    config.description = "Cluster backend using Core NATS";
    config.version.major = VERSION_MAJOR;
    config.version.minor = VERSION_MINOR;
    config.version.patch = VERSION_PATCH;
    return config;
}
