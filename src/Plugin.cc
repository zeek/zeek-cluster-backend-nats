#include <zeek/cluster/Component.h>
#include <zeek/plugin/Plugin.h>

#include "NATS.h"
#include "config.h"

namespace zeek::plugin::Zeek_Cluster_Backend_NATS {

class Plugin : public zeek::plugin::Plugin {
public:
    zeek::plugin::Configuration Configure() override {
        AddComponent(new cluster::BackendComponent("NATS", zeek::cluster::nats::NATSBackend::Instantiate));

        zeek::plugin::Configuration config;
        config.name = "Zeek::Cluster_Backend_NATS";
        config.description = "Cluster backend using Core NATS";
        config.version.major = VERSION_MAJOR;
        config.version.minor = VERSION_MINOR;
        config.version.patch = VERSION_PATCH;
        return config;
    }
} plugin;

} // namespace zeek::plugin::Zeek_Cluster_Backend_NATS
