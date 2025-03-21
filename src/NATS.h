// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <nats/nats.h>
#include <memory>

#include "zeek/cluster/Backend.h"
#include "zeek/cluster/Serializer.h"

namespace zeek::cluster::nats {

namespace detail {

class NATSManagerImpl;

}

class NATSBackend : public cluster::ThreadedBackend {
public:
    NATSBackend(std::unique_ptr<EventSerializer> es, std::unique_ptr<LogSerializer> ls,
                std::unique_ptr<cluster::detail::EventHandlingStrategy> ehs)
        : cluster::ThreadedBackend(std::move(es), std::move(ls), std::move(ehs)) {}

    void HandleSubscriptionMessage(natsSubscription* sub, natsMsg* msg);

    void HandleSubscriptionError(natsSubscription* sub, natsStatus err);

    enum class ConnectionEvent {
        Closed, // permanently lost
        Disconnected,
        Reconnected,
    };

    void HandleConnectionCallback(ConnectionEvent ev);

    static std::unique_ptr<Backend> Instantiate(std::unique_ptr<EventSerializer> es, std::unique_ptr<LogSerializer> ls,
                                                std::unique_ptr<cluster::detail::EventHandlingStrategy> ehs) {
        return std::make_unique<NATSBackend>(std::move(es), std::move(ls), std::move(ehs));
    }

private:
    void DoInitPostScript() override;

    bool DoInit() override;

    void DoTerminate() override;

    bool DoPublishEvent(const std::string& topic, const std::string& format,
                        const cluster::detail::byte_buffer& buf) override;

    bool DoSubscribe(const std::string& topic_prefix, SubscribeCallback cb) override;

    bool DoUnsubscribe(const std::string& topic_prefix) override;

    bool DoPublishLogWrites(const logging::detail::LogWriteHeader& header, const std::string& format,
                            cluster::detail::byte_buffer& buf) override;

    bool Connected() const { return conn != nullptr; }

    bool TrySubscribe(const std::string& topic_prefix, natsSubscription** sub);

private:
    bool logger_queue_consume = false;
    std::string logger_queue_name;
    std::string logger_queue_subject_prefix;
    int64_t flush_timeout_ms = 500;
    natsSubscription* logger_queue_subscription = nullptr;

    EventHandlerPtr event_nats_connected;
    EventHandlerPtr event_nats_disconnected;
    EventHandlerPtr event_nats_reconnected;

    natsOptions* options = nullptr;
    natsConnection* conn = nullptr;

    struct Subscription {
        std::string subject;
        natsSubscription* sub;
        cluster::Backend::SubscribeCallback cb;
    };

    std::vector<Subscription> subscriptions;
};

} // namespace zeek::cluster::nats
