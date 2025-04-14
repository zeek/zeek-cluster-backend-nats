FROM zeek/zeek-dev

RUN apt-get update && apt-get install --no-install-recommends -y \
	build-essential \
	cmake \
	libnats-dev \
	libpcap-dev \
	libssl-dev \
	nats-server

WORKDIR /build

COPY ./ .

RUN git config --global --add safe.directory $(pwd)
RUN git status .
RUN yes | zkg install .
RUN zeek -N Zeek::Cluster_Backend_NATS
