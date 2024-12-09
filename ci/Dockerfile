FROM zeek/zeek-dev

RUN apt-get update && apt-get install --no-install-recommends -y \
	build-essential \
	cmake \
	libpcap-dev \
	libssl-dev \
	libnats-dev

WORKDIR /build

COPY ./ .

RUN git config --global --add safe.directory $(pwd)
RUN git status .
RUN yes | zkg install .
RUN zeek -N Zeek::Cluster_Backend_NATS
