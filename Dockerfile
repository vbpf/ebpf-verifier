FROM ubuntu:18.10

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update
RUN apt-get -yq --no-install-suggests --no-install-recommends install build-essential cmake libboost-graph1.65-dev libboost1.65-tools-dev libgmp-dev

WORKDIR /verifier
COPY . /verifier/
RUN mkdir build
WORKDIR /verifier/build
RUN cmake .. -DCMAKE_BUILD_TYPE=Release
RUN make -j4
WORKDIR /verifier
ENTRYPOINT ["./check"]
