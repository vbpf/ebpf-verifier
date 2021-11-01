FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update
RUN apt-get -yq --no-install-suggests --no-install-recommends install build-essential cmake libboost-dev libyaml-cpp-dev

WORKDIR /verifier
COPY . /verifier/
RUN mkdir build
WORKDIR /verifier/build
RUN cmake .. -DCMAKE_BUILD_TYPE=Release
RUN make -j $(nproc)
WORKDIR /verifier
ENTRYPOINT ["./check"]
