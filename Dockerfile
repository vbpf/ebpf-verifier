FROM ubuntu:18.10

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update
RUN apt-get install -y build-essential git libboost-dev libgmp-dev g++-8 python3-pip python3-tk
RUN pip3 install matplotlib

WORKDIR /verifier
COPY . /verifier/
RUN cmake -B build && cmake --build build
ENTRYPOINT ["./check"]
