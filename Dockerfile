FROM ubuntu:18.10

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update
RUN apt-get install -y build-essential git cmake libboost-dev libgmp-dev g++-8 python3-pip python3-tk
RUN pip3 install matplotlib

WORKDIR /verifier
COPY . /verifier/
RUN mkdir build
WORKDIR /verifier/build
RUN cmake .. -DCMAKE_BUILD_TYPE=Release
RUN make
WORKDIR /verifier
ENTRYPOINT ["./check"]
