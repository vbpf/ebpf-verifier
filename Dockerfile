FROM ubuntu:18.10

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update
RUN apt-get install -y build-essential git cmake libboost-dev libgmp-dev libbz2-dev libmpfr-dev python3-pip python3-tk
RUN pip3 install matplotlib

WORKDIR /verifier
COPY . /verifier/
RUN make crab_install
RUN make
ENTRYPOINT ["./check"]
