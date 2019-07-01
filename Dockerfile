FROM ubuntu:18.04

ARG BUILD_TYPE=Debug

USER root
RUN apt-get update && \
    apt-get -y install clang-7 cmake zlib1g-dev ninja-build \
        python3.7 python3.7-dev python3-pip git wget software-properties-common
RUN wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key| apt-key add -
RUN add-apt-repository 'deb http://apt.llvm.org/bionic/ llvm-toolchain-bionic-8 main'
RUN apt-get update && \
    apt-get -y install llvm-8 llvm-8-dev

WORKDIR /krf/
ADD ./KRFAnalysisPass/ .
ADD ./test-bc/ ./test-bc/

WORKDIR /krf/build
RUN cmake ../
RUN cmake --build .