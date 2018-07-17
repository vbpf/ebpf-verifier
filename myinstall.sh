#!/bin/bash -e
set -o xtrace
mkdir -p crab/build
cd crab/build
cmake -DCMAKE_INSTALL_PREFIX=../install/ -DUSE_LDD=ON -DUSE_APRON=ON ../
cmake --build . --target ldd && cmake ../
cmake --build . --target apron && cmake ../
cmake --build . --target install
