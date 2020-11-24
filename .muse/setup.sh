#!/usr/bin/env bash
apt update && apt install -y autopoint
sed -i 's/libxcrypt-dev//' ./ci/install-dependencies.sh
./ci/install-dependencies.sh
./autogen.sh
./configure --disable-doc --disable-dependency-tracking
