#!/bin/bash

BUILD_TYPE=debug
if [ "$1" = "release" ]; then
  BUILD_TYPE=$1
fi
echo "Running receiver as $BUILD_TYPE..."

cd env/receiver2/
../../target/$BUILD_TYPE/hashsig receiver "127.0.0.1:5555"
