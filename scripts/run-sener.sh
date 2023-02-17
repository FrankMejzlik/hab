#!/bin/bash

BUILD_TYPE=debug
if [ "$1" = "release" ]; then
  BUILD_TYPE=$1
fi
echo "Running sender as $BUILD_TYPE..."

cd env/sender/
../../target/${BUILD_TYPE}/hashsig sender "0.0.0.0:5555"
