#!/bin/bash

BUILD_TYPE=debug
if [ "$1" = "release" ]; then
  BUILD_TYPE=$1
fi
echo "Running sender as $BUILD_TYPE..."

cd env/sender/
../../target/${BUILD_TYPE}/audibro --seed=40 --layers=3 --key-lifetime=3 --max-piece-size=10485760 sender "0.0.0.0:5555" tonda
