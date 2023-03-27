#!/bin/bash

BUILD_TYPE=debug
if [ "$1" = "release" ]; then
  BUILD_TYPE=$1
fi
echo "Running sender as $BUILD_TYPE..."

cd env/sender2/
../../target/${BUILD_TYPE}/audibro --seed=42 --layers=3 --key-lifetime=3 sender "0.0.0.0:5556" lojza
