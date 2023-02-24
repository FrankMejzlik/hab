#!/bin/bash

BUILD_TYPE=debug
if [ "$1" = "release" ]; then
  BUILD_TYPE=$1
fi
echo "Clearing logs..."

cd env/
rm ./sender/logs/*.log
rm ./receiver/logs/*.log
rm ./receiver2/logs/*.log
rm ./*.output
rm ./*.signed
