#!/bin/bash

BUILD_TYPE=debug
if [ "$1" = "release" ]; then
  BUILD_TYPE=$1
fi
echo "Clearing identities..."

cd env/
rm ./sender/.identity/*
rm ./receiver/.identity/*
