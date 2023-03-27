#!/bin/bash

BUILD_TYPE=debug
if [ "$1" = "release" ]; then
  BUILD_TYPE=$1
fi
echo "Clearing identities..."

cd env/
rm ./sender/.identity/*
rm ./sender2/.identity/*
rm ./receiver/.identity/*
rm ./receiver2/.identity/*
