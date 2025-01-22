#!/bin/bash

if [ "$1" = "" ]
then
    echo "Usage: $0 <noir-version>"
    exit 1
fi

docker run --rm -ti \
    -v "${PWD}/../resources:/script/artifacts" \
    -u $(id -u):$(id -g) \
    generate-test-data $@
