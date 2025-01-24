#!/bin/bash

if [ "$1" = "" ]
then
    echo "Usage: $0 <noir-version>"
    exit 1
fi

VERSION=$1

curl -L https://raw.githubusercontent.com/noir-lang/noirup/main/install | bash
curl -L https://raw.githubusercontent.com/AztecProtocol/aztec-packages/refs/heads/master/barretenberg/bbup/install | bash
export NARGO_HOME="$HOME/.nargo"
export PATH="$PATH:$NARGO_HOME/bin:$HOME/.bb"
cd hello_world
noirup -v $VERSION
bbup
nargo check --overwrite
cp Prover.toml.template Prover.toml
nargo compile
nargo execute hello_world
mkdir ../artifacts/$VERSION
bb prove -b target/hello_world.json -w target/hello_world.gz -o ../artifacts/$VERSION/proof.bin
bb write_vk -b target/hello_world.json -o ../artifacts/$VERSION/vk.bin
