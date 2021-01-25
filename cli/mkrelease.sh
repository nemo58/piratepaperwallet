#!/bin/bash
# This script depends on a docker image already being built
# To build it, 
# cd docker
# docker build --tag rustbuild:latest .

POSITIONAL=()
while [[ $# -gt 0 ]]
do
key="$1"

case $key in
    -v|--version)
    APP_VERSION="$2"
    shift # past argument
    shift # past value
    ;;
    *)    # unknown option
    POSITIONAL+=("$1") # save it in an array for later
    shift # past argument
    ;;
esac
done
set -- "${POSITIONAL[@]}" # restore positional parameters

if [ -z $APP_VERSION ]; then echo "APP_VERSION is not set"; exit 1; fi

# Clean everything first
cargo clean

# Compile for mac directly
cargo build --release 

# macOS
rm -rf target/macOS-piratepaperwallet-v$APP_VERSION
mkdir -p target/macOS-piratepaperwallet-v$APP_VERSION
cp target/release/piratepaperwallet target/macOS-piratepaperwallet-v$APP_VERSION/

# For Windows and Linux, build via docker
docker run --rm -v $(pwd)/..:/opt/piratepaperwallet rustbuild:latest bash -c "cd /opt/piratepaperwallet/cli && cargo build --release && cargo build --release --target x86_64-pc-windows-gnu && cargo build --release --target aarch64-unknown-linux-gnu"

# Now sign and zip the binaries
gpg --batch --output target/macOS-piratepaperwallet-v$APP_VERSION/piratepaperwallet.sig --detach-sig target/macOS-piratepaperwallet-v$APP_VERSION/piratepaperwallet 
cd target
cd macOS-piratepaperwallet-v$APP_VERSION
gsha256sum piratepaperwallet > sha256sum.txt
cd ..
zip -r macOS-piratepaperwallet-v$APP_VERSION.zip macOS-piratepaperwallet-v$APP_VERSION 
cd ..


#Linux
rm -rf target/linux-piratepaperwallet-v$APP_VERSION
mkdir -p target/linux-piratepaperwallet-v$APP_VERSION
cp target/release/piratepaperwallet target/linux-piratepaperwallet-v$APP_VERSION/
gpg --batch --output target/linux-piratepaperwallet-v$APP_VERSION/piratepaperwallet.sig --detach-sig target/linux-piratepaperwallet-v$APP_VERSION/piratepaperwallet
cd target
cd linux-piratepaperwallet-v$APP_VERSION
gsha256sum piratepaperwallet > sha256sum.txt
cd ..
zip -r linux-piratepaperwallet-v$APP_VERSION.zip linux-piratepaperwallet-v$APP_VERSION 
cd ..


#Windows
rm -rf target/Windows-piratepaperwallet-v$APP_VERSION
mkdir -p target/Windows-piratepaperwallet-v$APP_VERSION
cp target/x86_64-pc-windows-gnu/release/piratepaperwallet.exe target/Windows-piratepaperwallet-v$APP_VERSION/
gpg --batch --output target/Windows-piratepaperwallet-v$APP_VERSION/piratepaperwallet.sig --detach-sig target/Windows-piratepaperwallet-v$APP_VERSION/piratepaperwallet.exe
cd target
cd Windows-piratepaperwallet-v$APP_VERSION
gsha256sum piratepaperwallet.exe > sha256sum.txt
cd ..
zip -r Windows-piratepaperwallet-v$APP_VERSION.zip Windows-piratepaperwallet-v$APP_VERSION 
cd ..


# aarch64 (armv8)
rm -rf target/aarch64-piratepaperwallet-v$APP_VERSION
mkdir -p target/aarch64-piratepaperwallet-v$APP_VERSION
cp target/aarch64-unknown-linux-gnu/release/piratepaperwallet target/aarch64-piratepaperwallet-v$APP_VERSION/
gpg --batch --output target/aarch64-piratepaperwallet-v$APP_VERSION/piratepaperwallet.sig --detach-sig target/aarch64-piratepaperwallet-v$APP_VERSION/piratepaperwallet
cd target
cd aarch64-piratepaperwallet-v$APP_VERSION
gsha256sum piratepaperwallet > sha256sum.txt
cd ..
zip -r aarch64-piratepaperwallet-v$APP_VERSION.zip aarch64-piratepaperwallet-v$APP_VERSION 
cd ..

