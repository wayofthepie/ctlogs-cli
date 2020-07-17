#!/usr/bin/env bash 
set -e

config=$1
certname="cert.crt"
key="delete.key"
openssl req \
    -x509 \
    -newkey rsa:4096 \
    -sha256 \
    -days 3560 \
    -nodes \
    -keyout $key \
    -out $certname \
    -subj '/C=IE/O=nocht/CN=ctlogs-test' \
    -extensions san \
    -config $config

rm $key
