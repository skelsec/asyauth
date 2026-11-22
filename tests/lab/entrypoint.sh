#!/bin/sh
# Creates the TEST.LAB realm with the users and services the tests use, then runs the KDC.
set -e

AES256=aes256-cts-hmac-sha1-96:normal
AES128=aes128-cts-hmac-sha1-96:normal
RC4=arcfour-hmac:normal

kdb5_util create -s -r TEST.LAB -P masterpw

# user
kadmin.local -q "addprinc -pw Passw0rd! -e $AES256,$AES128,$RC4 alice"

# services
kadmin.local -q "addprinc -randkey -e $AES256 nfs/aes256.test.lab"
kadmin.local -q "addprinc -randkey -e $AES128 nfs/aes128.test.lab"
kadmin.local -q "addprinc -randkey -e $RC4 nfs/rc4.test.lab"
# the etype of the ticket session key (and so of the GSS context) follows this, not the key of the service
kadmin.local -q "setstr nfs/aes256.test.lab session_enctypes aes256-cts-hmac-sha1-96"
kadmin.local -q "setstr nfs/aes128.test.lab session_enctypes aes128-cts-hmac-sha1-96"
kadmin.local -q "setstr nfs/rc4.test.lab session_enctypes arcfour-hmac"
kadmin.local -q "ktadd -k /etc/krb5.keytab nfs/aes256.test.lab nfs/aes128.test.lab nfs/rc4.test.lab"

# credentials in other forms for the tests to fetch
mkdir -p /creds
kadmin.local -q "ktadd -norandkey -k /creds/alice.keytab alice"

krb5kdc

kinit -k -t /creds/alice.keytab -c /creds/alice.ccache alice
kvno -c /creds/alice.ccache nfs/aes256.test.lab
chmod 644 /creds/*
touch /ready

exec sleep infinity
