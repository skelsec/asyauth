#!/bin/sh
# Creates the realm with the users and services the tests use, then runs the KDC.
#	LAB_REALM   name of the realm, TEST.LAB if not set
#	LAB_TRUSTS  cross-realm krbtgt principals to create, like "krbtgt/OTHER.LAB@TEST.LAB"
#	LAB_LEGACY  set to also have the DES and 3DES services (needs the old krb5 of Dockerfile.legacy)
set -e

AES256=aes256-cts-hmac-sha1-96:normal
AES128=aes128-cts-hmac-sha1-96:normal
RC4=arcfour-hmac:normal
DES3=des3-cbc-sha1:normal
DES=des-cbc-md5:normal
DESCRC=des-cbc-crc:normal

REALM=${LAB_REALM:-TEST.LAB}
DOMAIN=$(echo $REALM | tr A-Z a-z)
KDC_ETYPES="$AES256 $AES128 $RC4"
if [ -n "$LAB_LEGACY" ]; then
	KDC_ETYPES="$KDC_ETYPES $DES3 $DES $DESCRC"
fi
ETYPES=$(echo $KDC_ETYPES | sed "s/:normal//g")
sed -i "s/@REALM@/$REALM/g; s/@ETYPES@/$ETYPES/; s/@KDC_ETYPES@/$KDC_ETYPES/" /etc/krb5.conf /etc/krb5kdc/kdc.conf

kdb5_util create -s -r $REALM -P masterpw

# user
kadmin.local -q "addprinc -pw Passw0rd! -e $AES256,$AES128,$RC4 alice"

# services
kadmin.local -q "addprinc -randkey -e $AES256 nfs/aes256.$DOMAIN"
kadmin.local -q "addprinc -randkey -e $AES128 nfs/aes128.$DOMAIN"
kadmin.local -q "addprinc -randkey -e $RC4 nfs/rc4.$DOMAIN"
# the etype of the ticket session key (and so of the GSS context) follows this, not the key of the service
kadmin.local -q "setstr nfs/aes256.$DOMAIN session_enctypes aes256-cts-hmac-sha1-96"
kadmin.local -q "setstr nfs/aes128.$DOMAIN session_enctypes aes128-cts-hmac-sha1-96"
kadmin.local -q "setstr nfs/rc4.$DOMAIN session_enctypes arcfour-hmac"
kadmin.local -q "ktadd -k /etc/krb5.keytab nfs/aes256.$DOMAIN nfs/aes128.$DOMAIN nfs/rc4.$DOMAIN"
if [ -n "$LAB_LEGACY" ]; then
	kadmin.local -q "addprinc -randkey -e $DES3 nfs/des3.$DOMAIN"
	kadmin.local -q "addprinc -randkey -e $DES nfs/des.$DOMAIN"
	kadmin.local -q "addprinc -randkey -e $DESCRC nfs/descrc.$DOMAIN"
	kadmin.local -q "setstr nfs/des3.$DOMAIN session_enctypes des3-cbc-sha1"
	kadmin.local -q "setstr nfs/des.$DOMAIN session_enctypes des-cbc-md5"
	kadmin.local -q "setstr nfs/descrc.$DOMAIN session_enctypes des-cbc-crc"
	# takes whatever session key etype the client asks for. The KDC does not hand out
	# DES session keys for a service unless they are listed like this
	kadmin.local -q "addprinc -randkey nfs/any.$DOMAIN"
	kadmin.local -q "setstr nfs/any.$DOMAIN session_enctypes \"$ETYPES\""
	kadmin.local -q "ktadd -k /etc/krb5.keytab nfs/des3.$DOMAIN nfs/des.$DOMAIN nfs/descrc.$DOMAIN nfs/any.$DOMAIN"
fi

# trusts. The same principal with the same key has to exist in both realms
for TRUST in $LAB_TRUSTS; do
	kadmin.local -q "addprinc -pw Trustpw0rd! -kvno 1 -e $AES256 $TRUST"
done

# credentials in other forms for the tests to fetch
mkdir -p /creds
kadmin.local -q "ktadd -norandkey -k /creds/alice.keytab alice"

krb5kdc

kinit -k -t /creds/alice.keytab -c /creds/alice.ccache alice
kvno -c /creds/alice.ccache nfs/aes256.$DOMAIN
chmod 644 /creds/*
touch /ready

exec sleep infinity
