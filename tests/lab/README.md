# krb5 lab

Throwaway MIT krb5 KDC (Debian bookworm, krb5 1.20) with python-gssapi in the
same container, for the interop tests of the RFC4121 GSSAPI code
(`asyauth/protocols/kerberos/gssapirfc.py`, `client/gssnative.py`).

`pytest tests/` builds and starts the container on its own when docker is
available (the lab tests are skipped otherwise) and removes it afterwards. Set
`ASYAUTH_LAB_KEEP=1` to keep it running. Nothing is published on the host, the
tests reach the KDC on the address of the container and drive the MIT side
over `docker exec`.

By hand:

    docker build -t asyauth-krb5lab tests/lab
    docker run -d --name asyauth-krb5lab --hostname kdc.test.lab asyauth-krb5lab

Realm `TEST.LAB`, user `alice` / `Passw0rd!`, services `nfs/aes256.test.lab`,
`nfs/aes128.test.lab` and `nfs/rc4.test.lab`. The name of the service tells
the etype of the ticket session key the KDC hands out for it.

## Cross-realm

The same image run with other `LAB_REALM` / `LAB_TRUSTS` settings gives the
realms for the cross-realm tests (`tests/test_gss_crossrealm.py`, containers
`asyauth-krb5lab-other` and `asyauth-krb5lab-third`, started only for those
tests). Each has the same user and services, named after its realm
(`nfs/aes256.other.lab@OTHER.LAB`).

    TEST.LAB  --krbtgt/OTHER.LAB@TEST.LAB-->  OTHER.LAB  --krbtgt/THIRD.LAB@OTHER.LAB-->  THIRD.LAB

Users of `TEST.LAB` can reach the services of `OTHER.LAB` directly and those
of `THIRD.LAB` over `OTHER.LAB`, nothing works in the other direction. The
KDCs map `*.other.lab` hostnames to `OTHER.LAB` and so on (`[domain_realm]`),
so asking the KDC of `TEST.LAB` for `nfs/aes256.other.lab` is answered with a
referral. The tests which need the KDC of a realm to be found by the name of
the realm patch the name resolution of python for that.

- `peer.py` MIT GSSAPI acceptor driven over stdin/stdout
- `genvectors.py` generates `tests/testdata/mit_gss_vectors.json` (MIT on both
  sides of the context):
  `docker exec asyauth-krb5lab python3 /genvectors.py > tests/testdata/mit_gss_vectors.json`
