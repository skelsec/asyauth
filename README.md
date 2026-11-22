# asyauth

Unified authentication library. Asynchronous, pure Python implementations of
the authentication protocols the network clients need (NTLM, Kerberos, SPNEGO,
CredSSP), behind one credential format and one context API, so the protocol
libraries on top of it ([aiosmb](https://github.com/skelsec/aiosmb),
[msldap](https://github.com/skelsec/msldap),
[aardwolf](https://github.com/skelsec/aardwolf), ...) do not each have to
bring their own.

It is made for people testing systems, not for hardening clients: pass-the-hash,
pass-the-key, pass-the-ticket, weak encryption types and relaying are features.

## Install

    pip install asyauth

or from the source tree:

    pip install .

Python 3.7+. Depends on `unicrypto`, `asn1crypto`, `asysocks` and
`minikerberos`.

## What is in it

| Protocol | Client | Server | Relay | Notes |
|---|---|---|---|---|
| NTLM | yes | yes | yes | NTLMv2, signing and sealing, anonymous |
| Kerberos | yes | | | Windows flavour for SMB / LDAP / DCERPC / RDP |
| Kerberos GSSAPI (RFC) | yes | | | raw krb5 mechanism per RFC4121 / RFC1964, for MIT krb5 / Heimdal peers |
| SPNEGO | yes | yes | yes | wraps NTLM and / or Kerberos |
| SPNEGOEX | yes | | | |
| CredSSP | yes | | | wraps SPNEGO (RDP, WinRM) |

`SIMPLE`, `PLAIN`, `SICILY`, `SSL`, SSH keys and the NFS `SYS` / `NULL` flavours
only exist as credential types, the protocol library using them does the rest.

A credential also has a subprotocol, which tells who does the actual work:

| Subprotocol | |
|---|---|
| `native` | asyauth itself, the default |
| `sspi` | the SSPI of the current Windows logon session, no secret needed |
| `sspiproxy` | SSPI of a remote agent |
| `wsnet`, `wsnetdirect` | SSPI over a wsnet agent |
| `custom` | your own factory object (`SubProtocolCustom`) |

## Credentials

Everything starts with a credential object. It can be created directly, from
an URL or from command line style parameters.

```python
from asyauth.common.constants import asyauthSecret
from asyauth.common.credentials.ntlm import NTLMCredential
from asyauth.common.credentials.kerberos import KerberosCredential
from asyauth.common.credentials.spnego import SPNEGOCredential
from asysocks.unicomm.common.target import UniTarget, UniProto

ntlm = NTLMCredential('Passw0rd!', 'alice', 'TEST', asyauthSecret.PASSWORD)

kdc = UniTarget('10.0.0.1', 88, UniProto.CLIENT_TCP, dc_ip = '10.0.0.1', domain = 'TEST.CORP')
kerberos = KerberosCredential('Passw0rd!', 'alice', 'TEST.CORP', asyauthSecret.PASSWORD, target = kdc)

# SPNEGO offering both
spnego = SPNEGOCredential([kerberos, ntlm])
```

### URL format

	protocol+authproto-secrettype://[domain\]username:secret@host:port/?param=value&...

`protocol` belongs to the library using asyauth (`smb`, `ldap`, ...), asyauth
reads the part after the `+`.

```python
from asyauth.common.credentials import UniCredential

UniCredential.from_url('smb+ntlm-password://TEST\\alice:Passw0rd!@10.0.0.5')
UniCredential.from_url('smb+ntlm-nt://TEST\\alice:8846f7eaee8fb117ad06bdd830b7586c@10.0.0.5')
UniCredential.from_url('smb+kerberos-password://TEST.CORP\\alice:Passw0rd!@fs.test.corp/?dc=10.0.0.1')
UniCredential.from_url('smb+kerberos-ccache://TEST.CORP\\alice:alice.ccache@fs.test.corp/?dc=10.0.0.1')
UniCredential.from_url('smb+sspi-ntlm://10.0.0.5') # Windows only, current user
```

`from_url` gives the NTLM or Kerberos credential, wrapping it in SPNEGO /
CredSSP is the job of the protocol library. `from_params` takes the same
`authproto` strings and also the wrapped forms:

```python
UniCredential.from_params('ntlm-nt', 'TEST\\alice', None, '8846f7eaee8fb117ad06bdd830b7586c')
UniCredential.from_params('spnego-kerberos-password', 'TEST.CORP\\alice', None, 'Passw0rd!', dc = '10.0.0.1')
UniCredential.from_params('credssp-ntlm-password', 'TEST\\alice', None, 'Passw0rd!')
```

`UniCredential.add_arguments(parser)` / `UniCredential.from_args(args)` do the
same for an `argparse` based tool, `UniCredential.argparser_help()` lists the
accepted `authproto` values.

Secret types:

| | |
|---|---|
| `password`, `pw`, `pass` | plaintext password |
| `pwhex`, `pwb64` | encoded password (`pwhex` also takes raw machine account passwords) |
| `pwprompt` | asks on the terminal |
| `nt`, `rc4` | NT hash |
| `aes` | Kerberos AES128 or AES256 key in hex, by length |
| `des`, `des3` | Kerberos DES / 3DES key in hex, give the matching `etype` (3 / 16) with it |
| `ccache`, `kirbi`, `keytab` | file name, with `hex` / `b64` suffix the encoded file itself |
| `pfx`, `pfxhex`, `pfxb64` | PKINIT, `keydata` is the file, the secret is its password |
| `none` | NTLM: anonymous. Kerberos: no preauth |

URL parameters:

| | |
|---|---|
| `dc` | Kerberos: address of the KDC. Mandatory |
| `etype` | Kerberos: encryption types to ask for, repeatable (`etype=23&etype=17`) |
| `dcc`, `realmc` | Kerberos: KDC address and name of the realm of the service when it is not the realm of the user |
| `altname`, `altdomain`, `certdata`, `keydata` | Kerberos: certificate authentication |
| `ntlmnosig` | NTLM: do not negotiate signing and sealing |
| `ntlmdisableess` | NTLM server: no extended session security in the challenge |
| `ntlmworkstation`, `ntlmdomain` | NTLM: names in the negotiate message |
| `ntlmflags` | NTLM: negotiate flags as a number |
| `ntlmversionmajor`, `ntlmversionminor`, `ntlmversionbuild` | NTLM: version in the messages |
| `proxy...` | Kerberos: proxy to reach the KDC, the proxy parameters of `asysocks` |

## Authenticating

`build_context()` on the credential gives the authentication context. All
contexts are driven the same way: call `authenticate` with the token of the
peer (`None` first) until it says there is nothing more to do. Errors are
returned, not raised.

```python
ctx = credential.build_context()

token, to_continue, err = await ctx.authenticate(None, spn = 'cifs/fs.test.corp@TEST.CORP')
while err is None and to_continue is True:
	reply = await exchange_with_server(token) # your protocol
	token, to_continue, err = await ctx.authenticate(reply, spn = 'cifs/fs.test.corp@TEST.CORP')
if err is not None:
	raise err

session_key = ctx.get_session_key()
if ctx.signing_needed():
	signature = await ctx.sign(data, message_no)
if ctx.encryption_needed():
	...	# await ctx.encrypt(data, message_no) / await ctx.decrypt(data, message_no)
```

`flags` takes `ISC_REQ` values (`asyauth.common.winapi.constants`) to ask for
mutual authentication, integrity, confidentiality and so on, `cb_data` the
channel bindings. What `encrypt` / `decrypt` return depends on the mechanism,
see `asyauth/common/clientauthalgo.py` for the interface.

A context can be used for one authentication only, take a new one from the
credential for each connection.

## NTLM

Native NTLM supports an explicit anonymous credential:

```python
from asyauth.common.credentials import UniCredential

credential = UniCredential.from_url("smb+ntlm-none://server.example")
```

`ntlm-none` is normalized to an empty username/domain with no secret and emits
the MS-NLMP anonymous AUTHENTICATE form. `NTLMCredential.create_anonymous()` is
the programmatic equivalent; `create_guest()` remains a compatibility alias.
Named accounts with an empty password must use `ntlm-password`. Kerberos
`none` credentials do not acquire anonymous semantics.

Native NTLM server credentials accept `ntlmdisableess=True` (or the
`ntlmdisableess=1` URL parameter) to clear extended session security from the
Type 2 challenge. This does not select NTLMv1 versus NTLMv2 authentication.

Server and relay side: `asyauth/protocols/ntlm/server`, `asyauth/protocols/ntlm/relay`
and their SPNEGO counterparts in `asyauth/protocols/spnego`.

## Kerberos

The Kerberos protocol itself is [minikerberos](https://github.com/skelsec/minikerberos),
asyauth adds the GSSAPI part. There are two flavours and they are not
interchangeable.

### Windows flavour

`credential.build_context()` gives `KerberosClientNative`, what Windows
services (SMB, LDAP, DCERPC, RDP) expect, normally inside SPNEGO. This is what
you get from the `kerberos-*` and `spnego-kerberos-*` credentials.

### RFC flavour

`credential.build_gss_context()` gives `KerberosGSSClientNative`: the raw
Kerberos V5 GSSAPI mechanism as the RFCs have it, no SPNEGO, no Windows
specifics. For peers built on MIT krb5 or Heimdal, the first user being
RPCSEC_GSS (NFS).

```python
from asyauth.protocols.kerberos.gssapi import GSSAPIFlags

ctx = credential.build_gss_context() # credential is a KerberosCredential
flags = GSSAPIFlags.GSS_C_MUTUAL_FLAG | GSSAPIFlags.GSS_C_INTEG_FLAG | GSSAPIFlags.GSS_C_CONF_FLAG

token, to_continue, err = await ctx.authenticate(None, flags = flags, spn = 'nfs/server.test.corp@TEST.CORP')
# send token to the acceptor. With mutual auth to_continue is set, feed the reply:
_, to_continue, err = await ctx.authenticate(reply_token)

mic, err = await ctx.get_mic(data)
_, err = await ctx.verify_mic(data, mic_from_peer)
token, err = await ctx.wrap(data, confidential = True)
data, confidential, err = await ctx.unwrap(token_from_peer)
```

- The per-message tokens follow the encryption type of the context key: AES
  (RFC4121), RC4 (RFC4757), 3DES and DES (RFC1964).
- `ctx.etypes` is the list of session key encryption types the KDC is asked
  for, `[18, 17, 23, 16, 3]` by default. Set it before `authenticate` to get a
  weaker context where the service allows it, eg. `ctx.etypes = [3]` for DES.
- Sequence numbers are kept by the context. Incoming tokens are only checked
  for order / replay when `GSS_C_SEQUENCE_FLAG` / `GSS_C_REPLAY_FLAG` was
  requested. A protocol where the messages arrive in any order (RPCSEC_GSS)
  must not request them.
- `des-cbc-crc` session keys are not supported, the tokens for such a key are.

### Cross-realm

With the RFC flavour the service can be in another realm than the user, over
a direct or a transitive trust. The realm comes from the SPN
(`nfs/server.other.corp@OTHER.CORP`), from the credential (`realmc`), or from
the KDC of the user when it answers with a referral. The KDC of that realm is
the `cross_target` of the credential (`dcc`). Without it, and for the realms
in between when the trust is not a direct one, the name of the realm has to
resolve to its KDC, as it does in AD.

	smb+kerberos-password://TEST.CORP\alice:Passw0rd!@server.other.corp/?dc=10.0.0.1&dcc=10.1.0.1&realmc=OTHER.CORP

## Tests

	pip install pytest
	pytest asyauth/tests tests

`asyauth/tests` are unit tests. `tests` has the token test vectors and the
interop tests of the RFC flavour Kerberos GSSAPI against MIT krb5. The latter
start throwaway KDC containers on their own and are skipped when docker is not
available, see [tests/lab/README.md](tests/lab/README.md).

## Author

Tamas Jos (@skelsec)
