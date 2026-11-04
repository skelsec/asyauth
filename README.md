# asyauth

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
