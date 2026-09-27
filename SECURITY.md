# Security policy

Please report vulnerabilities privately: on
https://github.com/willykeenan/warren open the **Security** tab and choose
**Report a vulnerability** (do not open a public issue). Include
`warren --version`, your platform and steps to reproduce.

The security model is described in [README.md](README.md#security-model) and
the requirements the tests check in [docs/security.md](docs/security.md).

## Windows candidate boundary

Windows uses a protected user + SYSTEM DACL and a local named pipe in place of
Unix file modes and sockets. The client verifies pipe ownership; the server
rejects remote clients and requires the first instance. The only source module
permitted to contain unsafe code is `src/sys/windows.rs`, containing documented
Win32 calls and owned allocation/handle guards. All security policy and framing
logic is safe Rust and tested on the native host. This is a deliberate exception
to the earlier crate-wide unsafe ban and needs independent security review.
Windows kernel behavior and cross-account rejection still require Windows proof.

## Named LAN gateway candidate

Named gateway shares add explicit, key-bound LAN access to the existing loopback
shares. See [gateway security and commands](docs/gateway-shares.md).
The source candidate is not yet the Windows-inclusive v0.2.0 release.
