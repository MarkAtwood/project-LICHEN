# X.509 Fixtures

These DER fixtures were generated with OpenSSL 3 from fresh RSA-2048 keys.
They are independent of the mbedTLS verifier under test.

| File | Purpose |
|------|---------|
| `root.der` | Configured valid trust anchor |
| `intermediate.der` | CA intermediate signed by `root.der` |
| `leaf.der` | Valid end-entity signed by `intermediate.der` |
| `wrong-root.der` | Unrelated trust anchor |
| `bad-signature.der` | Leaf name matches the intermediate, but another key signed it |
| `ca-leaf.der` | Leaf marked `CA:TRUE` |
| `no-digital-signature.der` | Leaf lacks `digitalSignature` key usage |

The source PEM files and private keys remain outside the repository. The
committed DER files contain public certificates only.
