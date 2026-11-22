# swift-rfc-9052

Use this package to read COSE keys (RFC 9052, section 7), the CBOR form in which WebAuthn authenticators and other COSE users hand over public keys. Start from `IETF.RFC.`9052`.Key` for one key and `IETF.RFC.`9052`.KeySet` for an array of them. What a key's type adds, such as an elliptic-curve key's curve and coordinates, is read with swift-rfc-9053.

## Laws

- The key sets of Appendix C.7 are read, and encode to the 481 and 816 bytes the RFC gives.
- A key must be a CBOR map with integer or text labels and a `kty` parameter. `kty` and `alg` must be integers or text, `kid` and `Base IV` byte strings, and `key_ops` a non-empty array of integers and text. Anything else is refused when the key is made.
- Parameters are kept in the order written, including those this package does not interpret. A map that repeats a label is refused by CBOR decoding.
- COSE messages (COSE_Sign, COSE_Encrypt, COSE_Mac and their single-recipient forms) are not modelled yet.
