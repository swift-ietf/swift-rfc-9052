extension IETF.RFC.`9052` {

    /// Why a CBOR item is not a COSE_Key or COSE_KeySet.
    public enum Error: Swift.Error, Sendable, Equatable {

        /// The bytes are not one CBOR item.
        case cbor(IETF.RFC.`8949`.Error)

        /// A COSE_Key that is not a map, or a COSE_KeySet that is not an array.
        case structure

        /// A key without the `kty` parameter.
        case missingKeyType

        /// A label that is neither an integer nor a text string.
        case label(IETF.RFC.`8949`.Value)

        /// A common parameter whose value has the wrong type (section 7.1): `kty` and `alg` must be an integer or a
        /// text string, `kid` and `Base IV` a byte string, `key_ops` a non-empty array of integers and text strings.
        case parameter(IETF.RFC.`8949`.Value)
    }
}
