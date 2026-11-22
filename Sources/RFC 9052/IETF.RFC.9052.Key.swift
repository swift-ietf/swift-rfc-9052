extension IETF.RFC.`9052` {

    /// A COSE_Key (section 7): a map of key parameters, with the common parameters of section 7.1 checked.
    ///
    /// Parameters a key type adds, such as an EC2 key's curve and coordinates, are kept as they are and read by
    /// the code that knows that key type (RFC 9053 for the initial ones).
    public struct Key: Sendable, Hashable {

        /// The parameters, in the order they were written.
        public let parameters: [IETF.RFC.`8949`.Pair]

        /// A key from its CBOR map, refused when a common parameter is missing or has the wrong type.
        public init(_ value: IETF.RFC.`8949`.Value) throws(IETF.RFC.`9052`.Error) {
            guard case .map(let pairs) = value else { throw .structure }
            for pair in pairs {
                switch pair.key {
                case .unsigned, .negative, .text: break
                default: throw .label(pair.key)
                }
            }
            self.parameters = pairs
            guard let keyType = self[Label.keyType] else { throw .missingKeyType }
            guard Self.isIdentifier(keyType) else { throw .parameter(Label.keyType) }
            if let keyID = self[Label.keyID], keyID.bytes == nil { throw .parameter(Label.keyID) }
            if let algorithm = self[Label.algorithm], !Self.isIdentifier(algorithm) {
                throw .parameter(Label.algorithm)
            }
            if let operations = self[Label.keyOperations] {
                guard let items = operations.array, !items.isEmpty, items.allSatisfy(Self.isIdentifier) else {
                    throw .parameter(Label.keyOperations)
                }
            }
            if let iv = self[Label.baseIV], iv.bytes == nil { throw .parameter(Label.baseIV) }
        }

        /// The key encoded in `bytes`, with nothing after it.
        public init(decoding bytes: [UInt8]) throws(IETF.RFC.`9052`.Error) {
            let value: IETF.RFC.`8949`.Value
            do {
                value = try IETF.RFC.`8949`.decode(bytes)
            } catch {
                throw .cbor(error)
            }
            try self.init(value)
        }

        private static func isIdentifier(_ value: IETF.RFC.`8949`.Value) -> Bool {
            switch value {
            case .unsigned, .negative, .text: true
            default: false
            }
        }
    }
}

extension IETF.RFC.`9052`.Key {

    /// The labels of the common key parameters (section 7.1, Table 4).
    public enum Label {
        /// `kty`: the key type.
        public static let keyType: IETF.RFC.`8949`.Value = 1
        /// `kid`: the key identifier.
        public static let keyID: IETF.RFC.`8949`.Value = 2
        /// `alg`: the one algorithm the key may be used with.
        public static let algorithm: IETF.RFC.`8949`.Value = 3
        /// `key_ops`: the operations the key may be used for.
        public static let keyOperations: IETF.RFC.`8949`.Value = 4
        /// `Base IV`.
        public static let baseIV: IETF.RFC.`8949`.Value = 5
    }
}

extension IETF.RFC.`9052`.Key {

    /// The value of the parameter with `label`.
    public subscript(label: IETF.RFC.`8949`.Value) -> IETF.RFC.`8949`.Value? {
        parameters.first { $0.key == label }?.value
    }

    /// `kty`.
    public var keyType: IETF.RFC.`8949`.Value {
        guard let keyType = self[Label.keyType] else { preconditionFailure("checked when the key was made") }
        return keyType
    }

    /// `kid`, when present.
    public var keyID: [UInt8]? { self[Label.keyID]?.bytes }

    /// `alg`, when present.
    public var algorithm: IETF.RFC.`8949`.Value? { self[Label.algorithm] }

    /// `key_ops`, when present.
    public var keyOperations: [IETF.RFC.`8949`.Value]? { self[Label.keyOperations]?.array }

    /// The key as a CBOR map.
    public var value: IETF.RFC.`8949`.Value { .map(parameters) }
}
