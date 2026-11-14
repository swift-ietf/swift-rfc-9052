extension RFC_9052 {

    /// A COSE_KeySet (section 7): an array of keys.
    public struct KeySet: Sendable, Hashable {

        public let keys: [Key]

        public init(_ value: RFC_8949.Value) throws(RFC_9052.Error) {
            guard case .array(let items) = value else { throw .structure }
            var keys: [Key] = []
            for item in items {
                keys.append(try Key(item))
            }
            self.keys = keys
        }
    }
}
