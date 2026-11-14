import RFC_9052
import Testing

@Suite
struct `RFC 9052 Tests` {

    @Test
    func `the Appendix C.7 key sets encode to the sizes the RFC gives`() {
        #expect(RFC_8949.encode(Appendix.publicKeys).count == 481)
        #expect(RFC_8949.encode(Appendix.privateKeys).count == 816)
    }

    @Test
    func `the Appendix C.7.1 public key set is read`() throws {
        let set = try RFC_9052.KeySet(Appendix.publicKeys)
        #expect(set.keys.count == 4)
        #expect(set.keys.map(\.keyType) == [2, 2, 2, 2])
        #expect(set.keys[0].keyID == Array("meriadoc.brandybuck@buckland.example".utf8))
        #expect(set.keys[1].keyID == Array("11".utf8))
        #expect(set.keys[2][-1] == 3)
        #expect(set.keys[0].algorithm == nil)
        #expect(set.keys[0].keyOperations == nil)
    }

    @Test
    func `the Appendix C.7.2 private key set is read`() throws {
        let set = try RFC_9052.KeySet(Appendix.privateKeys)
        #expect(set.keys.map(\.keyType) == [2, 2, 2, 4, 2, 4, 4])
        #expect(set.keys[3].keyID == Array("our-secret".utf8))
    }

    @Test
    func `a key decodes from its encoding and keeps its parameters in order`() throws {
        let set = try RFC_9052.KeySet(Appendix.publicKeys)
        let first = set.keys[0]
        let decoded = try RFC_9052.Key(decoding: RFC_8949.encode(first.value))
        #expect(decoded == first)
        #expect(decoded.parameters.map(\.key) == [-1, -2, -3, 1, 2])
    }

    @Test
    func `common parameters of the wrong type are refused`() {
        #expect(throws: RFC_9052.Error.structure) { try RFC_9052.Key([1, 2]) }
        #expect(throws: RFC_9052.Error.missingKeyType) { try RFC_9052.Key([2: .bytes([1])]) }
        #expect(throws: RFC_9052.Error.parameter(1)) { try RFC_9052.Key([1: .bytes([2])]) }
        #expect(throws: RFC_9052.Error.parameter(2)) { try RFC_9052.Key([1: 2, 2: "text"]) }
        #expect(throws: RFC_9052.Error.parameter(3)) { try RFC_9052.Key([1: 2, 3: .bytes([])]) }
        #expect(throws: RFC_9052.Error.parameter(4)) { try RFC_9052.Key([1: 2, 4: []]) }
        #expect(throws: RFC_9052.Error.parameter(4)) { try RFC_9052.Key([1: 2, 4: [.bytes([])]]) }
        #expect(throws: RFC_9052.Error.parameter(5)) { try RFC_9052.Key([1: 2, 5: 1]) }
        #expect(throws: RFC_9052.Error.label(.bytes([1]))) { try RFC_9052.Key([1: 2, .bytes([1]): 1]) }
        #expect(throws: RFC_9052.Error.structure) { try RFC_9052.KeySet([1: 2]) }
    }

    @Test
    func `text identifiers are accepted for kty, alg and key_ops`() throws {
        let key = try RFC_9052.Key([1: "private-type", 3: "private-alg", 4: [1, "sign"]])
        #expect(key.keyType == "private-type")
        #expect(key.algorithm == "private-alg")
        #expect(key.keyOperations == [1, "sign"])
    }

    @Test
    func `bytes that are not CBOR are refused with the CBOR error`() {
        #expect(throws: RFC_9052.Error.cbor(.truncated(at: 1))) { try RFC_9052.Key(decoding: [0xa1]) }
    }
}
