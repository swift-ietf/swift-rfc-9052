import RFC_9052
import Testing

struct Fuzzing: RandomNumberGenerator {
    var state: UInt64

    mutating func next() -> UInt64 {
        state &+= 0x9e37_79b9_7f4a_7c15
        var z = state
        z = (z ^ (z >> 30)) &* 0xbf58_476d_1ce4_e5b9
        z = (z ^ (z >> 27)) &* 0x94d0_49bb_1331_11eb
        return z ^ (z >> 31)
    }

    mutating func bytes(upTo limit: Int) -> [UInt8] {
        (0..<Int.random(in: 0...limit, using: &self)).map { _ in UInt8.random(in: .min ... .max, using: &self) }
    }
}

@Suite(.timeLimit(.minutes(1)))
struct `Fuzz Tests` {
    @Test
    func `random bytes are read as a key or refused, never crash`() {
        var random = Fuzzing(state: 0xc05e)
        for _ in 0..<50_000 {
            _ = try? RFC_9052.Key(decoding: random.bytes(upTo: 96))
        }
    }

    @Test
    func `random maps of small labels are read as a key or refused, never crash`() {
        var random = Fuzzing(state: 0x6a9)
        for _ in 0..<20_000 {
            let count = Int.random(in: 0...6, using: &random)
            var bytes: [UInt8] = [0xa0 | UInt8(count)]
            for _ in 0..<count {
                bytes.append(UInt8.random(in: 0x00...0x17, using: &random) | (Bool.random(using: &random) ? 0x20 : 0))
                bytes += random.bytes(upTo: 8)
            }
            _ = try? RFC_9052.Key(decoding: bytes)
        }
    }
}
