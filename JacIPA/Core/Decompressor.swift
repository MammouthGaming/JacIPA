import Foundation
import Compression

enum CompressionKind: Equatable {
    case none, gzip, xz, zstd, bzip2, lzmaAlone, unknown

    /// Détection par les octets magiques d'abord, par l'extension ensuite.
    static func detect(data: Data, filename: String) -> CompressionKind {
        if data.count >= 6 {
            if data.byte(0) == 0x1F, data.byte(1) == 0x8B { return .gzip }
            if data.byte(0) == 0xFD, data.byte(1) == 0x37, data.byte(2) == 0x7A,
               data.byte(3) == 0x58, data.byte(4) == 0x5A { return .xz }
            if data.byte(0) == 0x28, data.byte(1) == 0xB5, data.byte(2) == 0x2F, data.byte(3) == 0xFD { return .zstd }
            if data.byte(0) == 0x42, data.byte(1) == 0x5A, data.byte(2) == 0x68 { return .bzip2 }
            if data.count > 262, data.ascii(257, 5) == "ustar" { return .none }
        }
        let lower = filename.lowercased()
        if lower.hasSuffix(".gz") { return .gzip }
        if lower.hasSuffix(".xz") { return .xz }
        if lower.hasSuffix(".zst") { return .zstd }
        if lower.hasSuffix(".bz2") { return .bzip2 }
        if lower.hasSuffix(".lzma") { return .lzmaAlone }
        if lower.hasSuffix(".tar") { return .none }
        return .unknown
    }
}

enum Decompressor {
    /// Décompresse un membre `data.tar.*` / `control.tar.*` d'un .deb.
    static func decompress(_ data: Data, filename: String) throws -> Data {
        switch CompressionKind.detect(data: data, filename: filename) {
        case .none:
            return data
        case .gzip:
            return try decode(stripGzipHeader(data), algorithm: COMPRESSION_ZLIB)
        case .xz:
            return try decode(data, algorithm: COMPRESSION_LZMA)
        case .lzmaAlone:
            // LZMA 1 « alone » (dpkg ancien, utilisé par GTok) : pas géré par Compression → décodeur maison.
            return try LzmaAloneDecoder.decode(data)
        case .zstd:
            throw JacIPAError.message("\(filename) est compressé en zstd. Pas encore géré par JacIPA (prévu dans une prochaine version).")
        case .bzip2:
            throw JacIPAError.message("\(filename) est compressé en bzip2. Pas géré par JacIPA.")
        case .unknown:
            throw JacIPAError.message("Format de compression inconnu pour \(filename).")
        }
    }

    /// Décodage en flux avec le framework Compression. `COMPRESSION_ZLIB` = deflate brut (zip, gzip sans en-tête).
    static func decode(_ input: Data, algorithm: compression_algorithm, maxOutput: Int? = nil) throws -> Data {
        guard !input.isEmpty else { return Data() }

        let stream = UnsafeMutablePointer<compression_stream>.allocate(capacity: 1)
        defer { stream.deallocate() }
        guard compression_stream_init(stream, COMPRESSION_STREAM_DECODE, algorithm) != COMPRESSION_STATUS_ERROR else {
            throw JacIPAError.message("Impossible d'initialiser la décompression.")
        }
        defer { compression_stream_destroy(stream) }

        let chunk = 1 << 18
        let dst = UnsafeMutablePointer<UInt8>.allocate(capacity: chunk)
        defer { dst.deallocate() }

        var output = Data()
        output.reserveCapacity(min(input.count * 3, 256 << 20))

        try input.withUnsafeBytes { (src: UnsafeRawBufferPointer) throws in
            guard let base = src.baseAddress else { return }
            stream.pointee.src_ptr = base.assumingMemoryBound(to: UInt8.self)
            stream.pointee.src_size = src.count
            while true {
                stream.pointee.dst_ptr = dst
                stream.pointee.dst_size = chunk
                let status = compression_stream_process(stream, Int32(COMPRESSION_STREAM_FINALIZE.rawValue))
                let produced = chunk - stream.pointee.dst_size
                if produced > 0 { output.append(dst, count: produced) }
                if status == COMPRESSION_STATUS_END { return }
                if status == COMPRESSION_STATUS_ERROR {
                    throw JacIPAError.message("Données compressées corrompues ou format non supporté.")
                }
                if let maxOutput, output.count >= maxOutput { return }
                if produced == 0, stream.pointee.src_size == 0 { return }
            }
        }

        if let maxOutput, output.count > maxOutput {
            return Data(output.prefix(maxOutput))
        }
        return output
    }

    /// Retire l'en-tête gzip (RFC 1952) et le trailer pour ne garder que le deflate brut.
    static func stripGzipHeader(_ d: Data) throws -> Data {
        guard d.count >= 18, d.byte(0) == 0x1F, d.byte(1) == 0x8B, d.byte(2) == 8 else {
            throw JacIPAError.message("En-tête gzip invalide.")
        }
        let flags = d.byte(3)
        var off = 10
        if flags & 0x04 != 0 {
            guard off + 2 <= d.count else { throw JacIPAError.message("En-tête gzip tronqué.") }
            off += 2 + Int(d.u16(off))
        }
        if flags & 0x08 != 0 {
            while off < d.count, d.byte(off) != 0 { off += 1 }
            off += 1
        }
        if flags & 0x10 != 0 {
            while off < d.count, d.byte(off) != 0 { off += 1 }
            off += 1
        }
        if flags & 0x02 != 0 { off += 2 }
        guard off < d.count - 8 else { throw JacIPAError.message("En-tête gzip tronqué.") }
        return d.copy(off, d.count - 8 - off)
    }
}
