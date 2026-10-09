using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using ZstdSharp;

namespace LancerNexus.Updater;

/// <summary>Validates a complete NAP V1 archive before it becomes part of an active release.</summary>
public static class NapPackageVerifier
{
    public sealed record Metadata(Guid PackageId, ulong ContentVersion, IReadOnlyList<string> EntryPaths);
    private static readonly byte[] Magic = [0x4c, 0x4e, 0x41, 0x50, 0x00, 0x0d, 0x0a, 0x1a];
    private const int HeaderSize = 128;
    private const int ChunkRecordSize = 64;
    private const int MaxIndexSize = 64 * 1024 * 1024;
    private const uint MaxEntries = 1_000_000;
    private const uint MaxChunks = 4_000_000;
    private const int MaxChunkSize = 1024 * 1024;
    private const int MaxCompressedChunkSize = MaxChunkSize + 64 * 1024;

    private sealed record Chunk(byte[] Hash, long CompressedLength, long Length, long Offset, byte Codec);

    public static Metadata VerifyFile(string path)
    {
        using var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read,
            128 * 1024, FileOptions.SequentialScan);
        return Verify(file);
    }

    public static Metadata Verify(Stream stream)
    {
        ArgumentNullException.ThrowIfNull(stream);
        if (!stream.CanRead || !stream.CanSeek)
            throw new ArgumentException("NAP input must be readable and seekable.", nameof(stream));
        stream.Position = 0;
        if (stream.Length < HeaderSize) throw new InvalidDataException("NAP header is truncated.");
        using var reader = new BinaryReader(stream, Encoding.UTF8, leaveOpen: true);
        var header = ReadExact(reader, HeaderSize);
        if (!header.AsSpan(0, 8).SequenceEqual(Magic) || U16(header, 8) != 1 || U16(header, 10) != HeaderSize ||
            U32(header, 12) != 0 || U32(header, 44) != 0)
            throw new InvalidDataException("NAP header magic, version, size, flags or reserved bytes are invalid.");
        var chunkHint = U32(header, 40);
        if (chunkHint is 0 or > MaxChunkSize) throw new InvalidDataException("NAP chunk size hint is invalid.");
        var packageId = new Guid(header.AsSpan(16, 16));
        var contentVersion = U64(header, 32);

        var indexOffset = CheckedLong(U64(header, 48));
        var indexLength = CheckedLong(U64(header, 56));
        var chunkOffset = CheckedLong(U64(header, 64));
        var chunkLength = CheckedLong(U64(header, 72));
        var payloadOffset = CheckedLong(U64(header, 80));
        var payloadLength = CheckedLong(U64(header, 88));
        if (indexLength is < 12 or > MaxIndexSize || chunkLength % ChunkRecordSize != 0 ||
            chunkLength / ChunkRecordSize > MaxChunks)
            throw new InvalidDataException("NAP index or chunk table exceeds supported limits.");
        CheckRange(indexOffset, indexLength, stream.Length);
        CheckRange(chunkOffset, chunkLength, stream.Length);
        CheckRange(payloadOffset, payloadLength, stream.Length);
        if (indexOffset != HeaderSize || chunkOffset != indexOffset + indexLength ||
            payloadOffset != chunkOffset + chunkLength || payloadOffset + payloadLength != stream.Length)
            throw new InvalidDataException("NAP sections are not contiguous or do not match the file length.");

        stream.Position = indexOffset;
        var index = ReadExact(reader, checked((int)indexLength));
        if (!CryptographicOperations.FixedTimeEquals(SHA256.HashData(index), header.AsSpan(96, 32)))
            throw new InvalidDataException("NAP index hash mismatch.");

        stream.Position = chunkOffset;
        var chunks = new Chunk[checked((int)(chunkLength / ChunkRecordSize))];
        var ranges = new List<(long Start, long End)>(chunks.Length);
        for (var i = 0; i < chunks.Length; i++)
        {
            var record = ReadExact(reader, ChunkRecordSize);
            var codec = record[56];
            if (codec > 1 || record.AsSpan(57, 7).IndexOfAnyExcept((byte)0) >= 0)
                throw new InvalidDataException("NAP chunk codec or reserved bytes are invalid.");
            var compressedLength = CheckedLong(U64(record, 32));
            var length = CheckedLong(U64(record, 40));
            var offset = CheckedLong(U64(record, 48));
            if (length is <= 0 or > MaxChunkSize || compressedLength is <= 0 or > MaxCompressedChunkSize ||
                offset < payloadOffset || offset > payloadOffset + payloadLength ||
                compressedLength > payloadOffset + payloadLength - offset || codec == 0 && compressedLength != length)
                throw new InvalidDataException("NAP chunk bounds or lengths are invalid.");
            chunks[i] = new Chunk(record[..32], compressedLength, length, offset, codec);
            ranges.Add((offset, checked(offset + compressedLength)));
        }
        ranges.Sort((left, right) => left.Start.CompareTo(right.Start));
        for (var i = 1; i < ranges.Count; i++)
            if (ranges[i].Start < ranges[i - 1].End)
                throw new InvalidDataException("NAP chunk payload ranges overlap.");

        var entries = ParseIndex(index, chunks);
        VerifyContent(stream, entries, chunks);
        return new Metadata(packageId, contentVersion, entries.Select(entry => entry.Path).ToArray());
    }

    private sealed record Entry(string Path, long Length, byte[] Hash, int[] Chunks, bool Tombstone);

    private static List<Entry> ParseIndex(byte[] bytes, Chunk[] chunks)
    {
        using var stream = new MemoryStream(bytes, writable: false);
        using var reader = new BinaryReader(stream, Encoding.UTF8);
        if (!ReadExact(reader, 8).AsSpan().SequenceEqual(Encoding.ASCII.GetBytes("NAPIDX1\0")))
            throw new InvalidDataException("NAP index magic is invalid.");
        var count = reader.ReadUInt32();
        if (count > MaxEntries) throw new InvalidDataException("NAP entry count exceeds the supported limit.");
        var entries = new List<Entry>(checked((int)count));
        var paths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        string? previous = null;
        for (var i = 0; i < count; i++)
        {
            var pathLength = reader.ReadUInt16();
            if (pathLength == 0 || pathLength > 4096) throw new InvalidDataException("NAP path length is invalid.");
            var path = new UTF8Encoding(false, true).GetString(ReadExact(reader, pathLength));
            if (!IsCanonicalPath(path) || previous is not null && StringComparer.Ordinal.Compare(previous, path) >= 0 ||
                !paths.Add(path))
                throw new InvalidDataException("NAP paths are unsafe, noncanonical, unsorted or duplicated.");
            previous = path;
            var flags = reader.ReadByte();
            if (flags > 1) throw new InvalidDataException("NAP entry flags are invalid.");
            var length = CheckedLong(reader.ReadUInt64());
            var hash = ReadExact(reader, 32);
            var referenceCount = reader.ReadUInt32();
            if (referenceCount > MaxChunks || flags == 1 && (length != 0 || referenceCount != 0))
                throw new InvalidDataException("NAP entry chunk references are invalid.");
            var references = new int[checked((int)referenceCount)];
            long total = 0;
            for (var j = 0; j < references.Length; j++)
            {
                references[j] = checked((int)reader.ReadUInt32());
                if (references[j] >= chunks.Length) throw new InvalidDataException("NAP entry references an unknown chunk.");
                total = checked(total + chunks[references[j]].Length);
            }
            if (flags == 0 && total != length) throw new InvalidDataException("NAP file length does not match its chunks.");
            if (flags == 0 && length == 0 && !hash.AsSpan().SequenceEqual(SHA256.HashData([])))
                throw new InvalidDataException("NAP empty file hash is invalid.");
            if (flags == 1 && hash.AsSpan().IndexOfAnyExcept((byte)0) >= 0)
                throw new InvalidDataException("NAP tombstone hash is invalid.");
            entries.Add(new Entry(path, length, hash, references, flags == 1));
        }
        if (stream.Position != stream.Length) throw new InvalidDataException("NAP index has trailing bytes.");
        return entries;
    }

    private static void VerifyContent(Stream stream, IReadOnlyList<Entry> entries, IReadOnlyList<Chunk> chunks)
    {
        foreach (var entry in entries)
        {
            if (entry.Tombstone) continue;
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            long length = 0;
            foreach (var index in entry.Chunks)
            {
                var data = ReadChunk(stream, chunks[index]);
                length = checked(length + data.LongLength);
                hash.AppendData(data);
            }
            if (length != entry.Length ||
                !CryptographicOperations.FixedTimeEquals(hash.GetHashAndReset(), entry.Hash))
                throw new InvalidDataException($"NAP file content hash mismatch: {entry.Path}");
        }
    }

    private static byte[] ReadChunk(Stream stream, Chunk chunk)
    {
        stream.Position = chunk.Offset;
        var stored = new byte[checked((int)chunk.CompressedLength)];
        stream.ReadExactly(stored);
        byte[] data;
        if (chunk.Codec == 0) data = stored;
        else
        {
            try
            {
                using var source = new MemoryStream(stored, writable: false);
                using var decoder = new DecompressionStream(source);
                using var output = new MemoryStream(checked((int)chunk.Length));
                var buffer = new byte[8192];
                int read;
                while ((read = decoder.Read(buffer, 0, buffer.Length)) != 0)
                {
                    if (output.Length > chunk.Length - read)
                        throw new InvalidDataException("NAP chunk expands beyond its declared length.");
                    output.Write(buffer, 0, read);
                }
                data = output.ToArray();
            }
            catch (Exception error) when (error is not InvalidDataException)
            {
                throw new InvalidDataException("NAP chunk decompression failed.", error);
            }
        }
        if (data.LongLength != chunk.Length ||
            !CryptographicOperations.FixedTimeEquals(SHA256.HashData(data), chunk.Hash))
            throw new InvalidDataException("NAP chunk length or hash mismatch.");
        return data;
    }

    private static bool IsCanonicalPath(string path)
    {
        if (path.Length == 0 || path.Contains('\\') || path.Contains(':') || path.StartsWith('/') ||
            path.IndexOf('\0') >= 0 || path.StartsWith("EXE/../DATA/", StringComparison.OrdinalIgnoreCase) ||
            path.StartsWith("DATA/", StringComparison.OrdinalIgnoreCase)) return false;
        var strictUtf8 = new UTF8Encoding(false, true);
        if (strictUtf8.GetByteCount(path) > 4096) return false;
        foreach (var part in path.Split('/'))
        {
            if (part.Length is 0 or > 255 || part is "." or ".." || part.EndsWith(' ') || part.EndsWith('.') ||
                part.Any(c => c < 0x20 || "<>\"|?*".Contains(c))) return false;
            var stem = part.Split('.')[0];
            if (stem.Equals("CON", StringComparison.OrdinalIgnoreCase) || stem.Equals("PRN", StringComparison.OrdinalIgnoreCase) ||
                stem.Equals("AUX", StringComparison.OrdinalIgnoreCase) || stem.Equals("NUL", StringComparison.OrdinalIgnoreCase) ||
                stem.Length == 4 && (stem.StartsWith("COM", StringComparison.OrdinalIgnoreCase) ||
                    stem.StartsWith("LPT", StringComparison.OrdinalIgnoreCase)) && stem[3] is >= '1' and <= '9') return false;
        }
        return true;
    }

    private static byte[] ReadExact(BinaryReader reader, int count)
    {
        var bytes = reader.ReadBytes(count);
        return bytes.Length == count ? bytes : throw new InvalidDataException("NAP data is truncated.");
    }

    private static ushort U16(byte[] value, int offset) => BinaryPrimitives.ReadUInt16LittleEndian(value.AsSpan(offset, 2));
    private static uint U32(byte[] value, int offset) => BinaryPrimitives.ReadUInt32LittleEndian(value.AsSpan(offset, 4));
    private static ulong U64(byte[] value, int offset) => BinaryPrimitives.ReadUInt64LittleEndian(value.AsSpan(offset, 8));
    private static long CheckedLong(ulong value) => value <= long.MaxValue ? (long)value :
        throw new InvalidDataException("NAP integer exceeds the supported range.");

    private static void CheckRange(long offset, long length, long total)
    {
        if (offset < 0 || length < 0 || offset > total || length > total - offset)
            throw new InvalidDataException("NAP section is outside the package.");
    }
}
