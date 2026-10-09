using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using LancerNexus.Updater;
using ZstdSharp;
using Xunit;

namespace LancerNexus.Updater.Tests;

public sealed class NapPackageVerifierTests
{
    [Fact]
    public void AcceptsStructurallyValidArchiveAndVerifiesContents()
    {
        using var archive = new MemoryStream(NapFixture.Create([0x7f]));
        NapPackageVerifier.Verify(archive);
    }

    [Fact]
    public void AcceptsAndVerifiesIndependentlyCompressedChunks()
    {
        using var archive = new MemoryStream(NapFixture.Create(Enumerable.Repeat((byte)0x37, 8192).ToArray(), compress: true));
        NapPackageVerifier.Verify(archive);
    }

    [Theory]
    [InlineData("header")]
    [InlineData("payload")]
    [InlineData("index-hash")]
    public void RejectsCorruptedArchive(string corruption)
    {
        var bytes = NapFixture.Create([0x7f]);
        switch (corruption)
        {
            case "header": bytes[8] = 2; break;
            case "payload": bytes[^1] ^= 0xff; break;
            case "index-hash": bytes[96] ^= 0xff; break;
        }
        using var archive = new MemoryStream(bytes);
        Assert.Throws<InvalidDataException>(() => NapPackageVerifier.Verify(archive));
    }

    [Fact]
    public void RejectsUnsafeArchivePathEvenWhenIndexHashMatches()
    {
        using var archive = new MemoryStream(NapFixture.Create([0x7f], "../escape"));
        Assert.Throws<InvalidDataException>(() => NapPackageVerifier.Verify(archive));
    }
}

internal static class NapFixture
{
    public static byte[] Create(byte[] payload, string path = "a.bin", bool compress = false)
    {
        var pathBytes = Encoding.UTF8.GetBytes(path);
        var contentHash = SHA256.HashData(payload);
        byte[] storedPayload;
        if (compress)
        {
            using var compressed = new MemoryStream();
            using (var encoder = new CompressionStream(compressed, 3, 0, true))
                encoder.Write(payload);
            storedPayload = compressed.ToArray();
        }
        else storedPayload = payload;
        using var indexStream = new MemoryStream();
        using (var index = new BinaryWriter(indexStream, Encoding.UTF8, leaveOpen: true))
        {
            index.Write(Encoding.ASCII.GetBytes("NAPIDX1\0"));
            index.Write((uint)1);
            index.Write((ushort)pathBytes.Length);
            index.Write(pathBytes);
            index.Write((byte)0);
            index.Write((ulong)payload.Length);
            index.Write(contentHash);
            index.Write((uint)1);
            index.Write((uint)0);
        }
        var indexBytes = indexStream.ToArray();
        var chunkOffset = 128L + indexBytes.Length;
        var payloadOffset = chunkOffset + 64;
        var header = new byte[128];
        new byte[] { 0x4c, 0x4e, 0x41, 0x50, 0x00, 0x0d, 0x0a, 0x1a }.CopyTo(header, 0);
        BinaryPrimitives.WriteUInt16LittleEndian(header.AsSpan(8), 1);
        BinaryPrimitives.WriteUInt16LittleEndian(header.AsSpan(10), 128);
        Guid.NewGuid().TryWriteBytes(header.AsSpan(16, 16));
        BinaryPrimitives.WriteUInt64LittleEndian(header.AsSpan(32), 1);
        BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(40), 1024);
        BinaryPrimitives.WriteUInt64LittleEndian(header.AsSpan(48), 128);
        BinaryPrimitives.WriteUInt64LittleEndian(header.AsSpan(56), (ulong)indexBytes.Length);
        BinaryPrimitives.WriteUInt64LittleEndian(header.AsSpan(64), (ulong)chunkOffset);
        BinaryPrimitives.WriteUInt64LittleEndian(header.AsSpan(72), 64);
        BinaryPrimitives.WriteUInt64LittleEndian(header.AsSpan(80), (ulong)payloadOffset);
        BinaryPrimitives.WriteUInt64LittleEndian(header.AsSpan(88), (ulong)storedPayload.Length);
        SHA256.HashData(indexBytes).CopyTo(header, 96);

        var chunk = new byte[64];
        contentHash.CopyTo(chunk, 0);
        BinaryPrimitives.WriteUInt64LittleEndian(chunk.AsSpan(32), (ulong)storedPayload.Length);
        BinaryPrimitives.WriteUInt64LittleEndian(chunk.AsSpan(40), (ulong)payload.Length);
        BinaryPrimitives.WriteUInt64LittleEndian(chunk.AsSpan(48), (ulong)payloadOffset);
        chunk[56] = compress ? (byte)1 : (byte)0;
        using var archive = new MemoryStream();
        archive.Write(header);
        archive.Write(indexBytes);
        archive.Write(chunk);
        archive.Write(storedPayload);
        return archive.ToArray();
    }
}
