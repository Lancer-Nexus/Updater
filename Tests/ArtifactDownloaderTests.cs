using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using LancerNexus.Updater;
using Xunit;

namespace LancerNexus.Updater.Tests;

public sealed class ArtifactDownloaderTests
{
    [Fact]
    public async Task ResumesExistingPartialWithValidatedContentRange()
    {
        var bytes = Enumerable.Range(0, 64).Select(x => (byte)x).ToArray();
        using var fixture = new Fixture(bytes);
        var offset = 19;
        await File.WriteAllBytesAsync(fixture.PartialPath, bytes[..offset]);
        long? requestedOffset = null;
        using var handler = new ResponseHandler(request =>
        {
            requestedOffset = request.Headers.Range?.Ranges.Single().From;
            return Partial(bytes[offset..], offset, bytes.Length);
        });

        var path = await ArtifactDownloader.DownloadVerifiedAsync(
            fixture.Package, fixture.Options, CancellationToken.None, handler);

        Assert.Equal(offset, requestedOffset);
        Assert.Equal(bytes, await File.ReadAllBytesAsync(path));
        Assert.False(File.Exists(fixture.PartialPath));
    }

    [Fact]
    public async Task RestartsFromZeroWhenServerIgnoresRangeRequest()
    {
        var bytes = Enumerable.Range(0, 48).Select(x => (byte)(x + 1)).ToArray();
        using var fixture = new Fixture(bytes);
        await File.WriteAllBytesAsync(fixture.PartialPath, bytes[..7]);
        using var handler = new ResponseHandler(request =>
        {
            Assert.NotNull(request.Headers.Range);
            return new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(bytes) };
        });

        var path = await ArtifactDownloader.DownloadVerifiedAsync(
            fixture.Package, fixture.Options, CancellationToken.None, handler);

        Assert.Equal(bytes, await File.ReadAllBytesAsync(path));
    }

    [Fact]
    public async Task InterruptedBodyKeepsPartialAndNextCallResumesIt()
    {
        var bytes = Enumerable.Range(0, 80).Select(x => (byte)(255 - x)).ToArray();
        using var fixture = new Fixture(bytes);
        var written = 23;
        using (var interruptedHandler = new ResponseHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StreamContent(new FailingAfterPrefixStream(bytes[..written]))
        }))
        {
            await Assert.ThrowsAsync<IOException>(() => ArtifactDownloader.DownloadVerifiedAsync(
                fixture.Package, fixture.Options, CancellationToken.None, interruptedHandler));
        }
        Assert.Equal(written, new FileInfo(fixture.PartialPath).Length);

        long? requestedOffset = null;
        using var resumeHandler = new ResponseHandler(request =>
        {
            requestedOffset = request.Headers.Range?.Ranges.Single().From;
            return Partial(bytes[written..], written, bytes.Length);
        });
        var finalPath = await ArtifactDownloader.DownloadVerifiedAsync(
            fixture.Package, fixture.Options, CancellationToken.None, resumeHandler);

        Assert.Equal(written, requestedOffset);
        Assert.Equal(bytes, await File.ReadAllBytesAsync(finalPath));
    }

    [Fact]
    public async Task RejectsMismatchedRangeWithoutChangingPartial()
    {
        var bytes = Enumerable.Range(0, 32).Select(x => (byte)x).ToArray();
        using var fixture = new Fixture(bytes);
        var prefix = bytes[..9];
        await File.WriteAllBytesAsync(fixture.PartialPath, prefix);
        using var handler = new ResponseHandler(_ => Partial(bytes[9..], 8, bytes.Length));

        await Assert.ThrowsAsync<InvalidDataException>(() => ArtifactDownloader.DownloadVerifiedAsync(
            fixture.Package, fixture.Options, CancellationToken.None, handler));
        Assert.Equal(prefix, await File.ReadAllBytesAsync(fixture.PartialPath));
    }

    private static HttpResponseMessage Partial(byte[] bytes, long from, long total)
    {
        var response = new HttpResponseMessage(HttpStatusCode.PartialContent)
        {
            Content = new ByteArrayContent(bytes)
        };
        response.Content.Headers.ContentRange = new ContentRangeHeaderValue(from, total - 1, total);
        return response;
    }

    private sealed class Fixture : IDisposable
    {
        private readonly string root = Path.Combine(Path.GetTempPath(), "nap-download-tests-" + Guid.NewGuid().ToString("N"));
        public UpdatePackage Package { get; }
        public UpdaterOptions Options { get; }
        public string PartialPath => Path.Combine(Options.CachePath, "." + Package.Sha256 + ".part");

        public Fixture(byte[] bytes)
        {
            var cache = Path.Combine(root, "cache");
            Directory.CreateDirectory(cache);
            Package = new UpdatePackage("core", "1", "artifacts/core.nap", bytes.Length,
                Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant(), true, "nap");
            Options = new UpdaterOptions(new Uri("https://updates.example.test/manifest"), "stable", "linux", "x64",
                "trusted-root.json", ArtifactBaseUri: new Uri("https://updates.example.test/v1/"), CachePath: cache,
                InstallRootPath: root);
        }

        public void Dispose()
        {
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }

    private sealed class ResponseHandler(Func<HttpRequestMessage, HttpResponseMessage> respond) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(respond(request));
    }

    private sealed class FailingAfterPrefixStream(byte[] prefix) : Stream
    {
        private int position;
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));
        public override int Read(Span<byte> buffer)
        {
            if (position != 0) throw new IOException("Synthetic interrupted response.");
            var count = Math.Min(buffer.Length, prefix.Length);
            prefix.AsSpan(0, count).CopyTo(buffer);
            position = count;
            return count;
        }
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try { return ValueTask.FromResult(Read(buffer.Span)); }
            catch (Exception error) { return ValueTask.FromException<int>(error); }
        }
        public override void Flush() => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
