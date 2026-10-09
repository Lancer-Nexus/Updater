using System.Diagnostics;
using Xunit;

namespace LancerNexus.Updater.Tests;

public sealed class UpdaterRunLockTests
{
    [Fact]
    public async Task SerializesUpdaterProcessesForTheSameInstallationAndReleasesLockOnDispose()
    {
        var root = Path.Combine(Path.GetTempPath(), $"updater-run-lock-{Guid.NewGuid():N}");
        try
        {
            using (UpdaterRunLock.Acquire(root))
            {
                var error = Assert.Throws<InvalidOperationException>(() => UpdaterRunLock.Acquire(root));
                Assert.Contains("anderer Updater-Prozess", error.Message, StringComparison.Ordinal);

                var probePath = Path.Combine(AppContext.BaseDirectory, "activation-probe",
                    OperatingSystem.IsWindows() ? "activation-crash-probe.exe" : "activation-crash-probe");
                Assert.True(File.Exists(probePath), $"Activation probe was not found at {probePath}.");
                if (!OperatingSystem.IsWindows())
                    File.SetUnixFileMode(probePath,
                        UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
                using var process = Process.Start(new ProcessStartInfo
                {
                    FileName = probePath,
                    UseShellExecute = false,
                    ArgumentList = { "--lock-check", root }
                });
                Assert.NotNull(process);
                using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                await process.WaitForExitAsync(timeout.Token);
                Assert.Equal(74, process.ExitCode);
            }

            using var retry = UpdaterRunLock.Acquire(root);
            Assert.True(File.Exists(Path.Combine(root, "updater.lock")));
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }
}
