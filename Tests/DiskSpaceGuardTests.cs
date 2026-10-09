using LancerNexus.Updater;
using Xunit;

namespace LancerNexus.Updater.Tests;

public sealed class DiskSpaceGuardTests
{
    [Fact]
    public void RejectsStagingWhenAvailableSpaceIsBelowTheRequiredBytes()
    {
        var error = Assert.Throws<IOException>(() => DiskSpaceGuard.EnsureAvailable(
            Path.GetTempPath(), 101, _ => 100));
        Assert.Contains("101 Byte benötigt", error.Message);
        Assert.Contains("100 Byte verfügbar", error.Message);
    }

    [Fact]
    public void AllowsOperationWhenAvailableSpaceMeetsTheRequiredBytes()
    {
        DiskSpaceGuard.EnsureAvailable(Path.GetTempPath(), 100, _ => 100);
    }
}
