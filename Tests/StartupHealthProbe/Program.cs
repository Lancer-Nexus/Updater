using System.Diagnostics;
using System.Text;

var acknowledgementPath = Environment.GetEnvironmentVariable("LANCER_NEXUS_HEALTH_ACK_PATH");
var acknowledgementToken = Environment.GetEnvironmentVariable("LANCER_NEXUS_HEALTH_ACK_TOKEN");
if (string.IsNullOrWhiteSpace(acknowledgementPath) || string.IsNullOrWhiteSpace(acknowledgementToken))
    return 2;

await File.WriteAllTextAsync(acknowledgementPath + ".pid", Environment.ProcessId.ToString());
var directory = AppContext.BaseDirectory;
if (File.Exists(Path.Combine(directory, "no-ack")))
{
    await Task.Delay(Timeout.InfiniteTimeSpan);
}
if (File.Exists(Path.Combine(directory, "fail-startup")))
    return 1;

await File.WriteAllBytesAsync(acknowledgementPath, Encoding.ASCII.GetBytes(acknowledgementToken));
return 0;
