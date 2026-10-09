namespace LancerNexus.Updater;

public sealed class UpdaterRunLock : IDisposable
{
    private readonly FileStream lockStream;

    private UpdaterRunLock(FileStream lockStream) => this.lockStream = lockStream;

    public static UpdaterRunLock Acquire(string installRoot)
    {
        var root = Path.GetFullPath(installRoot);
        Directory.CreateDirectory(root);
        var lockPath = Path.Combine(root, "updater.lock");
        if (File.Exists(lockPath) && (File.GetAttributes(lockPath) & FileAttributes.ReparsePoint) != 0)
            throw new InvalidDataException("Updater-Lockdatei darf kein symbolischer Link sein.");

        try
        {
            return new UpdaterRunLock(new FileStream(lockPath, FileMode.OpenOrCreate, FileAccess.ReadWrite,
                FileShare.None, bufferSize: 1, FileOptions.WriteThrough));
        }
        catch (IOException error)
        {
            throw new InvalidOperationException("Ein anderer Updater-Prozess bearbeitet diese Installation bereits.", error);
        }
    }

    public void Dispose() => lockStream.Dispose();
}
