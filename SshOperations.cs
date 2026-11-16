using System.Collections.Concurrent;
using System.Text;
using Renci.SshNet;

namespace ServerPilot;

public sealed record CommandResult(int? ExitCode, string? ExitSignal, string Stdout, string Stderr, bool OutputTruncated);

public sealed class SshOperations(ServerStore store, AppOptions options, ILogger<SshOperations> logger)
{
    private const long MaxFileBytes = 128L * 1024 * 1024;
    private const int MaxOutputBytes = 512 * 1024;

    private static Renci.SshNet.ConnectionInfo Connection(StoredServer server)
    {
        AuthenticationMethod auth;
        if (server.View.AuthType == "password") auth = new PasswordAuthenticationMethod(server.View.Username, server.Credential.Password!);
        else
        {
            using var stream = new MemoryStream(Encoding.UTF8.GetBytes(server.Credential.PrivateKey!));
            var key = string.IsNullOrEmpty(server.Credential.Passphrase) ? new PrivateKeyFile(stream) : new PrivateKeyFile(stream, server.Credential.Passphrase);
            auth = new PrivateKeyAuthenticationMethod(server.View.Username, key);
        }
        return new Renci.SshNet.ConnectionInfo(server.View.Host, server.View.Port, server.View.Username, auth) { Timeout = TimeSpan.FromSeconds(15) };
    }
    private static void Pin(BaseClient client, ServerView server) => client.HostKeyReceived += (_, args) => args.CanTrust = Secrets.Equal("SHA256:" + args.FingerPrintSHA256, server.HostFingerprint);
    private SshClient Connect(StoredServer server)
    {
        var client = new SshClient(Connection(server)); Pin(client, server.View);
        try { client.Connect(); return client; } catch { client.Dispose(); throw; }
    }
    private SftpClient ConnectSftp(StoredServer server)
    {
        var client = new SftpClient(Connection(server)) { OperationTimeout = TimeSpan.FromMinutes(3) }; Pin(client, server.View);
        try { client.Connect(); return client; } catch { client.Dispose(); throw; }
    }
    private async Task<T> Logged<T>(string serverId, string actor, string action, Func<StoredServer, Task<T>> perform)
    {
        var server = store.Get(serverId);
        try { var result = await perform(server); store.Audit(actor, server.View.Name, action, "success"); return result; }
        catch (Exception e) { logger.LogWarning("SSH operation {Action} failed for {Server}; error type {ErrorType}", action, server.View.Name, e.GetType().Name); store.Audit(actor, server.View.Name, action, "failed"); throw; }
    }
    public Task<object> Test(string id, string actor) => Logged<object>(id, actor, "ssh.test", s => Task.Run<object>(() => { using var client = Connect(s); return new { connected = client.IsConnected, server = s.View.Name }; }));
    public Task<object> Probe(string host, int port)
    {
        if (string.IsNullOrWhiteSpace(host) || host.Length > 255 || host.Any(char.IsWhiteSpace) || host.Contains('/') || host.Contains('@') || port is < 1 or > 65535)
            throw new ArgumentException("服务器地址或端口无效。");
        return Task.Run<object>(() =>
        {
            using var client = new SshClient(host, port, "serverpilot-probe", "unused");
            client.ConnectionInfo.Timeout = TimeSpan.FromSeconds(15);
            string? fingerprint = null, algorithm = null;
            client.HostKeyReceived += (_, e) => { fingerprint = "SHA256:" + e.FingerPrintSHA256; algorithm = e.HostKeyName; e.CanTrust = false; };
            try { client.Connect(); } catch when (fingerprint is not null) { /* Stop before authentication. */ }
            if (fingerprint is null) throw new InvalidOperationException("未能获取主机指纹，请检查地址和网络。");
            return new { fingerprint, algorithm, warning = "此指纹来自当前网络连接，必须通过可信渠道独立核对。" };
        });
    }
    public Task<CommandResult> Execute(string id, string command, int seconds, string actor, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(command) || command.Length > 32768) throw new ArgumentException("命令为空或过长。");
        if (seconds is < 1 or > 1800) throw new ArgumentException("超时应在 1–1800 秒之间。");
        return Logged(id, actor, "ssh.execute", async s =>
        {
            using var client = await Task.Run(() => Connect(s), ct);
            using var cmd = client.CreateCommand(command); cmd.CommandTimeout = TimeSpan.FromSeconds(seconds);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct);
            linked.CancelAfter(TimeSpan.FromSeconds(seconds));
            var running = cmd.ExecuteAsync(linked.Token);
            var stdout = ReadBounded(cmd.OutputStream, linked.Token);
            var stderr = ReadBounded(cmd.ExtendedOutputStream, linked.Token);
            await Task.WhenAll(running, stdout, stderr);
            return new CommandResult(cmd.ExitStatus, cmd.ExitSignal, stdout.Result.Text, stderr.Result.Text, stdout.Result.Truncated || stderr.Result.Truncated);
        });
    }
    private static async Task<(string Text, bool Truncated)> ReadBounded(Stream stream, CancellationToken ct)
    {
        using var buffer = new MemoryStream(); var bytes = new byte[8192]; bool truncated = false; int n;
        while ((n = await stream.ReadAsync(bytes, ct)) > 0)
        {
            var keep = (int)Math.Min(n, MaxOutputBytes - buffer.Length);
            if (keep > 0) buffer.Write(bytes, 0, keep);
            if (keep < n) truncated = true;
        }
        return (Encoding.UTF8.GetString(buffer.ToArray()), truncated);
    }
    private string StagingPath(string name)
    {
        if (string.IsNullOrWhiteSpace(name) || name.Length > 180 || name is "." or ".." || name.IndexOfAny(['/', '\\', '\0', ':']) >= 0 || Path.GetFileName(name) != name)
            throw new ArgumentException("文件名必须是普通文件名，不能包含路径。");
        return Path.Combine(options.StagingDirectory, name);
    }
    private static void RemotePath(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || !path.StartsWith('/') || path.Contains('\0') || path.Length > 4096) throw new ArgumentException("远程路径必须是 Linux 绝对路径。");
    }
    public List<object> ListStaging() => Directory.EnumerateFiles(options.StagingDirectory).Select(p => new FileInfo(p)).Where(f => !f.Attributes.HasFlag(FileAttributes.ReparsePoint)).OrderBy(f => f.Name).Select(f => (object)new { name = f.Name, size = f.Length, updatedAt = f.LastWriteTimeUtc }).ToList();
    public async Task<object> StageFile(string name, Stream input, long length, CancellationToken ct)
    {
        if (length < 0 || length > MaxFileBytes) throw new ArgumentException("文件不能超过 128 MiB。");
        var path = StagingPath(name); if (File.Exists(path)) throw new ArgumentException("文件已存在，请换一个名称。");
        var created = false;
        try
        {
            await using var output = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
            created = true;
            if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            await input.CopyToAsync(output, ct);
            if (output.Length > MaxFileBytes) throw new ArgumentException("文件不能超过 128 MiB。");
            store.Audit("web", "-", "staging.upload", "success"); return new { name, size = output.Length };
        }
        catch { if (created && File.Exists(path)) File.Delete(path); throw; }
    }
    public Stream OpenStaged(string name)
    {
        var p = StagingPath(name); if (!File.Exists(p)) throw new FileNotFoundException("文件不存在。");
        if (File.GetAttributes(p).HasFlag(FileAttributes.ReparsePoint)) throw new ArgumentException("不支持符号链接。");
        return new FileStream(p, FileMode.Open, FileAccess.Read, FileShare.Read);
    }
    public void DeleteStaged(string name) { var path = StagingPath(name); if (!File.Exists(path)) throw new FileNotFoundException("文件不存在。"); File.Delete(path); store.Audit("web", "-", "staging.delete", "success"); }
    public Task<object> Upload(string id, string stagingFile, string remotePath, string actor, bool overwrite = false)
    {
        RemotePath(remotePath);
        return Logged<object>(id, actor, "sftp.upload", s => Task.Run<object>(() =>
        {
            using var input = OpenStaged(stagingFile); if (input.Length > MaxFileBytes) throw new ArgumentException("文件不能超过 128 MiB。");
            using var sftp = ConnectSftp(s); if (!overwrite && sftp.Exists(remotePath)) throw new ArgumentException("远程文件已存在；如需覆盖，请明确指定。");
            sftp.UploadFile(input, remotePath, overwrite); return new { uploaded = true, stagingFile, remotePath, bytes = input.Length };
        }));
    }
    public Task<object> Download(string id, string remotePath, string stagingFile, string actor)
    {
        RemotePath(remotePath); var local = StagingPath(stagingFile);
        return Logged<object>(id, actor, "sftp.download", s => Task.Run<object>(() =>
        {
            using var sftp = ConnectSftp(s); var attr = sftp.GetAttributes(remotePath);
            if (!attr.IsRegularFile || attr.Size > MaxFileBytes) throw new ArgumentException("仅支持下载不超过 128 MiB 的普通文件。");
            if (File.Exists(local)) throw new ArgumentException("暂存区文件已存在，请换一个名称。");
            var created = false;
            try
            {
                using var output = new FileStream(local, FileMode.CreateNew, FileAccess.Write, FileShare.None);
                created = true;
                if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(local, UnixFileMode.UserRead | UnixFileMode.UserWrite);
                using var limited = new LimitedWriteStream(output, MaxFileBytes); sftp.DownloadFile(remotePath, limited);
                return new { downloaded = true, stagingFile, remotePath, bytes = output.Length };
            }
            catch { if (created && File.Exists(local)) File.Delete(local); throw; }
        }));
    }
    private sealed class LimitedWriteStream(Stream inner, long max) : Stream
    {
        private long count;
        public override void Write(byte[] buffer, int offset, int count) { if (this.count + count > max) throw new IOException("File exceeds limit."); inner.Write(buffer, offset, count); this.count += count; }
        public override bool CanRead => false; public override bool CanSeek => false; public override bool CanWrite => true;
        public override long Length => count; public override long Position { get => count; set => throw new NotSupportedException(); }
        public override void Flush() => inner.Flush(); public override int Read(byte[] b,int o,int c) => throw new NotSupportedException();
        public override long Seek(long o,SeekOrigin s) => throw new NotSupportedException(); public override void SetLength(long v) => throw new NotSupportedException();
    }
}

public sealed class JobService(SshOperations ssh)
{
    private sealed class Job { public required string Id; public required string Server; public string Status = "running"; public CommandResult? Result; public string? Error; }
    private readonly ConcurrentDictionary<string, Job> jobs = new();
    public object Start(string server, string command, int timeoutSeconds)
    {
        if (jobs.Count >= 100) throw new ArgumentException("任务数量已达上限，请重启服务后再试。");
        if (string.IsNullOrWhiteSpace(command) || timeoutSeconds is < 1 or > 1800) throw new ArgumentException("命令为空或超时无效。");
        var job = new Job { Id = Guid.NewGuid().ToString("N"), Server = server }; jobs[job.Id] = job;
        _ = Task.Run(async () => { try { job.Result = await ssh.Execute(server, command, timeoutSeconds, "mcp-job", CancellationToken.None); job.Status = "completed"; } catch (Exception e) { job.Error = Errors.Public(e); job.Status = "failed"; } });
        return new { jobId = job.Id, status = job.Status, note = "任务仅在服务运行期间保留，完成后提供输出；服务重启会丢失任务状态。" };
    }
    public object Status(string id)
    {
        if (!jobs.TryGetValue(id, out var job)) throw new ArgumentException("任务不存在或服务已重启。");
        return new { jobId = job.Id, server = job.Server, status = job.Status, result = job.Result, error = job.Error };
    }
}
