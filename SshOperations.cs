using System.Collections.Concurrent;
using System.Globalization;
using System.Text;
using Renci.SshNet;
using Renci.SshNet.Common;
using Renci.SshNet.Sftp;

namespace ServerPilot;

public sealed record CommandResult(int? ExitCode, string? ExitSignal, string Stdout, string Stderr, bool OutputTruncated);
public sealed record TextReadResult(string Content, long Size, long Offset, long BytesRead, long? NextOffset, bool IsBinary);

public sealed class SshOperations(ServerStore store, AppOptions options, ILogger<SshOperations> logger)
{
    private const long MaxFileBytes = 512L * 1024 * 1024;
    private const int MaxOutputBytes = 512 * 1024;
    private const int MaxReadBytes = 1024 * 1024;

    private static Renci.SshNet.ConnectionInfo Connection(StoredServer server, AppOptions options)
    {
        var methods = new List<AuthenticationMethod>();
        var view = server.View;
        if (view.AuthType == "password" && !string.IsNullOrEmpty(server.Credential.Password))
            methods.Add(new PasswordAuthenticationMethod(view.Username, server.Credential.Password));
        var keys = new List<IPrivateKeySource>();
        if (view.AuthType == "privateKey" && !string.IsNullOrEmpty(server.Credential.PrivateKey))
        {
            using var stream = new MemoryStream(Encoding.UTF8.GetBytes(server.Credential.PrivateKey));
            var key = string.IsNullOrEmpty(server.Credential.Passphrase) ? new PrivateKeyFile(stream) : new PrivateKeyFile(stream, server.Credential.Passphrase);
            keys.Add(key);
        }
        if (view.UseServiceKey)
        {
            if (string.IsNullOrEmpty(options.ServiceKeyPath)) throw new InvalidOperationException("服务器启用了服务端密钥认证，但未配置 SERVERPILOT_SERVICE_KEY_PATH。");
            var serviceKey = string.IsNullOrEmpty(options.ServiceKeyPassphrase) ? new PrivateKeyFile(options.ServiceKeyPath) : new PrivateKeyFile(options.ServiceKeyPath, options.ServiceKeyPassphrase);
            keys.Add(serviceKey);
        }
        if (keys.Count > 0) methods.Add(new PrivateKeyAuthenticationMethod(view.Username, keys.ToArray()));
        if (view.TryKeyboard)
        {
            var keyboard = new KeyboardInteractiveAuthenticationMethod(view.Username);
            keyboard.AuthenticationPrompt += (_, e) =>
            {
                foreach (var prompt in e.Prompts)
                {
                    var text = prompt.Request.ToLowerInvariant();
                    if (text.Contains("password") || text.Contains("密码")) prompt.Response = server.Credential.Password ?? "";
                    else if (text.Contains("passphrase") || text.Contains("口令")) prompt.Response = server.Credential.Passphrase ?? "";
                    else if (text.Contains("otp") || text.Contains("one-time") || text.Contains("verification") || text.Contains("code") || text.Contains("验证码")) prompt.Response = options.TwoFactorCode ?? "";
                    else prompt.Response = "";
                }
            };
            methods.Add(keyboard);
        }
        if (methods.Count == 0) throw new InvalidOperationException("服务器没有可用的 SSH 认证方式。");
        Renci.SshNet.ConnectionInfo info;
        if (string.IsNullOrWhiteSpace(view.Proxy))
            info = new Renci.SshNet.ConnectionInfo(view.Host, view.Port, view.Username, methods.ToArray());
        else
        {
            ServerStore.ValidateProxy(view.Proxy);
            var uri = new Uri(view.Proxy);
            var type = uri.Scheme switch
            {
                "socks4" => ProxyTypes.Socks4,
                "socks5" => ProxyTypes.Socks5,
                _ => ProxyTypes.Http
            };
            var proxyUser = Uri.UnescapeDataString(uri.UserInfo.Split(':', 2)[0]);
            var proxyPass = uri.UserInfo.Contains(':') ? Uri.UnescapeDataString(uri.UserInfo.Split(':', 2)[1]) : "";
            info = new Renci.SshNet.ConnectionInfo(view.Host, view.Port, view.Username, type, uri.Host, uri.Port, proxyUser, proxyPass, methods.ToArray());
        }
        info.Timeout = TimeSpan.FromSeconds(15);
        return info;
    }
    private static void Pin(BaseClient client, ServerView server) =>
        client.HostKeyReceived += (_, args) => args.CanTrust = Secrets.Equal("SHA256:" + args.FingerPrintSHA256, server.HostFingerprint);
    private SshClient Connect(StoredServer server)
    {
        var client = new SshClient(Connection(server, options)); Pin(client, server.View);
        try { client.Connect(); return client; } catch { client.Dispose(); throw; }
    }
    private SftpClient ConnectSftp(StoredServer server)
    {
        var client = new SftpClient(Connection(server, options)) { OperationTimeout = TimeSpan.FromMinutes(3) }; Pin(client, server.View);
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
        if (path.Split('/').Any(part => part is "." or "..")) throw new ArgumentException("远程路径不能包含 . 或 .. 路径段。");
    }
    private static void AllowedRemotePath(SftpClient client, ServerView server, string path)
    {
        RemotePath(path);
        var roots = server.AllowedRemotePaths.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (roots.Length == 0) return;
        var normalized = NormalizeRemote(path);
        var parent = normalized[..normalized.LastIndexOf('/')];
        if (parent.Length == 0) parent = "/";
        client.ChangeDirectory(parent);
        var resolvedParent = client.WorkingDirectory.TrimEnd('/');
        var resolved = resolvedParent + normalized[normalized.LastIndexOf('/')..];
        if (client.Exists(normalized) && client.GetAttributes(normalized).IsSymbolicLink)
            throw new ArgumentException("配置了路径限制时不支持操作符号链接。");
        var allowed = false;
        foreach (var root in roots)
        {
            client.ChangeDirectory(root);
            var canonicalRoot = client.WorkingDirectory.TrimEnd('/');
            if (canonicalRoot.Length == 0 || resolved == canonicalRoot || resolved.StartsWith(canonicalRoot + "/", StringComparison.Ordinal)) allowed = true;
        }
        if (!allowed) throw new ArgumentException("远端路径不在允许范围内。");
    }
    private static string NormalizeRemote(string path)
    {
        var parts = new List<string>();
        foreach (var part in path.Split('/'))
        {
            if (part.Length == 0 || part == ".") continue;
            if (part == "..") { if (parts.Count > 0) parts.RemoveAt(parts.Count - 1); continue; }
            parts.Add(part);
        }
        return "/" + string.Join('/', parts);
    }
    public List<object> ListStaging() => Directory.EnumerateFiles(options.StagingDirectory).Select(p => new FileInfo(p)).Where(f => !f.Attributes.HasFlag(FileAttributes.ReparsePoint)).OrderBy(f => f.Name).Select(f => (object)new { name = f.Name, size = f.Length, updatedAt = f.LastWriteTimeUtc }).ToList();
    public async Task<object> StageFile(string name, Stream input, long length, CancellationToken ct)
    {
        if (length < 0 || length > MaxFileBytes) throw new ArgumentException("文件不能超过 512 MiB。");
        var path = StagingPath(name); if (File.Exists(path)) throw new ArgumentException("文件已存在，请换一个名称。");
        var created = false;
        try
        {
            await using var output = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
            created = true;
            if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            await input.CopyToAsync(output, ct);
            if (output.Length > MaxFileBytes) throw new ArgumentException("文件不能超过 512 MiB。");
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
            using var input = OpenStaged(stagingFile); if (input.Length > MaxFileBytes) throw new ArgumentException("文件不能超过 512 MiB。");
            using var sftp = ConnectSftp(s); AllowedRemotePath(sftp, s.View, remotePath); if (!overwrite && sftp.Exists(remotePath)) throw new ArgumentException("远程文件已存在；如需覆盖，请明确指定。");
            sftp.UploadFile(input, remotePath, overwrite); return new { uploaded = true, stagingFile, remotePath, bytes = input.Length };
        }));
    }
    public Task<object> Download(string id, string remotePath, string stagingFile, string actor)
    {
        RemotePath(remotePath); var local = StagingPath(stagingFile);
        return Logged<object>(id, actor, "sftp.download", s => Task.Run<object>(() =>
        {
            using var sftp = ConnectSftp(s); AllowedRemotePath(sftp, s.View, remotePath); var attr = sftp.GetAttributes(remotePath);
            if (!attr.IsRegularFile || attr.Size > MaxFileBytes) throw new ArgumentException("仅支持下载不超过 512 MiB 的普通文件。");
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
    public Task<TextReadResult> ReadFile(string id, string remotePath, long offset, int length, string actor)
    {
        RemotePath(remotePath);
        if (offset < 0) throw new ArgumentException("offset 不能为负数。");
        if (length is < 1 or > MaxReadBytes) throw new ArgumentException($"length 应在 1–{MaxReadBytes} 字节之间。");
        return Logged(id, actor, "sftp.read_file", s => Task.Run(() =>
        {
            using var sftp = ConnectSftp(s);
            AllowedRemotePath(sftp, s.View, remotePath);
            var attr = sftp.GetAttributes(remotePath);
            if (!attr.IsRegularFile) throw new ArgumentException("仅支持读取普通文件。");
            if (offset > attr.Size) throw new ArgumentException("offset 超过文件大小。");
            var want = Math.Max(0, (int)Math.Min(length, attr.Size - offset));
            using var stream = sftp.OpenRead(remotePath);
            stream.Seek(offset, SeekOrigin.Begin);
            var buffer = new byte[want];
            var read = 0;
            while (read < want)
            {
                var n = stream.Read(buffer, read, want - read);
                if (n <= 0) break;
                read += n;
            }
            var data = buffer.AsSpan(0, read).ToArray();
            if (offset > 0 && data.Length > 0 && (data[0] & 0xC0) == 0x80)
                throw new ArgumentException("offset 必须位于 UTF-8 字符边界。");
            var consumed = 0;
            var binary = false;
            while (consumed < data.Length)
            {
                var status = Rune.DecodeFromUtf8(data.AsSpan(consumed), out var rune, out var count);
                if (status == System.Buffers.OperationStatus.NeedMoreData && offset + read < attr.Size) break;
                if (status != System.Buffers.OperationStatus.Done || rune.Value == 0) { binary = true; break; }
                consumed += count;
            }
            if (binary) consumed = data.Length;
            var text = binary ? "" : Encoding.UTF8.GetString(data, 0, consumed);
            if (!binary && consumed == 0 && data.Length > 0) throw new ArgumentException("读取长度不足以容纳一个 UTF-8 字符，请增大读取长度。");
            long? next = offset + consumed < attr.Size ? offset + consumed : null;
            return new TextReadResult(text, attr.Size, offset, consumed, next, binary);
        }));
    }
    public Task<object> WriteFile(string id, string remotePath, string content, bool append, int? mode, string actor)
    {
        RemotePath(remotePath);
        if (Encoding.UTF8.GetByteCount(content) > 2 * 1024 * 1024) throw new ArgumentException("单次写入内容不能超过 2 MiB。");
        if (mode is < 0 or > 0x1FF) throw new ArgumentException("权限位应在 0–0777 之间。");
        return Logged<object>(id, actor, "sftp.write_file", s => Task.Run<object>(() =>
        {
            using var sftp = ConnectSftp(s);
            AllowedRemotePath(sftp, s.View, remotePath);
            var existed = sftp.Exists(remotePath);
            var bytes = Encoding.UTF8.GetBytes(content);
            using (var stream = sftp.Open(remotePath, append ? FileMode.Append : FileMode.Create, FileAccess.Write))
            {
                stream.Write(bytes, 0, bytes.Length);
            }
            var chmod = mode.HasValue && !existed;
            if (chmod) sftp.ChangePermissions(remotePath, (short)mode!.Value);
            return new { written = true, remotePath, bytes = bytes.Length, appended = append, created = !existed, permissions = chmod ? Convert.ToString(mode!.Value, 8) : null };
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
public sealed class JobService(SshOperations ssh, ServerStore store)
{
    public object Start(string server, string command, int timeoutSeconds)
    {
        if (string.IsNullOrWhiteSpace(command)) throw new ArgumentException("命令不能为空。");
        if (timeoutSeconds is < 1 or > 86400) throw new ArgumentException("超时应在 1–86400 秒之间。");
        var stored = store.Get(server);
        var id = Guid.NewGuid().ToString("N");
        var result = ssh.Execute(stored.View.Id, BuildStartScript(id, command, timeoutSeconds), 30, "mcp-job", CancellationToken.None).GetAwaiter().GetResult();
        if (result.ExitCode != 0 || !result.Stdout.Contains("__SP_STARTED__", StringComparison.Ordinal))
            throw new InvalidOperationException("启动后台任务失败：" + (result.Stderr.Length > 0 ? result.Stderr : result.Stdout));
        return new { jobId = id, server = stored.View.Name, directory = "~/.serverpilot-jobs/" + id, status = "running",
            note = "任务状态与输出保存在远端 ~/.serverpilot-jobs，MCP 重启或断线后仍可查询。" };
    }

    public object Status(string server, string id, long? offset, int tailBytes = 8192, int maxBytes = 65536)
    {
        ValidateJobId(id);
        if (offset < 0) throw new ArgumentException("offset 不能为负数。");
        if (maxBytes is < 1 or > 256 * 1024) throw new ArgumentException("maxBytes 应在 1–262144 之间。");
        if (tailBytes is < 1 or > 256 * 1024) throw new ArgumentException("tailBytes 应在 1–262144 之间。");
        var script = "d=$HOME/.serverpilot-jobs/" + id + "; if [ ! -d \"$d\" ]; then echo '__SP_MISSING__'; else cat \"$d/meta\" 2>/dev/null; echo ''; echo '__SP_SEP__'; cat \"$d/exit\" 2>/dev/null; echo ''; echo '__SP_SEP__'; wc -c < \"$d/output\" 2>/dev/null || echo 0; echo '__SP_SEP__'; " + (offset.HasValue ? "dd if=\"$d/output\" bs=1 skip=" + offset.Value + " count=" + maxBytes + " 2>/dev/null" : "tail -c " + tailBytes + " \"$d/output\" 2>/dev/null") + " | base64; fi";
        var result = ssh.Execute(server, script, 60, "mcp-job", CancellationToken.None).GetAwaiter().GetResult();
        if (result.Stdout.Trim() == "__SP_MISSING__") throw new ArgumentException("任务不存在或已被清理。");
        var sections = result.Stdout.Split("__SP_SEP__", 4, StringSplitOptions.None);
        if (sections.Length < 4) throw new InvalidOperationException("无法读取任务状态。");
        var meta = ParseMeta(sections[0]);
        var exitCode = int.TryParse(sections[1].Trim(), out var code) ? code : (int?)null;
        var totalMatch = System.Text.RegularExpressions.Regex.Match(sections[2], @"\d+");
        var total = totalMatch.Success && long.TryParse(totalMatch.Value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var size) ? size : 0;
        var bytes = Convert.FromBase64String(sections[3]);
        var output = Encoding.UTF8.GetString(bytes);
        var readBytes = bytes.Length;
        if (total < readBytes) total = readBytes;
        var state = meta.GetValueOrDefault("state");
        var stateText = exitCode.HasValue ? "exited" : state == "running" ? "running" : "lost";
        var startOffset = offset ?? Math.Max(0, total - readBytes);
        var next = startOffset + readBytes;
        return new { jobId = id, server, status = stateText, exitCode, startedAt = meta.GetValueOrDefault("started"),
            command = meta.GetValueOrDefault("command"), output, offset = startOffset, totalBytes = total,
            nextOffset = next < total ? next : (long?)null };
    }

    public object Kill(string server, string id)
    {
        ValidateJobId(id);
        throw new InvalidOperationException("任务终止功能暂不可用，需先完成真实 Linux 主机验证。");
    }

    public object List(string server, int limit)
    {
        if (limit is < 1 or > 100) throw new ArgumentException("limit 应在 1–100 之间。");
        var script = "b=$HOME/.serverpilot-jobs; if [ ! -d \"$b\" ]; then echo '__SP_EMPTY__'; else for d in $(ls -1t \"$b\" 2>/dev/null | head -n " + limit + "); do p=\"$b/$d\"; test -d \"$p\" || continue; case \"$d\" in (*[!0-9a-f]*) continue;; esac; [ ${#d} -eq 32 ] || continue; st=$(sed -n 's/^state=//p' \"$p/meta\" 2>/dev/null | head -n 1); t=$(sed -n 's/^started=//p' \"$p/meta\" 2>/dev/null | head -n 1); c=$(sed -n 's/^command=//p' \"$p/meta\" 2>/dev/null | head -n 1 | tr '\\t' ' '); e=$(cat \"$p/exit\" 2>/dev/null); printf '%s\\t%s\\t%s\\t%s\\t%s\\n' \"$d\" \"$st\" \"$t\" \"$e\" \"$c\"; done; fi";
        var result = ssh.Execute(server, script, 60, "mcp-job", CancellationToken.None).GetAwaiter().GetResult();
        if (result.Stdout.Contains("__SP_EMPTY__")) return new { server, jobs = Array.Empty<object>() };
        var rows = new List<object>();
        foreach (var line in result.Stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            var parts = line.Split('\t');
            if (parts.Length < 5) continue;
            rows.Add(new { jobId = parts[0], state = string.IsNullOrWhiteSpace(parts[1]) ? "unknown" : parts[1],
                exitCode = int.TryParse(parts[3].Trim(), out var code) ? code : (int?)null, startedAt = parts[2], command = parts[4] });
        }
        return new { server, jobs = rows };
    }

    private static void ValidateJobId(string id)
    {
        if (id.Length != 32 || !id.All(char.IsAsciiHexDigit)) throw new ArgumentException("jobId 格式无效。");
    }

    private static Dictionary<string, string> ParseMeta(string text)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var line in text.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            var ix = line.IndexOf('=');
            if (ix > 0) result[line[..ix].Trim()] = line[(ix + 1)..].Trim();
        }
        return result;
    }

    private static string Quote(string value) => "'" + value.Replace("'", "'\\''") + "'";

    private static string BuildStartScript(string id, string command, int timeoutSeconds)
    {
        var path = "$HOME/.serverpilot-jobs/" + id;
        var jobScript = "#!/bin/sh\ncd \"$HOME/.serverpilot-jobs/" + id + "\" || exit 1\ntrap 'rc=$?; printf \"%s\" \"$rc\" > exit; sed -i s/^state=.*/state=exited/ meta 2>/dev/null || true' EXIT\n" +
            "timeout " + timeoutSeconds + " sh -c " + Quote(command) + " >> output 2>&1\n";
        var displayCommand = command.Replace("\r", " ").Replace("\n", " ").Replace("__SP_SEP__", "[separator]");
        return "set -e\numask 077\ncommand -v setsid >/dev/null && command -v timeout >/dev/null && command -v base64 >/dev/null || { echo '需要 setsid、timeout 和 base64'; exit 1; }\nd=\"" + path + "\"\nmkdir -p \"$HOME/.serverpilot-jobs\"\nmkdir \"$d\"\nprintf '%s' " + Quote(jobScript) + " > \"$d/job.sh\"\n" +
            "printf 'state=running\\nstarted=%s\\ncommand=%s\\n' \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\" " + Quote(displayCommand) + " > \"$d/meta\"\n" +
            ": > \"$d/output\"\n: > \"$d/exit\"\n" +
            "chmod 700 \"$d/job.sh\"\n" +
            "nohup setsid sh \"$d/job.sh\" </dev/null >/dev/null 2>&1 &\n" +
            "echo $! > \"$d/pid\"\n" +
            "echo '__SP_STARTED__'\n";
    }
}
