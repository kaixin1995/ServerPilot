using System.Collections.Concurrent;
using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using Renci.SshNet;
using Renci.SshNet.Common;
using Renci.SshNet.Sftp;

namespace ServerPilot;

public sealed record CommandResult(int? ExitCode, string? ExitSignal, string Stdout, string Stderr, bool OutputTruncated);
public sealed record TextReadResult(string Content, long Size, long Offset, long BytesRead, long? NextOffset, bool IsBinary);

public sealed class TerminalSession : IDisposable
{
    public SshClient Client { get; }
    public ShellStream Stream { get; }
    private readonly IDisposable? _tunnel;
    private int _disposed;

    internal TerminalSession(SshClient client, ShellStream stream, IDisposable? tunnel)
    {
        Client = client;
        Stream = stream;
        _tunnel = tunnel;
    }

    public void Resize(int cols, int rows)
    {
        var c = (uint)Math.Clamp(cols, 20, 400);
        var r = (uint)Math.Clamp(rows, 5, 200);
        try { Stream.ChangeWindowSize(c, r, 0, 0); } catch { }
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        try { Stream.Dispose(); } catch { }
        try { Client.Dispose(); } catch { }
        try { _tunnel?.Dispose(); } catch { }
    }
}

public sealed class SshOperations : IDisposable
{
    private const long MaxFileBytes = 512L * 1024 * 1024;
    private const int MaxOutputBytes = 512 * 1024;
    private const int MaxReadBytes = 1024 * 1024;
    private const int MaxIdlePerServer = 4;
    private static readonly TimeSpan IdleTimeout = TimeSpan.FromMinutes(3);

    private readonly ServerStore store;
    private readonly AppOptions options;
    private readonly NotificationService notifications;
    private readonly ILogger<SshOperations> logger;

    private readonly ConcurrentDictionary<string, ConcurrentStack<PooledItem<SshClient>>> _sshPool = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, ConcurrentStack<PooledItem<SftpClient>>> _sftpPool = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, ServerSnapshot> _snapshots = new(StringComparer.OrdinalIgnoreCase);
    private readonly Timer _evictionTimer;

    public SshOperations(ServerStore store, AppOptions options, NotificationService notifications, ILogger<SshOperations> logger)
    {
        this.store = store;
        this.options = options;
        this.notifications = notifications;
        this.logger = logger;
        foreach (var snap in store.LoadSnapshots())
            _snapshots[snap.ServerId] = snap;
        store.ServerChanged += InvalidateServerPool;
        _evictionTimer = new Timer(_ => EvictIdle(), null, TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(1));
    }

    private sealed class JumpTunnel : IDisposable
    {
        private readonly List<IDisposable> _resources = [];
        public string BoundHost { get; }
        public int BoundPort { get; }

        public JumpTunnel(string boundHost, int boundPort, List<IDisposable> resources)
        {
            BoundHost = boundHost;
            BoundPort = boundPort;
            _resources = resources;
        }

        public bool IsAlive => _resources.OfType<SshClient>().All(c => c.IsConnected)
            && _resources.OfType<ForwardedPortLocal>().All(p => p.IsStarted);

        public void Dispose()
        {
            for (var i = _resources.Count - 1; i >= 0; i--)
            {
                try
                {
                    if (_resources[i] is ForwardedPortLocal fp && fp.IsStarted) fp.Stop();
                }
                catch { }
                try { _resources[i].Dispose(); } catch { }
            }
        }
    }

    private sealed class PooledItem<T>(T client, JumpTunnel? tunnel) : IDisposable where T : BaseClient
    {
        public T Client { get; } = client;
        public JumpTunnel? Tunnel { get; } = tunnel;
        public DateTime LastUsedUtc { get; set; } = DateTime.UtcNow;
        public bool IsAlive => Client.IsConnected && (Tunnel?.IsAlive ?? true);
        public void Dispose()
        {
            try { Client.Dispose(); } catch { }
            try { Tunnel?.Dispose(); } catch { }
        }
    }

    private sealed class Lease<T>(SshOperations owner, ConcurrentDictionary<string, ConcurrentStack<PooledItem<T>>> pool, string key, PooledItem<T> item) : IDisposable where T : BaseClient
    {
        public T Client => item.Client;
        private bool _broken;
        private int _disposed;
        public void MarkBroken() => _broken = true;
        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
            if (_broken || !item.IsAlive) { item.Dispose(); return; }
            item.LastUsedUtc = DateTime.UtcNow;
            var stack = pool.GetOrAdd(key, _ => new ConcurrentStack<PooledItem<T>>());
            if (stack.Count >= MaxIdlePerServer) { item.Dispose(); return; }
            stack.Push(item);
            _ = owner;
        }
    }

    private void InvalidateServerPool(string serverId)
    {
        // Evict all keys referencing this server (or jump chains that might involve it)
        foreach (var k in _sshPool.Keys.ToList())
            if (_sshPool.TryRemove(k, out var st)) while (st.TryPop(out var item)) item.Dispose();
        foreach (var k in _sftpPool.Keys.ToList())
            if (_sftpPool.TryRemove(k, out var st)) while (st.TryPop(out var item)) item.Dispose();
        _snapshots.TryRemove(serverId, out _);
        store.DeleteSnapshot(serverId);
    }

    private void EvictIdle()
    {
        EvictPool(_sshPool);
        EvictPool(_sftpPool);
    }

    private static void EvictPool<T>(ConcurrentDictionary<string, ConcurrentStack<PooledItem<T>>> pool) where T : BaseClient
    {
        var cutoff = DateTime.UtcNow - IdleTimeout;
        foreach (var (key, stack) in pool)
        {
            var kept = new List<PooledItem<T>>();
            while (stack.TryPop(out var item))
            {
                if (item.LastUsedUtc < cutoff || !item.IsAlive) item.Dispose();
                else kept.Add(item);
            }
            for (var i = kept.Count - 1; i >= 0; i--) stack.Push(kept[i]);
            if (stack.IsEmpty) pool.TryRemove(key, out _);
        }
    }

    public void Dispose()
    {
        _evictionTimer.Dispose();
        store.ServerChanged -= InvalidateServerPool;
        foreach (var (_, stack) in _sshPool) while (stack.TryPop(out var item)) item.Dispose();
        foreach (var (_, stack) in _sftpPool) while (stack.TryPop(out var item)) item.Dispose();
    }

    private string PoolKey(StoredServer server)
    {
        var sb = new StringBuilder();
        sb.Append(server.View.Id).Append('|').Append(server.View.UpdatedAt);
        var cur = server;
        var depth = 0;
        while (!string.IsNullOrEmpty(cur.View.JumpServerId) && depth < 3)
        {
            var jump = store.Get(cur.View.JumpServerId);
            sb.Append("->").Append(jump.View.Id).Append('|').Append(jump.View.UpdatedAt);
            cur = jump;
            depth++;
        }
        return sb.ToString();
    }

    private static Renci.SshNet.ConnectionInfo Connection(StoredServer server, AppOptions options, string? overrideHost = null, int? overridePort = null)
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

        var targetHost = overrideHost ?? view.Host;
        var targetPort = overridePort ?? view.Port;
        var proxyUrl = overrideHost is not null ? null : (server.Credential.ProxyUrl ?? (string.IsNullOrWhiteSpace(view.Proxy) ? null : view.Proxy));

        Renci.SshNet.ConnectionInfo info;
        if (string.IsNullOrWhiteSpace(proxyUrl))
            info = new Renci.SshNet.ConnectionInfo(targetHost, targetPort, view.Username, methods.ToArray());
        else
        {
            ServerStore.ValidateProxy(proxyUrl);
            var uri = new Uri(proxyUrl);
            var type = uri.Scheme switch
            {
                "socks4" => ProxyTypes.Socks4,
                "socks5" => ProxyTypes.Socks5,
                _ => ProxyTypes.Http
            };
            var proxyUser = string.IsNullOrEmpty(uri.UserInfo) ? "" : Uri.UnescapeDataString(uri.UserInfo.Split(':', 2)[0]);
            var proxyPass = uri.UserInfo.Contains(':') ? Uri.UnescapeDataString(uri.UserInfo.Split(':', 2)[1]) : "";
            info = new Renci.SshNet.ConnectionInfo(targetHost, targetPort, view.Username, type, uri.Host, uri.Port, proxyUser, proxyPass, methods.ToArray());
        }
        info.Timeout = TimeSpan.FromSeconds(15);
        return info;
    }

    private static void Pin(BaseClient client, ServerView server) =>
        client.HostKeyReceived += (_, args) => args.CanTrust = Secrets.Equal("SHA256:" + args.FingerPrintSHA256, server.HostFingerprint);

    private JumpTunnel? BuildJumpTunnel(StoredServer target)
    {
        if (string.IsNullOrEmpty(target.View.JumpServerId)) return null;
        var chain = new List<StoredServer>();
        var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { target.View.Id };
        var jumpId = target.View.JumpServerId;
        while (!string.IsNullOrEmpty(jumpId))
        {
            if (chain.Count >= 3 || !visited.Add(jumpId))
                throw new InvalidOperationException("跳板机链路无效或存在循环。");
            var hop = store.Get(jumpId);
            chain.Add(hop);
            jumpId = hop.View.JumpServerId;
        }
        // chain[0] is closest to target, chain[^1] is outermost bastion
        chain.Reverse();
        var resources = new List<IDisposable>();
        try
        {
            string? nextHost = null;
            int? nextPort = null;
            for (var i = 0; i < chain.Count; i++)
            {
                var hop = chain[i];
                var hopClient = new SshClient(Connection(hop, options, nextHost, nextPort));
                hopClient.KeepAliveInterval = TimeSpan.FromSeconds(30);
                Pin(hopClient, hop.View);
                hopClient.Connect();
                resources.Add(hopClient);

                var destHost = i + 1 < chain.Count ? chain[i + 1].View.Host : target.View.Host;
                var destPort = (uint)(i + 1 < chain.Count ? chain[i + 1].View.Port : target.View.Port);
                var fwd = new ForwardedPortLocal("127.0.0.1", 0, destHost, destPort);
                hopClient.AddForwardedPort(fwd);
                fwd.Start();
                resources.Add(fwd);

                nextHost = "127.0.0.1";
                nextPort = (int)fwd.BoundPort;
            }
            return new JumpTunnel(nextHost!, nextPort!.Value, resources);
        }
        catch
        {
            for (var i = resources.Count - 1; i >= 0; i--)
            {
                try { if (resources[i] is ForwardedPortLocal fp && fp.IsStarted) fp.Stop(); } catch { }
                try { resources[i].Dispose(); } catch { }
            }
            throw;
        }
    }

    private PooledItem<SshClient> CreateSsh(StoredServer server)
    {
        var tunnel = BuildJumpTunnel(server);
        SshClient? client = null;
        try
        {
            client = new SshClient(Connection(server, options, tunnel?.BoundHost, tunnel?.BoundPort));
            client.KeepAliveInterval = TimeSpan.FromSeconds(30);
            Pin(client, server.View);
            client.Connect();
            return new PooledItem<SshClient>(client, tunnel);
        }
        catch
        {
            try { client?.Dispose(); } catch { }
            try { tunnel?.Dispose(); } catch { }
            throw;
        }
    }

    private PooledItem<SftpClient> CreateSftp(StoredServer server)
    {
        var tunnel = BuildJumpTunnel(server);
        SftpClient? client = null;
        try
        {
            client = new SftpClient(Connection(server, options, tunnel?.BoundHost, tunnel?.BoundPort))
            {
                OperationTimeout = TimeSpan.FromMinutes(3),
                KeepAliveInterval = TimeSpan.FromSeconds(30)
            };
            Pin(client, server.View);
            client.Connect();
            return new PooledItem<SftpClient>(client, tunnel);
        }
        catch
        {
            try { client?.Dispose(); } catch { }
            try { tunnel?.Dispose(); } catch { }
            throw;
        }
    }

    private Lease<SshClient> RentSsh(StoredServer server, out bool fromPool)
    {
        var key = PoolKey(server);
        if (_sshPool.TryGetValue(key, out var stack))
        {
            while (stack.TryPop(out var pooled))
            {
                if (pooled.IsAlive) { fromPool = true; return new Lease<SshClient>(this, _sshPool, key, pooled); }
                pooled.Dispose();
            }
        }
        fromPool = false;
        return new Lease<SshClient>(this, _sshPool, key, CreateSsh(server));
    }

    private Lease<SftpClient> RentSftp(StoredServer server, out bool fromPool)
    {
        var key = PoolKey(server);
        if (_sftpPool.TryGetValue(key, out var stack))
        {
            while (stack.TryPop(out var pooled))
            {
                if (pooled.IsAlive) { fromPool = true; return new Lease<SftpClient>(this, _sftpPool, key, pooled); }
                pooled.Dispose();
            }
        }
        fromPool = false;
        return new Lease<SftpClient>(this, _sftpPool, key, CreateSftp(server));
    }

    private async Task<T> WithSshAsync<T>(StoredServer server, Func<SshClient, Task<T>> action, CancellationToken ct)
    {
        for (var attempt = 0; attempt < 2; attempt++)
        {
            var lease = await Task.Run(() => RentSsh(server, out var pooled) is var l ? (l, pooled) : default, ct);
            using var handle = lease.l;
            try { return await action(handle.Client); }
            catch (Exception e) when (attempt == 0 && lease.pooled && e is SshConnectionException or ObjectDisposedException or IOException or System.Net.Sockets.SocketException)
            {
                handle.MarkBroken();
            }
            catch
            {
                handle.MarkBroken();
                throw;
            }
        }
        throw new InvalidOperationException("SSH 连接重试失败。");
    }

    private T WithSftp<T>(StoredServer server, Func<SftpClient, T> action)
    {
        for (var attempt = 0; attempt < 2; attempt++)
        {
            using var handle = RentSftp(server, out var fromPool);
            try { return action(handle.Client); }
            catch (Exception e) when (attempt == 0 && fromPool && e is SshConnectionException or ObjectDisposedException or IOException or System.Net.Sockets.SocketException)
            {
                handle.MarkBroken();
            }
            catch (Exception e)
            {
                if (e is SshConnectionException or ObjectDisposedException or IOException or System.Net.Sockets.SocketException)
                    handle.MarkBroken();
                throw;
            }
        }
        throw new InvalidOperationException("SFTP 连接重试失败。");
    }

    private async Task<T> Logged<T>(string serverId, string actor, string action, Func<StoredServer, Task<T>> perform, string? detail = null, Func<T, int?>? exitCodeSelector = null)
    {
        var server = store.Get(serverId);
        var sw = Stopwatch.StartNew();
        try
        {
            var result = await perform(server);
            sw.Stop();
            store.Audit(actor, server.View.Name, action, "success", detail, exitCodeSelector?.Invoke(result), sw.ElapsedMilliseconds);
            return result;
        }
        catch (Exception e)
        {
            sw.Stop();
            logger.LogWarning("SSH operation {Action} failed for {Server}; error type {ErrorType} ({Detail})", action, server.View.Name, e.GetType().Name, e is System.Net.Sockets.SocketException se ? se.SocketErrorCode.ToString() : e.HResult.ToString("X8"));
            store.Audit(actor, server.View.Name, action, "failed", detail, null, sw.ElapsedMilliseconds);
            throw;
        }
    }

    // --- Core SSH Ops ---
    public Task<ConnectionTestResult> Test(string id, string actor) => Logged(id, actor, "ssh.test", s => Task.Run(() =>
    {
        var sw = Stopwatch.StartNew();
        using var item = CreateSsh(s);
        sw.Stop();
        return new ConnectionTestResult(item.Client.IsConnected, s.View.Name, sw.ElapsedMilliseconds);
    }));

    public Task<ProbeResult> Probe(string host, int port)
    {
        if (string.IsNullOrWhiteSpace(host) || host.Length > 255 || host.Any(char.IsWhiteSpace) || host.Contains('/') || host.Contains('@') || port is < 1 or > 65535)
            throw new ArgumentException("服务器地址或端口无效。");
        return Task.Run(() =>
        {
            using var client = new SshClient(host, port, "serverpilot-probe", "unused");
            client.ConnectionInfo.Timeout = TimeSpan.FromSeconds(15);
            string? fingerprint = null, algorithm = null;
            client.HostKeyReceived += (_, e) => { fingerprint = "SHA256:" + e.FingerPrintSHA256; algorithm = e.HostKeyName; e.CanTrust = false; };
            try { client.Connect(); } catch when (fingerprint is not null) { /* Stop before authentication. */ }
            if (fingerprint is null) throw new InvalidOperationException("未能获取主机指纹，请检查地址和网络。");
            return new ProbeResult(fingerprint, algorithm ?? "", "此指纹来自当前网络连接，必须通过可信渠道独立核对。");
        });
    }

    public Task<CommandResult> Execute(string id, string command, int seconds, string actor, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(command) || command.Length > 32768) throw new ArgumentException("命令为空或过长。");
        if (seconds is < 1 or > 1800) throw new ArgumentException("超时应在 1–1800 秒之间。");
        return Logged(id, actor, "ssh.execute", s => ExecuteCoreAsync(s, command, seconds, ct), command, r => r.ExitCode);
    }

    internal Task<CommandResult> ExecuteInternalAsync(StoredServer server, string command, int seconds, CancellationToken ct) =>
        ExecuteCoreAsync(server, command, seconds, ct);

    private Task<CommandResult> ExecuteCoreAsync(StoredServer server, string command, int seconds, CancellationToken ct) =>
        WithSshAsync(server, async client =>
        {
            using var cmd = client.CreateCommand(command);
            cmd.CommandTimeout = TimeSpan.FromSeconds(seconds);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct);
            linked.CancelAfter(TimeSpan.FromSeconds(seconds));
            var running = cmd.ExecuteAsync(linked.Token);
            var stdout = ReadBounded(cmd.OutputStream, linked.Token);
            var stderr = ReadBounded(cmd.ExtendedOutputStream, linked.Token);
            await Task.WhenAll(running, stdout, stderr);
            return new CommandResult(cmd.ExitStatus, cmd.ExitSignal, stdout.Result.Text, stderr.Result.Text, stdout.Result.Truncated || stderr.Result.Truncated);
        }, ct);

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

    // --- WebSSH Interactive Terminal ---
    public TerminalSession OpenTerminal(string id, int cols, int rows, string actor)
    {
        var server = store.Get(id);
        var c = (uint)Math.Clamp(cols, 20, 400);
        var r = (uint)Math.Clamp(rows, 5, 200);
        var tunnel = BuildJumpTunnel(server);
        SshClient? client = null;
        try
        {
            client = new SshClient(Connection(server, options, tunnel?.BoundHost, tunnel?.BoundPort));
            client.KeepAliveInterval = TimeSpan.FromSeconds(25);
            Pin(client, server.View);
            client.Connect();
            var stream = client.CreateShellStream("xterm-256color", c, r, 0, 0, 65536);
            store.Audit(actor, server.View.Name, "ssh.terminal", "success");
            return new TerminalSession(client, stream, tunnel);
        }
        catch
        {
            try { client?.Dispose(); } catch { }
            try { tunnel?.Dispose(); } catch { }
            store.Audit(actor, server.View.Name, "ssh.terminal", "failed");
            throw;
        }
    }

    // --- Server Snapshot / Health Monitoring ---
    public List<ServerSnapshot> GetCachedSnapshots() => _snapshots.Values.OrderBy(s => s.ServerName, StringComparer.OrdinalIgnoreCase).ToList();

    public async Task<ServerSnapshot> GetSnapshot(string id, string actor, CancellationToken ct = default)
    {
        var server = store.Get(id);
        var sw = Stopwatch.StartNew();
        const string probeScript = """
            export LC_ALL=C
            echo "HOST=$(hostname 2>/dev/null || echo unknown)"
            echo "OS=$(. /etc/os-release 2>/dev/null && printf '%s' "${PRETTY_NAME:-$NAME}" || uname -s)"
            echo "KERNEL=$(uname -r 2>/dev/null)"
            echo "UPTIME=$(uptime -p 2>/dev/null || uptime 2>/dev/null | sed 's/.*up *//; s/, *[0-9]* user.*//')"
            echo "CORES=$(nproc 2>/dev/null || grep -c ^processor /proc/cpuinfo 2>/dev/null || echo 1)"
            echo "LOAD=$(cat /proc/loadavg 2>/dev/null | awk '{print $1" "$2" "$3}' || uptime 2>/dev/null | awk -F'load average:' '{print $2}' | xargs)"
            echo "CPU=$(awk '/^cpu /{u=$2+$4; t=$2+$4+$5; if(t>0) printf "%.1f", (u*100)/t}' /proc/stat 2>/dev/null || echo '')"
            echo "MEM=$(free -m 2>/dev/null | awk '/^Mem:/{print $2" "$3}' || echo '')"
            SWAP_VAL=$(free -m 2>/dev/null | awk '/^Swap:/{print $2" "$3}')
            if [ -z "$SWAP_VAL" ] && [ -r /proc/meminfo ]; then
              SWAP_VAL=$(awk '/^SwapTotal:/{t=int($2/1024); has=1} /^SwapFree:/{f=int($2/1024)} END{if(has) print t" "(t>f ? t-f : 0)}' /proc/meminfo 2>/dev/null)
            fi
            echo "SWAP=$SWAP_VAL"
            DISK_LINE=$(df -Pk / 2>/dev/null | awk 'NR==2{gsub(/%/,"",$5); print $2" "$3" "$5}')
            if [ -z "$DISK_LINE" ]; then
              DISK_LINE=$(df -k / 2>/dev/null | awk 'NR>1 && NF>=5 {gsub(/%/,"",$(NF-1)); print $(NF-4)" "$(NF-3)" "$(NF-1); exit}')
            fi
            echo "DISK_KB=$DISK_LINE"
            PORTS=$(ss -tlnH 2>/dev/null | awk '{print $4}' | sed 's/.*://' | sort -nu | tr '\n' ',' | sed 's/,$//' || true)
            echo "PORTS=$PORTS"
            if command -v docker >/dev/null 2>&1; then
              DR=$(docker ps -q 2>/dev/null | wc -l | tr -d ' ')
              DT=$(docker ps -aq 2>/dev/null | wc -l | tr -d ' ')
              echo "DOCKER=$DR/$DT"
            fi
            if command -v systemctl >/dev/null 2>&1; then
              FS=$(systemctl --failed --no-legend 2>/dev/null | wc -l | tr -d ' ')
              echo "FAILED_SVC=$FS"
            fi
            """;
        try
        {
            var canDirectTcp = string.IsNullOrWhiteSpace(server.View.Proxy) && string.IsNullOrWhiteSpace(server.View.JumpServerId);
            var rttTask = canDirectTcp ? MeasureTcpRttAsync(server.View.Host, server.View.Port, ct) : Task.FromResult<long?>(null);
            var res = await ExecuteCoreAsync(server, probeScript, 20, ct);
            sw.Stop();
            var rttMs = await rttTask;
            if (rttMs is null && !canDirectTcp)
            {
                try
                {
                    var pingSw = Stopwatch.StartNew();
                    await ExecuteCoreAsync(server, ":", 10, ct);
                    pingSw.Stop();
                    rttMs = Math.Max(1, pingSw.ElapsedMilliseconds);
                }
                catch { }
            }
            var latencyMs = rttMs ?? sw.ElapsedMilliseconds;
            var kv = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var line in res.Stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries))
            {
                var ix = line.IndexOf('=');
                if (ix > 0) kv[line[..ix].Trim()] = line[(ix + 1)..].Trim();
            }

            int? cores = int.TryParse(kv.GetValueOrDefault("CORES"), out var cVal) ? cVal : null;
            double? cpuPct = double.TryParse(kv.GetValueOrDefault("CPU"), CultureInfo.InvariantCulture, out var cpuVal) ? Math.Round(cpuVal, 1) : null;
            long? memTotal = null, memUsed = null; double? memPct = null;
            var memParts = (kv.GetValueOrDefault("MEM") ?? "").Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (memParts.Length >= 2 && long.TryParse(memParts[0], out var mt) && long.TryParse(memParts[1], out var mu) && mt > 0)
            {
                memTotal = mt; memUsed = mu; memPct = Math.Round(mu * 100.0 / mt, 1);
            }
            long? swapTotal = null, swapUsed = null; double? swapPct = null;
            var swapParts = (kv.GetValueOrDefault("SWAP") ?? "").Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (swapParts.Length >= 2 && long.TryParse(swapParts[0], out var st) && long.TryParse(swapParts[1], out var su) && st >= 0)
            {
                swapTotal = st; swapUsed = Math.Max(0, su);
                swapPct = st > 0 ? Math.Round(swapUsed.Value * 100.0 / st, 1) : null;
            }
            else if (memTotal.HasValue)
            {
                swapTotal = 0; swapUsed = 0;
            }
            long? diskTotal = null, diskUsed = null, diskTotalMb = null, diskUsedMb = null; double? diskPct = null;
            var diskKbParts = (kv.GetValueOrDefault("DISK_KB") ?? "").Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (diskKbParts.Length >= 3 && long.TryParse(diskKbParts[0], out var dtKb) && long.TryParse(diskKbParts[1], out var duKb) && double.TryParse(diskKbParts[2], CultureInfo.InvariantCulture, out var dpKb))
            {
                diskTotalMb = dtKb / 1024;
                diskUsedMb = duKb / 1024;
                diskTotal = (long)Math.Round(dtKb / 1048576.0);
                diskUsed = (long)Math.Round(duKb / 1048576.0);
                diskPct = dtKb > 0 ? Math.Round(duKb * 100.0 / dtKb, 1) : Math.Round(dpKb, 1);
            }
            else
            {
                var diskParts = (kv.GetValueOrDefault("DISK") ?? "").Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (diskParts.Length >= 3 && long.TryParse(diskParts[0], out var dt) && long.TryParse(diskParts[1], out var du) && double.TryParse(diskParts[2], CultureInfo.InvariantCulture, out var dp))
                {
                    diskTotal = dt; diskUsed = du; diskPct = Math.Round(dp, 1);
                    diskTotalMb = dt * 1024; diskUsedMb = du * 1024;
                }
            }
            var portsStr = kv.GetValueOrDefault("PORTS") ?? "";
            var portsList = portsStr.Split(',', StringSplitOptions.RemoveEmptyEntries);
            int? dockerRun = null, dockerTot = null;
            if (kv.TryGetValue("DOCKER", out var dStr) && dStr.Contains('/'))
            {
                var dp2 = dStr.Split('/');
                if (int.TryParse(dp2[0], out var dr) && int.TryParse(dp2[1], out var dtt)) { dockerRun = dr; dockerTot = dtt; }
            }
            int? failedSvc = int.TryParse(kv.GetValueOrDefault("FAILED_SVC"), out var fs) ? fs : null;

            var snap = new ServerSnapshot(
                server.View.Id, server.View.Name, true, latencyMs, DateTimeOffset.UtcNow.ToString("O"),
                kv.GetValueOrDefault("HOST"), kv.GetValueOrDefault("OS"), kv.GetValueOrDefault("KERNEL"), kv.GetValueOrDefault("UPTIME"),
                cores, cpuPct, memTotal, memUsed, memPct, diskTotal, diskUsed, diskPct,
                kv.GetValueOrDefault("LOAD"), portsList.Length, portsList.Length > 0 ? string.Join(", ", portsList.Take(20)) : "",
                dockerRun, dockerTot, failedSvc, null, diskTotalMb, diskUsedMb, swapTotal, swapUsed, swapPct);

            _snapshots[server.View.Id] = snap;
            store.SaveSnapshot(snap);

            if ((diskPct.HasValue && diskPct.Value >= 90) || (memPct.HasValue && memPct.Value >= 90))
                notifications.Fire("alert", $"服务器资源告警：{server.View.Name}", $"内存：{memPct?.ToString("0.0") ?? "-"}%，磁盘：{diskPct?.ToString("0.0") ?? "-"}%");
            return snap;
        }
        catch (Exception e)
        {
            sw.Stop();
            var snap = new ServerSnapshot(
                server.View.Id, server.View.Name, false, sw.ElapsedMilliseconds, DateTimeOffset.UtcNow.ToString("O"),
                null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, Errors.Public(e));
            _snapshots[server.View.Id] = snap;
            store.SaveSnapshot(snap);
            notifications.Fire("alert", $"服务器离线告警：{server.View.Name}", $"主机 {server.View.Host}:{server.View.Port} 连接失败：{Errors.Public(e)}");
            return snap;
        }
    }

    public async Task<List<ServerSnapshot>> RefreshAllSnapshots(string actor, CancellationToken ct = default)
    {
        var servers = store.List();
        using var sem = new SemaphoreSlim(6);
        var tasks = servers.Select(async s =>
        {
            await sem.WaitAsync(ct);
            try { return await GetSnapshot(s.Id, actor, ct); }
            finally { sem.Release(); }
        });
        return (await Task.WhenAll(tasks)).OrderBy(s => s.ServerName, StringComparer.OrdinalIgnoreCase).ToList();
    }

    private static async Task<long?> MeasureTcpRttAsync(string host, int port, CancellationToken ct)
    {
        try
        {
            IPAddress addr;
            if (!IPAddress.TryParse(host, out addr!))
            {
                var addrs = await Dns.GetHostAddressesAsync(host, ct);
                if (addrs.Length == 0) return null;
                addr = addrs.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork) ?? addrs[0];
            }
            using var socket = new Socket(addr.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeoutCts.CancelAfter(TimeSpan.FromSeconds(5));
            var sw = Stopwatch.StartNew();
            await socket.ConnectAsync(new IPEndPoint(addr, port), timeoutCts.Token);
            sw.Stop();
            return Math.Max(1, sw.ElapsedMilliseconds);
        }
        catch
        {
            return null;
        }
    }

    // --- Batch Execute ---
    public async Task<BatchExecuteResult> BatchExecute(List<ServerView> targets, string command, int timeoutSeconds, string actor, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(command) || command.Length > 32768) throw new ArgumentException("命令为空或过长。");
        if (timeoutSeconds is < 1 or > 1800) throw new ArgumentException("超时应在 1–1800 秒之间。");
        if (targets.Count == 0) throw new ArgumentException("未匹配到任何目标服务器。");

        using var sem = new SemaphoreSlim(6);
        var tasks = targets.Select(async srv =>
        {
            await sem.WaitAsync(ct);
            var sw = Stopwatch.StartNew();
            try
            {
                var r = await Execute(srv.Id, command, timeoutSeconds, actor, ct);
                sw.Stop();
                return new BatchItemResult(srv.Id, srv.Name, r.ExitCode == 0, r.ExitCode, r.ExitSignal, r.Stdout, r.Stderr, r.OutputTruncated, sw.ElapsedMilliseconds, null);
            }
            catch (Exception e)
            {
                sw.Stop();
                return new BatchItemResult(srv.Id, srv.Name, false, null, null, "", "", false, sw.ElapsedMilliseconds, Errors.Public(e));
            }
            finally { sem.Release(); }
        });
        var results = (await Task.WhenAll(tasks)).ToList();
        var succeeded = results.Count(r => r.Success);
        return new BatchExecuteResult(command, results.Count, succeeded, results.Count - succeeded, results);
    }

    // --- Deploy Public Key to Remote ~/.ssh/authorized_keys ---
    public async Task<DeployKeyResult> DeploySharedKey(string keyId, List<string>? serverIds, bool bindAfterDeploy, string actor, CancellationToken ct)
    {
        var key = store.GetSharedKeySummary(keyId);
        if (string.IsNullOrWhiteSpace(key.PublicKey))
            throw new InvalidOperationException("该密钥缺少可用公钥。");
        var idSet = (serverIds ?? []).Where(x => !string.IsNullOrWhiteSpace(x)).ToHashSet(StringComparer.OrdinalIgnoreCase);
        if (idSet.Count == 0) throw new ArgumentException("请至少选择一台目标服务器。");
        var targets = store.List().Where(s => idSet.Contains(s.Id) || idSet.Contains(s.Name)).ToList();
        if (targets.Count == 0) throw new ArgumentException("未找到指定的目标服务器。");

        var parts = key.PublicKey.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        var matchToken = parts.Length >= 2 ? parts[0] + " " + parts[1] : key.PublicKey;
        var pubB64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(key.PublicKey));
        var tokB64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(matchToken));
        var script = $$"""
            set -e
            mkdir -p "$HOME/.ssh"
            chmod 700 "$HOME/.ssh"
            auth="$HOME/.ssh/authorized_keys"
            touch "$auth"
            chmod 600 "$auth"
            pub=$(printf '%s' '{{pubB64}}' | base64 -d)
            tok=$(printf '%s' '{{tokB64}}' | base64 -d)
            if grep -Fq "$tok" "$auth" 2>/dev/null; then
              echo '__SP_EXISTS__'
            else
              if [ -s "$auth" ] && [ -n "$(tail -c 1 "$auth" 2>/dev/null)" ]; then printf '\n' >> "$auth"; fi
              printf '%s\n' "$pub" >> "$auth"
              echo '__SP_ADDED__'
            fi
            """;

        using var sem = new SemaphoreSlim(6);
        var tasks = targets.Select(async srv =>
        {
            await sem.WaitAsync(ct);
            try
            {
                var r = await Logged(srv.Id, actor, "key.deploy", s => ExecuteCoreAsync(s, script, 30, ct), key.Name, x => x.ExitCode);
                if (r.ExitCode != 0)
                    return new DeployKeyItemResult(srv.Id, srv.Name, false, false, false, string.IsNullOrWhiteSpace(r.Stderr) ? $"退出码 {r.ExitCode}" : r.Stderr.Trim());
                var already = r.Stdout.Contains("__SP_EXISTS__", StringComparison.Ordinal);
                var bound = false;
                if (bindAfterDeploy)
                {
                    store.BindServerToSharedKey(srv.Id, key.Id);
                    bound = true;
                }
                var msg = already ? "公钥已存在" : "公钥已写入 ~/.ssh/authorized_keys";
                if (bound) msg += "，并已自动绑定此密钥";
                return new DeployKeyItemResult(srv.Id, srv.Name, true, already, bound, msg);
            }
            catch (Exception e)
            {
                return new DeployKeyItemResult(srv.Id, srv.Name, false, false, false, Errors.Public(e));
            }
            finally { sem.Release(); }
        });
        var items = (await Task.WhenAll(tasks)).ToList();
        var ok = items.Count(x => x.Success);
        return new DeployKeyResult(key.Id, key.Name, items.Count, ok, items.Count - ok, items);
    }

    // --- Staging & Path Validation ---
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

    private static void AllowedRemotePath(SftpClient client, ServerView server, string path, bool isDirectoryCheck = false)
    {
        RemotePath(path);
        var roots = server.AllowedRemotePaths.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (roots.Length == 0) return;
        var normalized = NormalizeRemote(path);
        string resolved;
        if (isDirectoryCheck && normalized == "/")
        {
            resolved = "/";
        }
        else if (isDirectoryCheck && client.Exists(normalized))
        {
            if (client.GetAttributes(normalized).IsSymbolicLink)
                throw new ArgumentException("配置了路径限制时不支持操作符号链接。");
            client.ChangeDirectory(normalized);
            resolved = client.WorkingDirectory.TrimEnd('/');
            if (resolved.Length == 0) resolved = "/";
        }
        else
        {
            var parent = normalized[..normalized.LastIndexOf('/')];
            if (parent.Length == 0) parent = "/";
            client.ChangeDirectory(parent);
            var resolvedParent = client.WorkingDirectory.TrimEnd('/');
            resolved = resolvedParent + normalized[normalized.LastIndexOf('/')..];
            if (client.Exists(normalized) && client.GetAttributes(normalized).IsSymbolicLink)
                throw new ArgumentException("配置了路径限制时不支持操作符号链接。");
        }
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

    public List<StagedFileInfo> ListStaging() => Directory.EnumerateFiles(options.StagingDirectory).Select(p => new FileInfo(p)).Where(f => !f.Attributes.HasFlag(FileAttributes.ReparsePoint)).OrderBy(f => f.Name).Select(f => new StagedFileInfo(f.Name, f.Length, f.LastWriteTimeUtc)).ToList();

    public async Task<StagedFileResult> StageFile(string name, Stream input, long length, CancellationToken ct)
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
            store.Audit("web", "-", "staging.upload", "success", name); return new(name, output.Length);
        }
        catch { if (created && File.Exists(path)) File.Delete(path); throw; }
    }

    public Stream OpenStaged(string name)
    {
        var p = StagingPath(name); if (!File.Exists(p)) throw new FileNotFoundException("文件不存在。");
        if (File.GetAttributes(p).HasFlag(FileAttributes.ReparsePoint)) throw new ArgumentException("不支持符号链接。");
        return new FileStream(p, FileMode.Open, FileAccess.Read, FileShare.Read);
    }

    public void DeleteStaged(string name) { var path = StagingPath(name); if (!File.Exists(path)) throw new FileNotFoundException("文件不存在。"); File.Delete(path); store.Audit("web", "-", "staging.delete", "success", name); }

    // --- SFTP File Browser Operations ---
    public Task<DirectoryListResult> ListDirectory(string id, string remotePath, string actor)
    {
        var path = string.IsNullOrWhiteSpace(remotePath) ? "/" : remotePath.Trim();
        RemotePath(path);
        var normalized = NormalizeRemote(path);
        return Logged(id, actor, "sftp.list_dir", s => Task.Run(() => WithSftp(s, sftp =>
        {
            AllowedRemotePath(sftp, s.View, normalized, isDirectoryCheck: true);
            var entries = new List<RemoteFileEntry>();
            foreach (var f in sftp.ListDirectory(normalized))
            {
                if (f.Name is "." or "..") continue;
                var full = normalized == "/" ? "/" + f.Name : normalized + "/" + f.Name;
                var perms = FormatPermissions(f.Attributes);
                entries.Add(new RemoteFileEntry(f.Name, full, f.IsDirectory, f.IsSymbolicLink, f.Length, perms, f.LastWriteTimeUtc.ToString("O")));
            }
            entries.Sort((a, b) =>
            {
                var dirCmp = b.IsDirectory.CompareTo(a.IsDirectory);
                return dirCmp != 0 ? dirCmp : StringComparer.OrdinalIgnoreCase.Compare(a.Name, b.Name);
            });
            string? parent = normalized == "/" ? null : normalized[..normalized.LastIndexOf('/')];
            if (parent == "") parent = "/";
            return new DirectoryListResult(normalized, parent, entries);
        })), normalized);
    }

    private static string FormatPermissions(SftpFileAttributes a)
    {
        var sb = new StringBuilder(9);
        sb.Append(a.OwnerCanRead ? 'r' : '-').Append(a.OwnerCanWrite ? 'w' : '-').Append(a.OwnerCanExecute ? 'x' : '-');
        sb.Append(a.GroupCanRead ? 'r' : '-').Append(a.GroupCanWrite ? 'w' : '-').Append(a.GroupCanExecute ? 'x' : '-');
        sb.Append(a.OthersCanRead ? 'r' : '-').Append(a.OthersCanWrite ? 'w' : '-').Append(a.OthersCanExecute ? 'x' : '-');
        return sb.ToString();
    }

    public Task<OkResponse> CreateDirectory(string id, string remotePath, string actor)
    {
        RemotePath(remotePath);
        var normalized = NormalizeRemote(remotePath);
        return Logged(id, actor, "sftp.mkdir", s => Task.Run(() => WithSftp(s, sftp =>
        {
            AllowedRemotePath(sftp, s.View, normalized);
            sftp.CreateDirectory(normalized);
            return new OkResponse(true);
        })), normalized);
    }

    public Task<OkResponse> RenameRemote(string id, string oldPath, string newPath, string actor)
    {
        RemotePath(oldPath); RemotePath(newPath);
        var oldNorm = NormalizeRemote(oldPath); var newNorm = NormalizeRemote(newPath);
        if (oldNorm == "/" || newNorm == "/") throw new ArgumentException("不能重命名根目录。");
        return Logged(id, actor, "sftp.rename", s => Task.Run(() => WithSftp(s, sftp =>
        {
            AllowedRemotePath(sftp, s.View, oldNorm);
            AllowedRemotePath(sftp, s.View, newNorm);
            sftp.RenameFile(oldNorm, newNorm);
            return new OkResponse(true);
        })), $"{oldNorm} -> {newNorm}");
    }

    public Task<OkResponse> DeleteRemote(string id, string remotePath, string actor)
    {
        RemotePath(remotePath);
        var normalized = NormalizeRemote(remotePath);
        if (normalized == "/") throw new ArgumentException("不能删除根目录。");
        return Logged(id, actor, "sftp.delete", s => Task.Run(() => WithSftp(s, sftp =>
        {
            AllowedRemotePath(sftp, s.View, normalized);
            var attr = sftp.GetAttributes(normalized);
            if (attr.IsDirectory) sftp.DeleteDirectory(normalized);
            else sftp.DeleteFile(normalized);
            return new OkResponse(true);
        })), normalized);
    }

    public Task<UploadResult> DirectUpload(string id, string remotePath, Stream input, long length, bool overwrite, string actor)
    {
        RemotePath(remotePath);
        if (length < 0 || length > MaxFileBytes) throw new ArgumentException("文件不能超过 512 MiB。");
        var normalized = NormalizeRemote(remotePath);
        var fileName = normalized[(normalized.LastIndexOf('/') + 1)..];
        return Logged(id, actor, "sftp.direct_upload", s => Task.Run(() => WithSftp(s, sftp =>
        {
            AllowedRemotePath(sftp, s.View, normalized);
            if (!overwrite && sftp.Exists(normalized)) throw new ArgumentException("远程文件已存在；请勾选覆盖或更改文件名。");
            sftp.UploadFile(input, normalized, overwrite);
            return new UploadResult(true, fileName, normalized, length);
        })), normalized);
    }

    public (Stream Stream, string FileName) DirectDownload(string id, string remotePath, string actor)
    {
        RemotePath(remotePath);
        var normalized = NormalizeRemote(remotePath);
        var server = store.Get(id);
        var item = CreateSftp(server);
        try
        {
            AllowedRemotePath(item.Client, server.View, normalized);
            var attr = item.Client.GetAttributes(normalized);
            if (!attr.IsRegularFile || attr.Size > MaxFileBytes) throw new ArgumentException("仅支持下载不超过 512 MiB 的普通文件。");
            var sftpStream = item.Client.OpenRead(normalized);
            store.Audit(actor, server.View.Name, "sftp.direct_download", "success", normalized);
            var fileName = normalized[(normalized.LastIndexOf('/') + 1)..];
            return (new OwnedReadStream(sftpStream, item), fileName);
        }
        catch
        {
            item.Dispose();
            store.Audit(actor, server.View.Name, "sftp.direct_download", "failed", normalized);
            throw;
        }
    }

    private sealed class OwnedReadStream(Stream inner, IDisposable owner) : Stream
    {
        public override bool CanRead => inner.CanRead;
        public override bool CanSeek => inner.CanSeek;
        public override bool CanWrite => false;
        public override long Length => inner.Length;
        public override long Position { get => inner.Position; set => inner.Position = value; }
        public override void Flush() => inner.Flush();
        public override int Read(byte[] buffer, int offset, int count) => inner.Read(buffer, offset, count);
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default) => inner.ReadAsync(buffer, ct);
        public override long Seek(long offset, SeekOrigin origin) => inner.Seek(offset, origin);
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        protected override void Dispose(bool disposing)
        {
            if (disposing) { try { inner.Dispose(); } catch { } try { owner.Dispose(); } catch { } }
            base.Dispose(disposing);
        }
    }

    // --- Staging <-> Remote SFTP ---
    public Task<UploadResult> Upload(string id, string stagingFile, string remotePath, string actor, bool overwrite = false)
    {
        RemotePath(remotePath);
        return Logged(id, actor, "sftp.upload", s => Task.Run(() => WithSftp(s, sftp =>
        {
            using var input = OpenStaged(stagingFile); if (input.Length > MaxFileBytes) throw new ArgumentException("文件不能超过 512 MiB。");
            AllowedRemotePath(sftp, s.View, remotePath); if (!overwrite && sftp.Exists(remotePath)) throw new ArgumentException("远程文件已存在；如需覆盖，请明确指定。");
            sftp.UploadFile(input, remotePath, overwrite); return new UploadResult(true, stagingFile, remotePath, input.Length);
        })), $"{stagingFile} -> {remotePath}");
    }

    public Task<DownloadResult> Download(string id, string remotePath, string stagingFile, string actor)
    {
        RemotePath(remotePath); var local = StagingPath(stagingFile);
        return Logged(id, actor, "sftp.download", s => Task.Run(() => WithSftp(s, sftp =>
        {
            AllowedRemotePath(sftp, s.View, remotePath); var attr = sftp.GetAttributes(remotePath);
            if (!attr.IsRegularFile || attr.Size > MaxFileBytes) throw new ArgumentException("仅支持下载不超过 512 MiB 的普通文件。");
            if (File.Exists(local)) throw new ArgumentException("暂存区文件已存在，请换一个名称。");
            var created = false;
            try
            {
                using var output = new FileStream(local, FileMode.CreateNew, FileAccess.Write, FileShare.None);
                created = true;
                if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(local, UnixFileMode.UserRead | UnixFileMode.UserWrite);
                using var limited = new LimitedWriteStream(output, MaxFileBytes); sftp.DownloadFile(remotePath, limited);
                return new DownloadResult(true, stagingFile, remotePath, output.Length);
            }
            catch { if (created && File.Exists(local)) File.Delete(local); throw; }
        })), $"{remotePath} -> {stagingFile}");
    }

    // --- Text File Read / Write / Patch ---
    public Task<TextReadResult> ReadFile(string id, string remotePath, long offset, int length, string actor)
    {
        RemotePath(remotePath);
        if (offset < 0) throw new ArgumentException("offset 不能为负数。");
        if (length is < 1 or > MaxReadBytes) throw new ArgumentException($"length 应在 1–{MaxReadBytes} 字节之间。");
        return Logged(id, actor, "sftp.read_file", s => Task.Run(() => WithSftp(s, sftp =>
        {
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
        })), remotePath);
    }

    public Task<WriteFileResult> WriteFile(string id, string remotePath, string content, bool append, int? mode, string actor)
    {
        RemotePath(remotePath);
        if (Encoding.UTF8.GetByteCount(content) > 2 * 1024 * 1024) throw new ArgumentException("单次写入内容不能超过 2 MiB。");
        if (mode is < 0 or > 0x1FF) throw new ArgumentException("权限位应在 0–0777 之间。");
        return Logged(id, actor, "sftp.write_file", s => Task.Run(() => WithSftp(s, sftp =>
        {
            AllowedRemotePath(sftp, s.View, remotePath);
            var existed = sftp.Exists(remotePath);
            var bytes = Encoding.UTF8.GetBytes(content);
            using (var stream = sftp.Open(remotePath, append ? FileMode.Append : FileMode.Create, FileAccess.Write))
                stream.Write(bytes, 0, bytes.Length);
            var chmod = mode.HasValue && !existed;
            if (chmod) sftp.ChangePermissions(remotePath, (short)mode!.Value);
            return new WriteFileResult(true, remotePath, bytes.Length, append, !existed, chmod ? Convert.ToString(mode!.Value, 8) : null);
        })), remotePath);
    }

    public Task<PatchFileResult> PatchFile(string id, string remotePath, string oldText, string newText, bool replaceAll, string actor)
    {
        RemotePath(remotePath);
        if (string.IsNullOrEmpty(oldText)) throw new ArgumentException("oldText 不能为空。");
        return Logged(id, actor, "sftp.patch_file", s => Task.Run(() => WithSftp(s, sftp =>
        {
            AllowedRemotePath(sftp, s.View, remotePath);
            var attr = sftp.GetAttributes(remotePath);
            if (!attr.IsRegularFile) throw new ArgumentException("仅支持修改普通文本文件。");
            if (attr.Size > 2 * 1024 * 1024) throw new ArgumentException("patch_file 仅支持不超过 2 MiB 的文本文件。");
            byte[] raw;
            using (var ms = new MemoryStream())
            {
                using var rs = sftp.OpenRead(remotePath);
                rs.CopyTo(ms);
                raw = ms.ToArray();
            }
            if (raw.Any(b => b == 0)) throw new ArgumentException("检测到二进制文件，拒绝文本替换。");
            var content = Encoding.UTF8.GetString(raw);
            var count = 0;
            var pos = 0;
            while ((pos = content.IndexOf(oldText, pos, StringComparison.Ordinal)) >= 0) { count++; pos += oldText.Length; }
            if (count == 0) throw new ArgumentException("在目标文件中未找到指定的 oldText。");
            if (!replaceAll && count > 1) throw new ArgumentException($"找到 {count} 处匹配，请提供更多上下文使其唯一，或设置 replaceAll=true。");
            string updated;
            if (replaceAll)
            {
                updated = content.Replace(oldText, newText, StringComparison.Ordinal);
            }
            else
            {
                var ix = content.IndexOf(oldText, StringComparison.Ordinal);
                updated = string.Concat(content.AsSpan(0, ix), newText, content.AsSpan(ix + oldText.Length));
            }
            var outBytes = Encoding.UTF8.GetBytes(updated);
            if (outBytes.Length > 2 * 1024 * 1024) throw new ArgumentException("修改后的文件超过 2 MiB 限制。");
            using (var ws = sftp.Open(remotePath, FileMode.Create, FileAccess.Write))
                ws.Write(outBytes, 0, outBytes.Length);
            return new PatchFileResult(true, remotePath, replaceAll ? count : 1, outBytes.Length);
        })), remotePath);
    }

    private sealed class LimitedWriteStream(Stream inner, long max) : Stream
    {
        private long count;
        public override void Write(byte[] buffer, int offset, int count) { if (this.count + count > max) throw new IOException("File exceeds limit."); inner.Write(buffer, offset, count); this.count += count; }
        public override bool CanRead => false; public override bool CanSeek => false; public override bool CanWrite => true;
        public override long Length => count; public override long Position { get => count; set => throw new NotSupportedException(); }
        public override void Flush() => inner.Flush(); public override int Read(byte[] b, int o, int c) => throw new NotSupportedException();
        public override long Seek(long o, SeekOrigin s) => throw new NotSupportedException(); public override void SetLength(long v) => throw new NotSupportedException();
    }
}

public sealed class JobService(SshOperations ssh, ServerStore store, NotificationService notifications)
{
    public JobStartResult Start(string server, string command, int timeoutSeconds, string actor = "job")
    {
        if (string.IsNullOrWhiteSpace(command)) throw new ArgumentException("命令不能为空。");
        if (timeoutSeconds is < 1 or > 86400) throw new ArgumentException("超时应在 1–86400 秒之间。");
        var stored = store.Get(server);
        var id = Guid.NewGuid().ToString("N");
        var result = ssh.Execute(stored.View.Id, BuildStartScript(id, command, timeoutSeconds), 30, actor, CancellationToken.None).GetAwaiter().GetResult();
        if (result.ExitCode != 0 || !result.Stdout.Contains("__SP_STARTED__", StringComparison.Ordinal))
            throw new InvalidOperationException("启动后台任务失败：" + (result.Stderr.Length > 0 ? result.Stderr : result.Stdout));
        notifications.Fire("job", $"后台任务已启动：{stored.View.Name}", $"jobId={id}\n命令：{ServerStore.RedactDetail(command)}");
        return new(id, stored.View.Name, "~/.serverpilot-jobs/" + id, "running",
            "任务状态与输出保存在远端 ~/.serverpilot-jobs，服务重启或断线后仍可查询。");
    }

    public JobStatusResult Status(string server, string id, long? offset, int tailBytes = 8192, int maxBytes = 65536, string actor = "job")
    {
        ValidateJobId(id);
        if (offset < 0) throw new ArgumentException("offset 不能为负数。");
        if (maxBytes is < 1 or > 256 * 1024) throw new ArgumentException("maxBytes 应在 1–262144 之间。");
        if (tailBytes is < 1 or > 256 * 1024) throw new ArgumentException("tailBytes 应在 1–262144 之间。");
        var script = "d=$HOME/.serverpilot-jobs/" + id + "; if [ ! -d \"$d\" ]; then echo '__SP_MISSING__'; else cat \"$d/meta\" 2>/dev/null; echo ''; echo '__SP_SEP__'; cat \"$d/exit\" 2>/dev/null; echo ''; echo '__SP_SEP__'; wc -c < \"$d/output\" 2>/dev/null || echo 0; echo '__SP_SEP__'; " + (offset.HasValue ? "dd if=\"$d/output\" bs=1 skip=" + offset.Value + " count=" + maxBytes + " 2>/dev/null" : "tail -c " + tailBytes + " \"$d/output\" 2>/dev/null") + " | base64; fi";
        var result = ssh.Execute(server, script, 60, actor, CancellationToken.None).GetAwaiter().GetResult();
        if (result.Stdout.Trim() == "__SP_MISSING__") throw new ArgumentException("任务不存在或已被清理。");
        var sections = result.Stdout.Split("__SP_SEP__", 4, StringSplitOptions.None);
        if (sections.Length < 4) throw new InvalidOperationException("无法读取任务状态。");
        var meta = ParseMeta(sections[0]);
        var exitCode = int.TryParse(sections[1].Trim(), out var code) ? code : (int?)null;
        var totalMatch = Regex.Match(sections[2], @"\d+");
        var total = totalMatch.Success && long.TryParse(totalMatch.Value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var size) ? size : 0;
        var bytes = Convert.FromBase64String(sections[3]);
        var output = Encoding.UTF8.GetString(bytes);
        var readBytes = bytes.Length;
        if (total < readBytes) total = readBytes;
        var state = meta.GetValueOrDefault("state");
        var stateText = state == "killed" ? "killed" : exitCode.HasValue ? "exited" : state == "running" ? "running" : "lost";
        var startOffset = offset ?? Math.Max(0, total - readBytes);
        var next = startOffset + readBytes;
        return new(id, server, stateText, exitCode, meta.GetValueOrDefault("started"),
            meta.GetValueOrDefault("command"), output, startOffset, total,
            next < total ? next : null);
    }

    public JobKillResult Kill(string server, string id, string actor = "job")
    {
        ValidateJobId(id);
        var stored = store.Get(server);
        var script = $$"""
            d="$HOME/.serverpilot-jobs/{{id}}"
            if [ ! -d "$d" ]; then echo '__SP_MISSING__'; exit 0; fi
            ex=$(cat "$d/exit" 2>/dev/null | tr -d '[:space:]')
            if [ -n "$ex" ]; then echo '__SP_EXITED__'; exit 0; fi
            pid=$(cat "$d/pid" 2>/dev/null | tr -d '[:space:]')
            if [ -z "$pid" ]; then echo '__SP_NOPID__'; exit 0; fi
            if ! kill -0 "$pid" 2>/dev/null; then
              sed -i 's/^state=.*/state=exited/' "$d/meta" 2>/dev/null || true
              echo '__SP_EXITED__'
              exit 0
            fi
            saved_st=$(cat "$d/starttime" 2>/dev/null | tr -d '[:space:]')
            if [ -n "$saved_st" ] && [ -r "/proc/$pid/stat" ]; then
              cur_st=$(awk '{print $22}' "/proc/$pid/stat" 2>/dev/null)
              if [ -n "$cur_st" ] && [ "$cur_st" != "$saved_st" ]; then
                echo '__SP_PID_REUSED__'
                exit 0
              fi
            fi
            kill -TERM -"$pid" 2>/dev/null || kill -TERM "$pid" 2>/dev/null || true
            sleep 1
            if kill -0 "$pid" 2>/dev/null; then
              kill -KILL -"$pid" 2>/dev/null || kill -KILL "$pid" 2>/dev/null || true
            fi
            [ -s "$d/exit" ] || printf '143' > "$d/exit"
            sed -i 's/^state=.*/state=killed/' "$d/meta" 2>/dev/null || true
            echo '__SP_KILLED__'
            """;
        var res = ssh.Execute(stored.View.Id, script, 30, actor, CancellationToken.None).GetAwaiter().GetResult();
        var outText = res.Stdout;
        if (outText.Contains("__SP_MISSING__")) throw new ArgumentException("任务不存在或已被清理。");
        if (outText.Contains("__SP_EXITED__")) return new(false, id, stored.View.Name, "任务已经结束，无需终止。");
        if (outText.Contains("__SP_PID_REUSED__")) throw new InvalidOperationException("检测到进程 PID 已被系统复用，已安全放弃终止操作。");
        if (outText.Contains("__SP_KILLED__"))
        {
            notifications.Fire("job", $"后台任务已终止：{stored.View.Name}", $"jobId={id}");
            return new(true, id, stored.View.Name, "已发送终止信号并停止后台任务进程组。");
        }
        throw new InvalidOperationException("无法确认任务是否已终止：" + (res.Stderr.Length > 0 ? res.Stderr : res.Stdout));
    }

    public JobCleanupResult Delete(string server, string id, string actor = "job")
    {
        ValidateJobId(id);
        var stored = store.Get(server);
        var script = $$"""
            d="$HOME/.serverpilot-jobs/{{id}}"
            if [ ! -d "$d" ]; then echo '__SP_MISSING__'; exit 0; fi
            st=$(sed -n 's/^state=//p' "$d/meta" 2>/dev/null | head -n 1)
            ex=$(cat "$d/exit" 2>/dev/null | tr -d '[:space:]')
            if [ "$st" = "running" ] && [ -z "$ex" ]; then echo '__SP_RUNNING__'; exit 0; fi
            rm -rf "$d"
            echo '__SP_DELETED__'
            """;
        var res = ssh.Execute(stored.View.Id, script, 30, actor, CancellationToken.None).GetAwaiter().GetResult();
        if (res.Stdout.Contains("__SP_MISSING__")) throw new ArgumentException("任务不存在。");
        if (res.Stdout.Contains("__SP_RUNNING__")) throw new ArgumentException("任务仍在运行中，请先终止后再清理。");
        return new(stored.View.Name, 1, "已删除任务记录。");
    }

    public JobCleanupResult Cleanup(string server, int olderThanHours, string actor = "job")
    {
        if (olderThanHours is < 0 or > 8760) throw new ArgumentException("olderThanHours 应在 0–8760 之间。");
        var stored = store.Get(server);
        var minutes = olderThanHours * 60;
        var script = $$"""
            b="$HOME/.serverpilot-jobs"
            if [ ! -d "$b" ]; then echo 'REMOVED=0'; exit 0; fi
            n=0
            for d in "$b"/*; do
              [ -d "$d" ] || continue
              name=$(basename "$d")
              case "$name" in (*[!0-9a-f]*) continue;; esac
              [ ${#name} -eq 32 ] || continue
              st=$(sed -n 's/^state=//p' "$d/meta" 2>/dev/null | head -n 1)
              ex=$(cat "$d/exit" 2>/dev/null | tr -d '[:space:]')
              if [ "$st" = "running" ] && [ -z "$ex" ]; then continue; fi
              if [ {{minutes}} -gt 0 ]; then
                if [ -z "$(find "$d" -maxdepth 0 -mmin +{{minutes}} 2>/dev/null)" ]; then continue; fi
              fi
              rm -rf "$d" && n=$((n+1))
            done
            echo "REMOVED=$n"
            """;
        var res = ssh.Execute(stored.View.Id, script, 60, actor, CancellationToken.None).GetAwaiter().GetResult();
        var m = Regex.Match(res.Stdout, @"REMOVED=(\d+)");
        var removed = m.Success && int.TryParse(m.Groups[1].Value, out var cnt) ? cnt : 0;
        return new(stored.View.Name, removed, $"已清理 {removed} 个已完成后台任务。");
    }

    public JobListResult List(string server, int limit, string actor = "job")
    {
        if (limit is < 1 or > 100) throw new ArgumentException("limit 应在 1–100 之间。");
        var script = "b=$HOME/.serverpilot-jobs; if [ ! -d \"$b\" ]; then echo '__SP_EMPTY__'; else for d in $(ls -1t \"$b\" 2>/dev/null | head -n " + limit + "); do p=\"$b/$d\"; test -d \"$p\" || continue; case \"$d\" in (*[!0-9a-f]*) continue;; esac; [ ${#d} -eq 32 ] || continue; st=$(sed -n 's/^state=//p' \"$p/meta\" 2>/dev/null | head -n 1); t=$(sed -n 's/^started=//p' \"$p/meta\" 2>/dev/null | head -n 1); c=$(sed -n 's/^command=//p' \"$p/meta\" 2>/dev/null | head -n 1 | tr '\\t' ' '); e=$(cat \"$p/exit\" 2>/dev/null); printf '%s\\t%s\\t%s\\t%s\\t%s\\n' \"$d\" \"$st\" \"$t\" \"$e\" \"$c\"; done; fi";
        var result = ssh.Execute(server, script, 60, actor, CancellationToken.None).GetAwaiter().GetResult();
        if (result.Stdout.Contains("__SP_EMPTY__")) return new(server, []);
        var rows = new List<JobListItem>();
        foreach (var line in result.Stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            var parts = line.Split('\t');
            if (parts.Length < 5) continue;
            rows.Add(new(parts[0], string.IsNullOrWhiteSpace(parts[1]) ? "unknown" : parts[1],
                int.TryParse(parts[3].Trim(), out var code) ? code : null, parts[2], parts[4]));
        }
        return new(server, rows);
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
        var jobScript = "#!/bin/sh\ncd \"$HOME/.serverpilot-jobs/" + id + "\" || exit 1\n" +
            "if [ -r \"/proc/$$/stat\" ]; then awk '{print $22}' \"/proc/$$/stat\" > starttime 2>/dev/null || true; fi\n" +
            "trap 'rc=$?; [ -s exit ] || printf \"%s\" \"$rc\" > exit; grep -q \"^state=killed\" meta 2>/dev/null || sed -i s/^state=.*/state=exited/ meta 2>/dev/null || true' EXIT\n" +
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
