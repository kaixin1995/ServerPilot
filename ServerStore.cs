using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Data.Sqlite;

namespace ServerPilot;

public sealed record ServerInput(string? Name, string? Host, int Port, string? Username, string? AuthType, string? Password, string? PrivateKey, string? Passphrase, string? HostFingerprint, string? Tags, string? Notes,
    bool UseServiceKey = false, bool TryKeyboard = false, string? Proxy = null, string? AllowedRemotePaths = null, string? SharedKeyId = null, string? JumpServerId = null,
    string? Provider = null, string? Region = null, string? ExpiresAt = null, string? BillingCycle = null, string? RenewalPrice = null,
    double? TrafficLimitGb = null, int? TrafficResetDay = null);
public sealed record SharedKeyInput(string? Name, string? PrivateKey, string? Passphrase, string? Notes = null);
public sealed record ServerView(string Id, string Name, string Host, int Port, string Username, string AuthType, string HostFingerprint, string Tags, string Notes, string UpdatedAt,
    bool UseServiceKey, bool TryKeyboard, string Proxy, string AllowedRemotePaths, string JumpServerId = "", string SharedKeyId = "",
    string Provider = "", string Region = "", string ExpiresAt = "", string BillingCycle = "", string RenewalPrice = "",
    double? TrafficLimitGb = null, int? TrafficResetDay = null);
public sealed record Credential(string? Password, string? PrivateKey, string? Passphrase, string? ProxyUrl = null);
public sealed record StoredServer(ServerView View, Credential Credential);

public sealed class ServerStore(AppOptions options)
{
    private readonly string _connectionString = new SqliteConnectionStringBuilder { DataSource = Path.Combine(options.DataDirectory, "serverpilot.db"), Mode = SqliteOpenMode.ReadWriteCreate }.ToString();

    public event Action<string>? ServerChanged;

    private SqliteConnection Open()
    {
        var c = new SqliteConnection(_connectionString); c.Open();
        using var cmd = c.CreateCommand(); cmd.CommandText = "PRAGMA busy_timeout=5000; PRAGMA foreign_keys=ON;"; cmd.ExecuteNonQuery();
        return c;
    }

    public void Initialize()
    {
        using var c = Open(); using var cmd = c.CreateCommand();
        cmd.CommandText = """
            CREATE TABLE IF NOT EXISTS servers(
                id TEXT PRIMARY KEY, name TEXT NOT NULL COLLATE NOCASE UNIQUE, host TEXT NOT NULL,
                port INTEGER NOT NULL, username TEXT NOT NULL, auth_type TEXT NOT NULL,
                host_fingerprint TEXT NOT NULL, tags TEXT NOT NULL, notes TEXT NOT NULL,
                credential TEXT NOT NULL, updated_at TEXT NOT NULL,
                use_service_key INTEGER NOT NULL DEFAULT 0, try_keyboard INTEGER NOT NULL DEFAULT 0, proxy TEXT NOT NULL DEFAULT '',
                allowed_remote_paths TEXT NOT NULL DEFAULT '', jump_server_id TEXT NOT NULL DEFAULT '', shared_key_id TEXT NOT NULL DEFAULT '',
                provider TEXT NOT NULL DEFAULT '', region TEXT NOT NULL DEFAULT '', expires_at TEXT NOT NULL DEFAULT '',
                billing_cycle TEXT NOT NULL DEFAULT '', renewal_price TEXT NOT NULL DEFAULT '',
                traffic_limit_gb REAL, traffic_reset_day INTEGER);
            CREATE TABLE IF NOT EXISTS audit(
                id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT NOT NULL, actor TEXT NOT NULL,
                server_name TEXT NOT NULL, action TEXT NOT NULL, result TEXT NOT NULL,
                detail TEXT NOT NULL DEFAULT '', exit_code INTEGER, duration_ms INTEGER, client_ip TEXT NOT NULL DEFAULT '');
            CREATE INDEX IF NOT EXISTS audit_at_idx ON audit(at);
            CREATE TABLE IF NOT EXISTS shared_keys(
                id TEXT PRIMARY KEY, name TEXT NOT NULL COLLATE NOCASE UNIQUE, credential TEXT NOT NULL, created_at TEXT NOT NULL,
                algorithm TEXT NOT NULL DEFAULT '', fingerprint TEXT NOT NULL DEFAULT '', public_key TEXT NOT NULL DEFAULT '',
                has_passphrase INTEGER NOT NULL DEFAULT 0, notes TEXT NOT NULL DEFAULT '', updated_at TEXT NOT NULL DEFAULT '');
            CREATE TABLE IF NOT EXISTS mcp_tokens(
                id TEXT PRIMARY KEY, name TEXT NOT NULL COLLATE NOCASE UNIQUE, prefix TEXT NOT NULL,
                token_hash TEXT NOT NULL UNIQUE, read_only INTEGER NOT NULL DEFAULT 0,
                allowed_tags TEXT NOT NULL DEFAULT '', allowed_server_ids TEXT NOT NULL DEFAULT '',
                expires_at TEXT, last_used_at TEXT, created_at TEXT NOT NULL, revoked INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS snippets(
                id TEXT PRIMARY KEY, name TEXT NOT NULL COLLATE NOCASE UNIQUE, category TEXT NOT NULL DEFAULT '通用',
                command TEXT NOT NULL, description TEXT NOT NULL DEFAULT '', updated_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS settings(
                key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS server_snapshots(
                server_id TEXT PRIMARY KEY, payload TEXT NOT NULL, checked_at TEXT NOT NULL);
            """;
        cmd.ExecuteNonQuery();
        EnsureColumns(c);
        BackfillSharedKeyMetadata(c);
        SeedDefaultSnippets(c);
        CleanupAudit();
        if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(Path.Combine(options.DataDirectory, "serverpilot.db"), UnixFileMode.UserRead | UnixFileMode.UserWrite);
    }

    private static void EnsureColumns(SqliteConnection c)
    {
        EnsureTableColumns(c, "servers", [
            ("use_service_key", "ALTER TABLE servers ADD COLUMN use_service_key INTEGER NOT NULL DEFAULT 0"),
            ("try_keyboard", "ALTER TABLE servers ADD COLUMN try_keyboard INTEGER NOT NULL DEFAULT 0"),
            ("proxy", "ALTER TABLE servers ADD COLUMN proxy TEXT NOT NULL DEFAULT ''"),
            ("allowed_remote_paths", "ALTER TABLE servers ADD COLUMN allowed_remote_paths TEXT NOT NULL DEFAULT ''"),
            ("jump_server_id", "ALTER TABLE servers ADD COLUMN jump_server_id TEXT NOT NULL DEFAULT ''"),
            ("shared_key_id", "ALTER TABLE servers ADD COLUMN shared_key_id TEXT NOT NULL DEFAULT ''"),
            ("provider", "ALTER TABLE servers ADD COLUMN provider TEXT NOT NULL DEFAULT ''"),
            ("region", "ALTER TABLE servers ADD COLUMN region TEXT NOT NULL DEFAULT ''"),
            ("expires_at", "ALTER TABLE servers ADD COLUMN expires_at TEXT NOT NULL DEFAULT ''"),
            ("billing_cycle", "ALTER TABLE servers ADD COLUMN billing_cycle TEXT NOT NULL DEFAULT ''"),
            ("renewal_price", "ALTER TABLE servers ADD COLUMN renewal_price TEXT NOT NULL DEFAULT ''"),
            ("traffic_limit_gb", "ALTER TABLE servers ADD COLUMN traffic_limit_gb REAL"),
            ("traffic_reset_day", "ALTER TABLE servers ADD COLUMN traffic_reset_day INTEGER")
        ]);
        EnsureTableColumns(c, "shared_keys", [
            ("algorithm", "ALTER TABLE shared_keys ADD COLUMN algorithm TEXT NOT NULL DEFAULT ''"),
            ("fingerprint", "ALTER TABLE shared_keys ADD COLUMN fingerprint TEXT NOT NULL DEFAULT ''"),
            ("public_key", "ALTER TABLE shared_keys ADD COLUMN public_key TEXT NOT NULL DEFAULT ''"),
            ("has_passphrase", "ALTER TABLE shared_keys ADD COLUMN has_passphrase INTEGER NOT NULL DEFAULT 0"),
            ("notes", "ALTER TABLE shared_keys ADD COLUMN notes TEXT NOT NULL DEFAULT ''"),
            ("updated_at", "ALTER TABLE shared_keys ADD COLUMN updated_at TEXT NOT NULL DEFAULT ''")
        ]);
        EnsureTableColumns(c, "audit", [
            ("detail", "ALTER TABLE audit ADD COLUMN detail TEXT NOT NULL DEFAULT ''"),
            ("exit_code", "ALTER TABLE audit ADD COLUMN exit_code INTEGER"),
            ("duration_ms", "ALTER TABLE audit ADD COLUMN duration_ms INTEGER"),
            ("client_ip", "ALTER TABLE audit ADD COLUMN client_ip TEXT NOT NULL DEFAULT ''")
        ]);
    }

    private static void EnsureTableColumns(SqliteConnection c, string table, (string Name, string Ddl)[] specs)
    {
        using var info = c.CreateCommand(); info.CommandText = $"PRAGMA table_info({table})";
        var columns = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        using (var r = info.ExecuteReader()) while (r.Read()) columns.Add(r.GetString(1));
        foreach (var (name, ddl) in specs)
        {
            if (columns.Contains(name)) continue;
            using var alter = c.CreateCommand(); alter.CommandText = ddl; alter.ExecuteNonQuery();
        }
    }

    private static void SeedDefaultSnippets(SqliteConnection c)
    {
        using var check = c.CreateCommand();
        check.CommandText = "SELECT value FROM settings WHERE key='snippets_seeded'";
        if (check.ExecuteScalar() is not null) return;

        var now = DateTimeOffset.UtcNow.ToString("O");
        var defaults = new (string Name, string Category, string Command, string Desc)[]
        {
            ("系统资源概览", "巡检", "uname -a && uptime && free -h && df -h -x tmpfs -x devtmpfs", "查看系统版本、运行时间、内存与磁盘使用情况"),
            ("监听端口列表", "网络", "ss -tulnp 2>/dev/null || netstat -tulnp 2>/dev/null", "查看本机所有 TCP/UDP 监听端口及对应进程"),
            ("Docker 容器状态", "容器", "docker ps -a --format 'table {{.Names}}\\t{{.Status}}\\t{{.Ports}}'", "列出所有 Docker 容器运行状态与端口映射"),
            ("Nginx 配置检测与重载", "Web服务", "nginx -t && systemctl reload nginx", "检查 Nginx 配置语法并无损重载"),
            ("异常 Systemd 服务", "巡检", "systemctl --failed --no-pager", "排查当前处于 failed 状态的系统服务"),
            ("磁盘大目录 Top15", "存储", "du -xhd 2 / 2>/dev/null | sort -hr | head -n 15", "快速定位根分区占用空间最大的目录")
        };

        foreach (var (name, category, command, desc) in defaults)
        {
            using var ins = c.CreateCommand();
            ins.CommandText = "INSERT OR IGNORE INTO snippets(id,name,category,command,description,updated_at) VALUES($id,$name,$cat,$cmd,$desc,$at)";
            ins.Parameters.AddWithValue("$id", Guid.NewGuid().ToString("N"));
            ins.Parameters.AddWithValue("$name", name);
            ins.Parameters.AddWithValue("$cat", category);
            ins.Parameters.AddWithValue("$cmd", command);
            ins.Parameters.AddWithValue("$desc", desc);
            ins.Parameters.AddWithValue("$at", now);
            ins.ExecuteNonQuery();
        }

        using var mark = c.CreateCommand();
        mark.CommandText = "INSERT OR REPLACE INTO settings(key,value,updated_at) VALUES('snippets_seeded','1',$at)";
        mark.Parameters.AddWithValue("$at", now);
        mark.ExecuteNonQuery();
    }

    private static ServerView View(SqliteDataReader r) => new(
        r.GetString(0), r.GetString(1), r.GetString(2), r.GetInt32(3), r.GetString(4),
        r.GetString(5), r.GetString(6), r.GetString(7), r.GetString(8), r.GetString(9),
        r.GetInt32(10) != 0, r.GetInt32(11) != 0, MaskProxy(r.GetString(12)), r.GetString(13), r.GetString(14), r.GetString(15),
        r.GetString(16), r.GetString(17), r.GetString(18), r.GetString(19), r.GetString(20),
        r.IsDBNull(21) ? null : r.GetDouble(21), r.IsDBNull(22) ? null : r.GetInt32(22));

    public List<ServerView> List()
    {
        using var c = Open(); using var cmd = c.CreateCommand();
        cmd.CommandText = "SELECT id,name,host,port,username,auth_type,host_fingerprint,tags,notes,updated_at,use_service_key,try_keyboard,proxy,allowed_remote_paths,jump_server_id,shared_key_id,provider,region,expires_at,billing_cycle,renewal_price,traffic_limit_gb,traffic_reset_day FROM servers ORDER BY name";
        using var r = cmd.ExecuteReader(); var rows = new List<ServerView>(); while (r.Read()) rows.Add(View(r)); return rows;
    }

    public StoredServer Get(string idOrName)
    {
        using var c = Open(); using var cmd = c.CreateCommand();
        cmd.CommandText = "SELECT id,name,host,port,username,auth_type,host_fingerprint,tags,notes,updated_at,use_service_key,try_keyboard,proxy,allowed_remote_paths,jump_server_id,shared_key_id,provider,region,expires_at,billing_cycle,renewal_price,traffic_limit_gb,traffic_reset_day,credential FROM servers WHERE id=$id OR name=$id COLLATE NOCASE";
        cmd.Parameters.AddWithValue("$id", idOrName);
        using var r = cmd.ExecuteReader();
        if (!r.Read()) throw new ArgumentException("找不到指定服务器。请使用服务器 ID 或名称。");
        var view = View(r);
        var cred = Decrypt(r.GetString(23));
        if (string.IsNullOrWhiteSpace(cred.ProxyUrl) && !string.IsNullOrWhiteSpace(r.GetString(12)))
            cred = cred with { ProxyUrl = r.GetString(12) };
        if (view.AuthType == "privateKey" && !string.IsNullOrEmpty(view.SharedKeyId))
        {
            var shared = GetSharedKey(view.SharedKeyId);
            cred = new Credential(null, shared.PrivateKey, shared.Passphrase, cred.ProxyUrl);
        }
        return new(view, cred);
    }

    public ServerView Save(string? id, ServerInput input)
    {
        var name = Required(input.Name, "名称", 80); var host = Required(input.Host, "地址", 255);
        var username = Required(input.Username, "用户名", 128); var auth = Required(input.AuthType, "认证方式", 20);
        var fingerprint = Required(input.HostFingerprint, "SSH 主机指纹", 100);
        if (!Regex.IsMatch(fingerprint, @"^SHA256:[A-Za-z0-9+/]{43}$")) throw new ArgumentException("主机指纹应为 SHA256: 开头的 OpenSSH 指纹。");
        if (input.Port is < 1 or > 65535) throw new ArgumentException("SSH 端口无效。");
        if (auth is not ("password" or "privateKey")) throw new ArgumentException("请选择密码或私钥认证。");
        if (host.Any(char.IsWhiteSpace) || host.Contains('/') || host.Contains('@')) throw new ArgumentException("服务器地址无效。");

        var previous = id is null ? null : Get(id);
        var rawProxyInput = (input.Proxy ?? "").Trim();
        string? effectiveProxyUrl;
        if (rawProxyInput.Length == 0)
        {
            effectiveProxyUrl = null;
        }
        else if (previous is not null && rawProxyInput == previous.View.Proxy && !string.IsNullOrWhiteSpace(previous.Credential.ProxyUrl))
        {
            effectiveProxyUrl = previous.Credential.ProxyUrl;
        }
        else
        {
            if (rawProxyInput.Length > 2048 || rawProxyInput.Contains('\0')) throw new ArgumentException("代理地址无效。");
            ValidateProxy(rawProxyInput);
            effectiveProxyUrl = rawProxyInput;
        }
        var maskedProxy = effectiveProxyUrl is null ? "" : MaskProxy(effectiveProxyUrl);

        var jumpServerId = (input.JumpServerId ?? "").Trim();
        var allowedRemote = NormalizeRemoteRoots(input.AllowedRemotePaths);
        var sameAuth = previous?.View.AuthType == auth;
        var sharedKeyId = auth == "privateKey" ? (input.SharedKeyId ?? "").Trim() : "";

        Credential credential;
        if (auth == "privateKey" && !string.IsNullOrEmpty(sharedKeyId))
        {
            // Verify referenced shared key exists; store reference only (no duplicate private key copy)
            _ = GetSharedKey(sharedKeyId);
            credential = new Credential(null, null, null, effectiveProxyUrl);
        }
        else if (auth == "password")
        {
            credential = new Credential(!string.IsNullOrEmpty(input.Password) ? input.Password : sameAuth ? previous?.Credential.Password : null, null, null, effectiveProxyUrl);
        }
        else
        {
            var prevWasInline = sameAuth && string.IsNullOrEmpty(previous?.View.SharedKeyId);
            credential = new Credential(null,
                !string.IsNullOrWhiteSpace(input.PrivateKey) ? input.PrivateKey : prevWasInline ? previous?.Credential.PrivateKey : null,
                !string.IsNullOrEmpty(input.PrivateKey) ? input.Passphrase : !string.IsNullOrEmpty(input.Passphrase) ? input.Passphrase : prevWasInline ? previous?.Credential.Passphrase : null,
                effectiveProxyUrl);
        }

        if (!input.UseServiceKey && string.IsNullOrEmpty(sharedKeyId))
        {
            if (auth == "password" && string.IsNullOrEmpty(credential.Password)) throw new ArgumentException("请输入 SSH 密码。");
            if (auth == "privateKey" && string.IsNullOrWhiteSpace(credential.PrivateKey)) throw new ArgumentException("请选择共享密钥或输入 SSH 私钥。");
        }
        if ((credential.Password?.Length ?? 0) > 4096 || (credential.PrivateKey?.Length ?? 0) > 65536 || (credential.Passphrase?.Length ?? 0) > 4096) throw new ArgumentException("凭据过长。");
        id ??= Guid.NewGuid().ToString("N");

        if (!string.IsNullOrEmpty(jumpServerId))
            ValidateJumpChain(id, jumpServerId);

        var provider = Optional(input.Provider, 80);
        var region = Optional(input.Region, 80);
        var expiresAt = (input.ExpiresAt ?? "").Trim();
        if (expiresAt.Length > 0 && !DateOnly.TryParseExact(expiresAt, "yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.None, out _))
            throw new ArgumentException("到期日期格式应为 YYYY-MM-DD。");
        var billingCycle = Optional(input.BillingCycle, 40);
        var renewalPrice = Optional(input.RenewalPrice, 40);
        var trafficLimitGb = input.TrafficLimitGb;
        if (trafficLimitGb.HasValue && (double.IsNaN(trafficLimitGb.Value) || double.IsInfinity(trafficLimitGb.Value) || trafficLimitGb.Value <= 0 || trafficLimitGb.Value > 10_000_000))
            throw new ArgumentException("月流量限额应在 0–10000000 GB 之间。");
        var trafficResetDay = input.TrafficResetDay;
        if (trafficResetDay.HasValue && trafficResetDay.Value is < 1 or > 31)
            throw new ArgumentException("流量重置日应在 1–31 之间。");

        var updated = DateTimeOffset.UtcNow.ToString("O");
        using var c = Open(); using var cmd = c.CreateCommand();
        cmd.CommandText = """
            INSERT INTO servers (id,name,host,port,username,auth_type,host_fingerprint,tags,notes,credential,updated_at,use_service_key,try_keyboard,proxy,allowed_remote_paths,jump_server_id,shared_key_id,provider,region,expires_at,billing_cycle,renewal_price,traffic_limit_gb,traffic_reset_day)
            VALUES ($id,$name,$host,$port,$username,$auth,$fp,$tags,$notes,$credential,$updated,$serviceKey,$keyboard,$proxy,$allowed,$jump,$sharedKey,$provider,$region,$expiresAt,$billingCycle,$renewalPrice,$trafficLimit,$trafficReset)
            ON CONFLICT(id) DO UPDATE SET name=$name,host=$host,port=$port,username=$username,auth_type=$auth,
              host_fingerprint=$fp,tags=$tags,notes=$notes,credential=$credential,updated_at=$updated,
              use_service_key=$serviceKey,try_keyboard=$keyboard,proxy=$proxy,allowed_remote_paths=$allowed,jump_server_id=$jump,shared_key_id=$sharedKey,
              provider=$provider,region=$region,expires_at=$expiresAt,billing_cycle=$billingCycle,renewal_price=$renewalPrice,traffic_limit_gb=$trafficLimit,traffic_reset_day=$trafficReset
            """;
        foreach (var (k, v) in new Dictionary<string, object>
        {
            ["$id"] = id, ["$name"] = name, ["$host"] = host, ["$port"] = input.Port, ["$username"] = username,
            ["$auth"] = auth, ["$fp"] = fingerprint, ["$tags"] = Optional(input.Tags, 300), ["$notes"] = Optional(input.Notes, 1000),
            ["$credential"] = Encrypt(credential), ["$updated"] = updated, ["$serviceKey"] = input.UseServiceKey ? 1 : 0,
            ["$keyboard"] = input.TryKeyboard ? 1 : 0, ["$proxy"] = maskedProxy, ["$allowed"] = allowedRemote, ["$jump"] = jumpServerId, ["$sharedKey"] = sharedKeyId,
            ["$provider"] = provider, ["$region"] = region, ["$expiresAt"] = expiresAt, ["$billingCycle"] = billingCycle, ["$renewalPrice"] = renewalPrice,
            ["$trafficLimit"] = (object?)trafficLimitGb ?? DBNull.Value, ["$trafficReset"] = (object?)trafficResetDay ?? DBNull.Value
        }) cmd.Parameters.AddWithValue(k, v);
        try { cmd.ExecuteNonQuery(); } catch (SqliteException e) when (e.SqliteErrorCode == 19) { throw new ArgumentException("服务器名称已存在。"); }
        Audit("web", name, previous is null ? "server.create" : "server.update", "success");
        ServerChanged?.Invoke(id);
        return new(id, name, host, input.Port, username, auth, fingerprint, Optional(input.Tags, 300), Optional(input.Notes, 1000), updated,
            input.UseServiceKey, input.TryKeyboard, maskedProxy, allowedRemote, jumpServerId, sharedKeyId,
            provider, region, expiresAt, billingCycle, renewalPrice, trafficLimitGb, trafficResetDay);
    }

    public void BindServerToSharedKey(string serverId, string sharedKeyId)
    {
        var server = Get(serverId);
        _ = GetSharedKey(sharedKeyId);
        var newCred = new Credential(null, null, null, server.Credential.ProxyUrl);
        var updated = DateTimeOffset.UtcNow.ToString("O");
        using var c = Open(); using var cmd = c.CreateCommand();
        cmd.CommandText = "UPDATE servers SET auth_type='privateKey', shared_key_id=$keyId, credential=$cred, updated_at=$at WHERE id=$id";
        cmd.Parameters.AddWithValue("$keyId", sharedKeyId);
        cmd.Parameters.AddWithValue("$cred", Encrypt(newCred));
        cmd.Parameters.AddWithValue("$at", updated);
        cmd.Parameters.AddWithValue("$id", server.View.Id);
        cmd.ExecuteNonQuery();
        Audit("web", server.View.Name, "server.bind_key", "success");
        ServerChanged?.Invoke(server.View.Id);
    }

    private void ValidateJumpChain(string serverId, string jumpServerId)
    {
        if (string.Equals(serverId, jumpServerId, StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("不能将服务器自身设为跳板机。");
        var all = List().ToDictionary(s => s.Id, StringComparer.OrdinalIgnoreCase);
        if (!all.TryGetValue(jumpServerId, out var current))
            throw new ArgumentException("指定的跳板机服务器不存在。");
        var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { serverId };
        var depth = 0;
        while (current is not null)
        {
            if (!visited.Add(current.Id))
                throw new ArgumentException("跳板机链路存在循环依赖，请重新选择。");
            depth++;
            if (depth > 3)
                throw new ArgumentException("跳板机级联层数最多支持 3 级。");
            if (string.IsNullOrEmpty(current.JumpServerId)) break;
            all.TryGetValue(current.JumpServerId, out current);
        }
    }

    public void Delete(string id)
    {
        var s = Get(id);
        using var c = Open();
        using (var check = c.CreateCommand())
        {
            check.CommandText = "SELECT name FROM servers WHERE jump_server_id=$id LIMIT 1";
            check.Parameters.AddWithValue("$id", s.View.Id);
            if (check.ExecuteScalar() is string dependent)
                throw new ArgumentException($"服务器「{dependent}」正在使用该主机作为跳板机，请先修改其跳板机配置。");
        }
        using var cmd = c.CreateCommand();
        cmd.CommandText = "DELETE FROM servers WHERE id=$id";
        cmd.Parameters.AddWithValue("$id", s.View.Id);
        cmd.ExecuteNonQuery();
        DeleteSnapshot(s.View.Id);
        Audit("web", s.View.Name, "server.delete", "success");
        ServerChanged?.Invoke(s.View.Id);
    }

    public void SaveSnapshot(ServerSnapshot snap)
    {
        using var c = Open(); using var cmd = c.CreateCommand();
        cmd.CommandText = "INSERT OR REPLACE INTO server_snapshots(server_id, payload, checked_at) VALUES ($id, $payload, $at)";
        cmd.Parameters.AddWithValue("$id", snap.ServerId);
        cmd.Parameters.AddWithValue("$payload", JsonSerializer.Serialize(snap, ApiJsonContext.Default.ServerSnapshot));
        cmd.Parameters.AddWithValue("$at", snap.CheckedAt);
        cmd.ExecuteNonQuery();
    }

    public List<ServerSnapshot> LoadSnapshots()
    {
        var list = new List<ServerSnapshot>();
        using var c = Open(); using var cmd = c.CreateCommand();
        cmd.CommandText = "SELECT s.payload FROM server_snapshots s INNER JOIN servers srv ON srv.id = s.server_id";
        using var r = cmd.ExecuteReader();
        while (r.Read())
        {
            try
            {
                var snap = JsonSerializer.Deserialize(r.GetString(0), ApiJsonContext.Default.ServerSnapshot);
                if (snap is not null) list.Add(snap);
            }
            catch { }
        }
        return list;
    }

    public void DeleteSnapshot(string serverId)
    {
        using var c = Open(); using var cmd = c.CreateCommand();
        cmd.CommandText = "DELETE FROM server_snapshots WHERE server_id=$id";
        cmd.Parameters.AddWithValue("$id", serverId);
        cmd.ExecuteNonQuery();
    }

    // --- Audit ---
    public void Audit(string actor, string server, string action, string result, string? detail = null, int? exitCode = null, long? durationMs = null, string? clientIp = null)
    {
        var storedDetail = !string.IsNullOrEmpty(detail) && GetAuditRecordDetails() ? RedactDetail(detail) : "";
        using var c = Open(); using var cmd = c.CreateCommand();
        cmd.CommandText = "INSERT INTO audit(at,actor,server_name,action,result,detail,exit_code,duration_ms,client_ip) VALUES ($at,$actor,$server,$action,$result,$detail,$exitCode,$durationMs,$clientIp)";
        cmd.Parameters.AddWithValue("$at", DateTimeOffset.UtcNow.ToString("O"));
        cmd.Parameters.AddWithValue("$actor", actor);
        cmd.Parameters.AddWithValue("$server", server);
        cmd.Parameters.AddWithValue("$action", action);
        cmd.Parameters.AddWithValue("$result", result);
        cmd.Parameters.AddWithValue("$detail", storedDetail);
        cmd.Parameters.AddWithValue("$exitCode", exitCode.HasValue ? exitCode.Value : DBNull.Value);
        cmd.Parameters.AddWithValue("$durationMs", durationMs.HasValue ? durationMs.Value : DBNull.Value);
        cmd.Parameters.AddWithValue("$clientIp", clientIp ?? "");
        cmd.ExecuteNonQuery();
    }

    public static string RedactDetail(string input)
    {
        var s = input.Replace("\r", " ").Replace("\n", " ").Trim();
        s = Regex.Replace(s, @"-----BEGIN [A-Z0-9 ]+PRIVATE KEY-----.*?-----END [A-Z0-9 ]+PRIVATE KEY-----", "[REDACTED_KEY]", RegexOptions.Singleline);
        s = Regex.Replace(s, @"(?i)(password|passwd|pwd|token|secret|api[_-]?key|passphrase)(\s*[:=]\s*)(\S+)", "$1$2***");
        s = Regex.Replace(s, @"(?i)(Bearer\s+)([A-Za-z0-9\-._~+/]+=*)", "$1***");
        s = Regex.Replace(s, @"(?i)(sshpass\s+-p\s+)(\S+)", "$1***");
        s = Regex.Replace(s, @"(?i)(mysql[^\n]*?\s-p)([^\s;]+)", "$1***");
        return s.Length > 500 ? s[..500] + "…" : s;
    }

    public void CleanupAudit()
    {
        using var c = Open(); using var cmd = c.CreateCommand(); cmd.CommandText = "DELETE FROM audit WHERE at < $cutoff";
        cmd.Parameters.AddWithValue("$cutoff", DateTimeOffset.UtcNow.AddDays(-30).ToString("O")); cmd.ExecuteNonQuery();
    }

    private static (string Where, Dictionary<string, object> Params) BuildAuditFilter(string? server, string? actor, string? result, string? query)
    {
        var clauses = new List<string>();
        var p = new Dictionary<string, object>();
        if (!string.IsNullOrWhiteSpace(server)) { clauses.Add("server_name LIKE $server"); p["$server"] = "%" + server.Trim() + "%"; }
        if (!string.IsNullOrWhiteSpace(actor)) { clauses.Add("actor LIKE $actor"); p["$actor"] = "%" + actor.Trim() + "%"; }
        if (!string.IsNullOrWhiteSpace(result)) { clauses.Add("result = $result"); p["$result"] = result.Trim(); }
        if (!string.IsNullOrWhiteSpace(query))
        {
            clauses.Add("(server_name LIKE $q OR action LIKE $q OR detail LIKE $q OR actor LIKE $q)");
            p["$q"] = "%" + query.Trim() + "%";
        }
        return (clauses.Count > 0 ? " WHERE " + string.Join(" AND ", clauses) : "", p);
    }

    public AuditPageResult AuditList(int page, int pageSize, string? server = null, string? actor = null, string? result = null, string? query = null)
    {
        if (page < 1 || pageSize is < 1 or > 100) throw new ArgumentException("页码无效，每页数量应在 1–100 之间。");
        CleanupAudit();
        var (where, parameters) = BuildAuditFilter(server, actor, result, query);
        using var c = Open(); using var transaction = c.BeginTransaction();
        using var count = c.CreateCommand(); count.Transaction = transaction; count.CommandText = "SELECT COUNT(*) FROM audit" + where;
        foreach (var (k, v) in parameters) count.Parameters.AddWithValue(k, v);
        var total = (long)count.ExecuteScalar()!; var totalPages = Math.Max(1, (total + pageSize - 1) / pageSize); page = (int)Math.Min(page, totalPages);
        using var cmd = c.CreateCommand(); cmd.Transaction = transaction;
        cmd.CommandText = "SELECT at,actor,server_name,action,result,detail,exit_code,duration_ms,client_ip FROM audit" + where + " ORDER BY id DESC LIMIT $limit OFFSET $offset";
        foreach (var (k, v) in parameters) cmd.Parameters.AddWithValue(k, v);
        cmd.Parameters.AddWithValue("$limit", pageSize); cmd.Parameters.AddWithValue("$offset", ((long)page - 1) * pageSize);
        using var r = cmd.ExecuteReader(); var rows = new List<AuditItem>();
        while (r.Read()) rows.Add(ReadAuditItem(r));
        return new(rows, page, pageSize, total, totalPages);
    }

    public List<AuditItem> AuditExport(string? server = null, string? actor = null, string? result = null, string? query = null)
    {
        CleanupAudit();
        var (where, parameters) = BuildAuditFilter(server, actor, result, query);
        using var c = Open(); using var cmd = c.CreateCommand();
        cmd.CommandText = "SELECT at,actor,server_name,action,result,detail,exit_code,duration_ms,client_ip FROM audit" + where + " ORDER BY id DESC LIMIT 5000";
        foreach (var (k, v) in parameters) cmd.Parameters.AddWithValue(k, v);
        using var r = cmd.ExecuteReader(); var rows = new List<AuditItem>();
        while (r.Read()) rows.Add(ReadAuditItem(r));
        return rows;
    }

    private static AuditItem ReadAuditItem(SqliteDataReader r) => new(
        r.GetString(0), r.GetString(1), r.GetString(2), r.GetString(3), r.GetString(4),
        r.IsDBNull(5) ? "" : r.GetString(5),
        r.IsDBNull(6) ? null : r.GetInt32(6),
        r.IsDBNull(7) ? null : r.GetInt64(7),
        r.IsDBNull(8) ? "" : r.GetString(8));

    // --- Shared Keys (Reference-Bound Key Vault) ---
    private sealed record KeyMetadata(string Algorithm, string Fingerprint, string PublicKey, bool HasPassphrase);

    private static KeyMetadata InspectPrivateKey(string privateKey, string? passphrase, string comment)
    {
        try
        {
            using var stream = new MemoryStream(Encoding.UTF8.GetBytes(privateKey));
            using var key = string.IsNullOrEmpty(passphrase) ? new Renci.SshNet.PrivateKeyFile(stream) : new Renci.SshNet.PrivateKeyFile(stream, passphrase);
            var alg = key.HostKeyAlgorithms.FirstOrDefault(a => a.Name == "ssh-rsa")
                ?? key.HostKeyAlgorithms.FirstOrDefault()
                ?? throw new ArgumentException("无法识别私钥算法。");
            var label = alg.Name switch
            {
                "ssh-ed25519" => "ED25519",
                "ssh-rsa" or "rsa-sha2-256" or "rsa-sha2-512" => "RSA",
                var s when s.StartsWith("ecdsa-", StringComparison.OrdinalIgnoreCase) => "ECDSA",
                var s => s.ToUpperInvariant()
            };
            var fp = "SHA256:" + Convert.ToBase64String(SHA256.HashData(alg.Data)).TrimEnd('=');
            var safeComment = Regex.Replace(comment, @"\s+", "-").Trim();
            if (safeComment.Length == 0) safeComment = "serverpilot";
            var pubKey = $"{alg.Name} {Convert.ToBase64String(alg.Data)} {safeComment}";
            return new(label, fp, pubKey, !string.IsNullOrEmpty(passphrase));
        }
        catch (Exception exception) when (exception is Renci.SshNet.Common.SshException or CryptographicException or ArgumentException or FormatException)
        {
            throw new ArgumentException("无法读取私钥，请检查文件格式和口令。");
        }
    }

    private static string GeneratePrivateKeyPem(string algorithm)
    {
        var alg = (algorithm ?? "ed25519").Trim().ToLowerInvariant();
        if (alg == "ed25519")
        {
            var gen = new Org.BouncyCastle.Crypto.Generators.Ed25519KeyPairGenerator();
            gen.Init(new Org.BouncyCastle.Crypto.Parameters.Ed25519KeyGenerationParameters(new Org.BouncyCastle.Security.SecureRandom()));
            var pair = gen.GenerateKeyPair();
            var blob = Org.BouncyCastle.Crypto.Utilities.OpenSshPrivateKeyUtilities.EncodePrivateKey(pair.Private);
            var b64 = Convert.ToBase64String(blob);
            var sb = new StringBuilder();
            sb.AppendLine("-----BEGIN OPENSSH PRIVATE KEY-----");
            for (var i = 0; i < b64.Length; i += 70)
                sb.AppendLine(b64.Substring(i, Math.Min(70, b64.Length - i)));
            sb.AppendLine("-----END OPENSSH PRIVATE KEY-----");
            return sb.ToString();
        }
        if (alg == "rsa4096")
        {
            using var rsa = RSA.Create(4096);
            return rsa.ExportRSAPrivateKeyPem() + "\n";
        }
        throw new ArgumentException("仅支持生成 ed25519 或 rsa4096 密钥。");
    }

    private void BackfillSharedKeyMetadata(SqliteConnection c)
    {
        var pending = new List<(string Id, string Name, string Cred, string CreatedAt)>();
        using (var sel = c.CreateCommand())
        {
            sel.CommandText = "SELECT id,name,credential,created_at FROM shared_keys WHERE fingerprint='' OR public_key=''";
            using var r = sel.ExecuteReader();
            while (r.Read()) pending.Add((r.GetString(0), r.GetString(1), r.GetString(2), r.GetString(3)));
        }
        foreach (var (id, name, enc, createdAt) in pending)
        {
            try
            {
                var cred = Decrypt(enc);
                if (string.IsNullOrWhiteSpace(cred.PrivateKey)) continue;
                var meta = InspectPrivateKey(cred.PrivateKey, cred.Passphrase, name);
                using var upd = c.CreateCommand();
                upd.CommandText = "UPDATE shared_keys SET algorithm=$alg,fingerprint=$fp,public_key=$pub,has_passphrase=$hp,updated_at=CASE WHEN updated_at='' THEN $at ELSE updated_at END WHERE id=$id";
                upd.Parameters.AddWithValue("$alg", meta.Algorithm);
                upd.Parameters.AddWithValue("$fp", meta.Fingerprint);
                upd.Parameters.AddWithValue("$pub", meta.PublicKey);
                upd.Parameters.AddWithValue("$hp", meta.HasPassphrase ? 1 : 0);
                upd.Parameters.AddWithValue("$at", createdAt);
                upd.Parameters.AddWithValue("$id", id);
                upd.ExecuteNonQuery();
            }
            catch { /* Ignore corrupted legacy rows during startup backfill */ }
        }
    }

    public List<SharedKeySummary> ListSharedKeys()
    {
        using var c = Open();
        var boundMap = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        using (var sCmd = c.CreateCommand())
        {
            sCmd.CommandText = "SELECT shared_key_id, name FROM servers WHERE shared_key_id != '' ORDER BY name";
            using var sr = sCmd.ExecuteReader();
            while (sr.Read())
            {
                var kid = sr.GetString(0);
                if (!boundMap.TryGetValue(kid, out var list)) boundMap[kid] = list = [];
                list.Add(sr.GetString(1));
            }
        }
        using var cmd = c.CreateCommand();
        cmd.CommandText = "SELECT id,name,algorithm,fingerprint,public_key,has_passphrase,notes,created_at,updated_at FROM shared_keys ORDER BY name";
        using var r = cmd.ExecuteReader();
        var rows = new List<SharedKeySummary>();
        while (r.Read())
        {
            var id = r.GetString(0);
            var created = r.GetString(7);
            var updated = r.GetString(8);
            rows.Add(new(id, r.GetString(1), r.GetString(2), r.GetString(3), r.GetString(4), r.GetInt32(5) != 0, r.GetString(6), created, string.IsNullOrEmpty(updated) ? created : updated, boundMap.GetValueOrDefault(id) ?? []));
        }
        return rows;
    }

    public SharedKeySummary GetSharedKeySummary(string id) =>
        ListSharedKeys().FirstOrDefault(k => string.Equals(k.Id, id, StringComparison.OrdinalIgnoreCase))
        ?? throw new ArgumentException("找不到指定的共享私钥。");

    private Credential GetSharedKey(string id)
    {
        using var c = Open(); using var cmd = c.CreateCommand(); cmd.CommandText = "SELECT credential FROM shared_keys WHERE id=$id"; cmd.Parameters.AddWithValue("$id", id);
        var encrypted = cmd.ExecuteScalar() as string ?? throw new ArgumentException("找不到指定的共享私钥。"); return Decrypt(encrypted);
    }

    public SharedKeySummary AddSharedKey(SharedKeyInput input)
    {
        var name = Required(input.Name, "密钥名称", 80); var privateKey = input.PrivateKey;
        var notes = Optional(input.Notes, 500);
        if (string.IsNullOrWhiteSpace(privateKey) || privateKey.Length > 65536 || (input.Passphrase?.Length ?? 0) > 4096) throw new ArgumentException("私钥为空或过长。");
        var meta = InspectPrivateKey(privateKey, input.Passphrase, name);
        var id = Guid.NewGuid().ToString("N");
        var now = DateTimeOffset.UtcNow.ToString("O");
        using var c = Open(); using var cmd = c.CreateCommand();
        cmd.CommandText = "INSERT INTO shared_keys(id,name,credential,created_at,algorithm,fingerprint,public_key,has_passphrase,notes,updated_at) VALUES($id,$name,$credential,$created,$alg,$fp,$pub,$hp,$notes,$updated)";
        cmd.Parameters.AddWithValue("$id", id);
        cmd.Parameters.AddWithValue("$name", name);
        cmd.Parameters.AddWithValue("$credential", Encrypt(new Credential(null, privateKey, input.Passphrase)));
        cmd.Parameters.AddWithValue("$created", now);
        cmd.Parameters.AddWithValue("$alg", meta.Algorithm);
        cmd.Parameters.AddWithValue("$fp", meta.Fingerprint);
        cmd.Parameters.AddWithValue("$pub", meta.PublicKey);
        cmd.Parameters.AddWithValue("$hp", meta.HasPassphrase ? 1 : 0);
        cmd.Parameters.AddWithValue("$notes", notes);
        cmd.Parameters.AddWithValue("$updated", now);
        try { cmd.ExecuteNonQuery(); } catch (SqliteException exception) when (exception.SqliteErrorCode == 19) { throw new ArgumentException("密钥名称已存在。"); }
        Audit("web", "-", "key.create", "success", name);
        return new(id, name, meta.Algorithm, meta.Fingerprint, meta.PublicKey, meta.HasPassphrase, notes, now, now, []);
    }

    public SharedKeySummary GenerateSharedKey(GenerateKeyInput input)
    {
        var name = Required(input.Name, "密钥名称", 80);
        var privateKey = GeneratePrivateKeyPem(input.Algorithm ?? "ed25519");
        return AddSharedKey(new SharedKeyInput(name, privateKey, null, input.Notes));
    }

    public SharedKeySummary UpdateSharedKey(string id, SharedKeyUpdateInput input)
    {
        var existing = GetSharedKeySummary(id);
        var name = Required(input.Name, "密钥名称", 80);
        var notes = Optional(input.Notes, 500);
        var now = DateTimeOffset.UtcNow.ToString("O");
        var rotating = !string.IsNullOrWhiteSpace(input.PrivateKey);
        using var c = Open();
        using var cmd = c.CreateCommand();
        if (rotating)
        {
            if (input.PrivateKey!.Length > 65536 || (input.Passphrase?.Length ?? 0) > 4096) throw new ArgumentException("私钥或口令过长。");
            var meta = InspectPrivateKey(input.PrivateKey, input.Passphrase, name);
            cmd.CommandText = "UPDATE shared_keys SET name=$name,credential=$cred,algorithm=$alg,fingerprint=$fp,public_key=$pub,has_passphrase=$hp,notes=$notes,updated_at=$at WHERE id=$id";
            cmd.Parameters.AddWithValue("$cred", Encrypt(new Credential(null, input.PrivateKey, input.Passphrase)));
            cmd.Parameters.AddWithValue("$alg", meta.Algorithm);
            cmd.Parameters.AddWithValue("$fp", meta.Fingerprint);
            cmd.Parameters.AddWithValue("$pub", meta.PublicKey);
            cmd.Parameters.AddWithValue("$hp", meta.HasPassphrase ? 1 : 0);
        }
        else
        {
            cmd.CommandText = "UPDATE shared_keys SET name=$name,notes=$notes,updated_at=$at WHERE id=$id";
        }
        cmd.Parameters.AddWithValue("$name", name);
        cmd.Parameters.AddWithValue("$notes", notes);
        cmd.Parameters.AddWithValue("$at", now);
        cmd.Parameters.AddWithValue("$id", existing.Id);
        try { cmd.ExecuteNonQuery(); } catch (SqliteException e) when (e.SqliteErrorCode == 19) { throw new ArgumentException("密钥名称已存在。"); }
        if (rotating) ServerChanged?.Invoke(existing.Id);
        Audit("web", "-", rotating ? "key.rotate" : "key.update", "success", name);
        return GetSharedKeySummary(existing.Id);
    }

    public void DeleteSharedKey(string id)
    {
        using var c = Open();
        using (var chk = c.CreateCommand())
        {
            chk.CommandText = "SELECT name FROM servers WHERE shared_key_id=$id ORDER BY name";
            chk.Parameters.AddWithValue("$id", id);
            var names = new List<string>();
            using var r = chk.ExecuteReader();
            while (r.Read()) names.Add(r.GetString(0));
            if (names.Count > 0)
            {
                var sample = string.Join("、", names.Take(3)) + (names.Count > 3 ? $" 等 {names.Count} 台" : "");
                throw new ArgumentException($"该密钥正被服务器（{sample}）使用，请先更换这些服务器的认证方式后再删除。");
            }
        }
        using var cmd = c.CreateCommand(); cmd.CommandText = "DELETE FROM shared_keys WHERE id=$id"; cmd.Parameters.AddWithValue("$id", id);
        if (cmd.ExecuteNonQuery() == 0) throw new ArgumentException("找不到指定的共享私钥。");
        Audit("web", "-", "key.delete", "success");
    }

    // --- MCP Tokens ---
    public List<McpTokenView> ListMcpTokens()
    {
        using var c = Open(); using var cmd = c.CreateCommand();
        cmd.CommandText = "SELECT id,name,prefix,read_only,allowed_tags,allowed_server_ids,expires_at,last_used_at,created_at,revoked FROM mcp_tokens ORDER BY created_at DESC";
        using var r = cmd.ExecuteReader(); var rows = new List<McpTokenView>();
        while (r.Read()) rows.Add(ReadMcpTokenView(r));
        return rows;
    }

    private static McpTokenView ReadMcpTokenView(SqliteDataReader r) => new(
        r.GetString(0), r.GetString(1), r.GetString(2), r.GetInt32(3) != 0, r.GetString(4),
        r.GetString(5).Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries).ToList(),
        r.IsDBNull(6) ? null : r.GetString(6), r.IsDBNull(7) ? null : r.GetString(7), r.GetString(8), r.GetInt32(9) != 0);

    public McpTokenCreatedResult CreateMcpToken(McpTokenInput input)
    {
        var name = Required(input.Name, "令牌名称", 80);
        if (input.ExpiresInDays is < 1 or > 3650) throw new ArgumentException("有效期应在 1–3650 天之间。");
        var tags = Optional(input.AllowedTags, 300);
        var serverIds = (input.AllowedServerIds ?? []).Where(s => !string.IsNullOrWhiteSpace(s)).Select(s => s.Trim()).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        var plainToken = "sp_" + WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(32));
        var prefix = plainToken[..12] + "…";
        var hash = HashToken(plainToken);
        var id = Guid.NewGuid().ToString("N");
        var now = DateTimeOffset.UtcNow;
        var createdAt = now.ToString("O");
        var expiresAt = input.ExpiresInDays.HasValue ? now.AddDays(input.ExpiresInDays.Value).ToString("O") : null;

        using var c = Open(); using var cmd = c.CreateCommand();
        cmd.CommandText = "INSERT INTO mcp_tokens(id,name,prefix,token_hash,read_only,allowed_tags,allowed_server_ids,expires_at,last_used_at,created_at,revoked) VALUES($id,$name,$prefix,$hash,$ro,$tags,$sids,$exp,NULL,$at,0)";
        cmd.Parameters.AddWithValue("$id", id);
        cmd.Parameters.AddWithValue("$name", name);
        cmd.Parameters.AddWithValue("$prefix", prefix);
        cmd.Parameters.AddWithValue("$hash", hash);
        cmd.Parameters.AddWithValue("$ro", input.ReadOnly ? 1 : 0);
        cmd.Parameters.AddWithValue("$tags", tags);
        cmd.Parameters.AddWithValue("$sids", string.Join(',', serverIds));
        cmd.Parameters.AddWithValue("$exp", expiresAt is null ? DBNull.Value : expiresAt);
        cmd.Parameters.AddWithValue("$at", createdAt);
        try { cmd.ExecuteNonQuery(); } catch (SqliteException e) when (e.SqliteErrorCode == 19) { throw new ArgumentException("令牌名称已存在。"); }
        Audit("web", "-", "mcp_token.create", "success", name);
        return new(new McpTokenView(id, name, prefix, input.ReadOnly, tags, serverIds, expiresAt, null, createdAt, false), plainToken);
    }

    public McpTokenView? AuthenticateMcpToken(string bearerToken)
    {
        if (string.IsNullOrWhiteSpace(bearerToken) || !bearerToken.StartsWith("sp_", StringComparison.Ordinal) || bearerToken.Length > 256)
            return null;
        var hash = HashToken(bearerToken);
        using var c = Open(); using var cmd = c.CreateCommand();
        cmd.CommandText = "SELECT id,name,prefix,read_only,allowed_tags,allowed_server_ids,expires_at,last_used_at,created_at,revoked FROM mcp_tokens WHERE token_hash=$hash";
        cmd.Parameters.AddWithValue("$hash", hash);
        using var r = cmd.ExecuteReader();
        if (!r.Read()) return null;
        var token = ReadMcpTokenView(r);
        r.Close();
        if (token.Revoked) return null;
        if (!string.IsNullOrEmpty(token.ExpiresAt) && DateTimeOffset.TryParse(token.ExpiresAt, out var exp) && exp < DateTimeOffset.UtcNow)
            return null;
        using var upd = c.CreateCommand();
        upd.CommandText = "UPDATE mcp_tokens SET last_used_at=$at WHERE id=$id";
        upd.Parameters.AddWithValue("$at", DateTimeOffset.UtcNow.ToString("O"));
        upd.Parameters.AddWithValue("$id", token.Id);
        upd.ExecuteNonQuery();
        return token;
    }

    public void RevokeMcpToken(string id)
    {
        using var c = Open(); using var cmd = c.CreateCommand();
        cmd.CommandText = "UPDATE mcp_tokens SET revoked=1 WHERE id=$id";
        cmd.Parameters.AddWithValue("$id", id);
        if (cmd.ExecuteNonQuery() == 0) throw new ArgumentException("找不到指定的 MCP 令牌。");
        Audit("web", "-", "mcp_token.revoke", "success");
    }

    public void DeleteMcpToken(string id)
    {
        using var c = Open(); using var cmd = c.CreateCommand();
        cmd.CommandText = "DELETE FROM mcp_tokens WHERE id=$id";
        cmd.Parameters.AddWithValue("$id", id);
        if (cmd.ExecuteNonQuery() == 0) throw new ArgumentException("找不到指定的 MCP 令牌。");
        Audit("web", "-", "mcp_token.delete", "success");
    }

    private static string HashToken(string token) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(token)));

    // --- Snippets ---
    public List<SnippetView> ListSnippets()
    {
        using var c = Open(); using var cmd = c.CreateCommand();
        cmd.CommandText = "SELECT id,name,category,command,description,updated_at FROM snippets ORDER BY category, name";
        using var r = cmd.ExecuteReader(); var rows = new List<SnippetView>();
        while (r.Read()) rows.Add(new(r.GetString(0), r.GetString(1), r.GetString(2), r.GetString(3), r.GetString(4), r.GetString(5)));
        return rows;
    }

    public SnippetView SaveSnippet(string? id, SnippetInput input)
    {
        var name = Required(input.Name, "片段名称", 80);
        var category = string.IsNullOrWhiteSpace(input.Category) ? "通用" : Optional(input.Category, 40);
        var command = Required(input.Command, "命令内容", 16384);
        var desc = Optional(input.Description, 300);
        id ??= Guid.NewGuid().ToString("N");
        var updated = DateTimeOffset.UtcNow.ToString("O");
        using var c = Open(); using var cmd = c.CreateCommand();
        cmd.CommandText = """
            INSERT INTO snippets(id,name,category,command,description,updated_at) VALUES($id,$name,$cat,$cmd,$desc,$at)
            ON CONFLICT(id) DO UPDATE SET name=$name,category=$cat,command=$cmd,description=$desc,updated_at=$at
            """;
        cmd.Parameters.AddWithValue("$id", id);
        cmd.Parameters.AddWithValue("$name", name);
        cmd.Parameters.AddWithValue("$cat", category);
        cmd.Parameters.AddWithValue("$cmd", command);
        cmd.Parameters.AddWithValue("$desc", desc);
        cmd.Parameters.AddWithValue("$at", updated);
        try { cmd.ExecuteNonQuery(); } catch (SqliteException e) when (e.SqliteErrorCode == 19) { throw new ArgumentException("片段名称已存在。"); }
        Audit("web", "-", "snippet.save", "success", name);
        return new(id, name, category, command, desc, updated);
    }

    public void DeleteSnippet(string id)
    {
        using var c = Open(); using var cmd = c.CreateCommand();
        cmd.CommandText = "DELETE FROM snippets WHERE id=$id";
        cmd.Parameters.AddWithValue("$id", id);
        if (cmd.ExecuteNonQuery() == 0) throw new ArgumentException("找不到指定的命令片段。");
        Audit("web", "-", "snippet.delete", "success");
    }

    // --- System Settings & Notifications ---
    private string? GetSetting(string key)
    {
        using var c = Open(); using var cmd = c.CreateCommand();
        cmd.CommandText = "SELECT value FROM settings WHERE key=$k";
        cmd.Parameters.AddWithValue("$k", key);
        return cmd.ExecuteScalar() as string;
    }

    private void SetSetting(string key, string value)
    {
        using var c = Open(); using var cmd = c.CreateCommand();
        cmd.CommandText = "INSERT OR REPLACE INTO settings(key,value,updated_at) VALUES($k,$v,$at)";
        cmd.Parameters.AddWithValue("$k", key);
        cmd.Parameters.AddWithValue("$v", value);
        cmd.Parameters.AddWithValue("$at", DateTimeOffset.UtcNow.ToString("O"));
        cmd.ExecuteNonQuery();
    }

    public bool GetAuditRecordDetails() => GetSetting("audit_record_details") == "1";
    public bool GetAllowAdminPasswordForMcp() => GetSetting("allow_admin_password_mcp") != "0";

    public NotificationConfig GetNotificationConfig()
    {
        var raw = GetSetting("notification_config_enc");
        if (string.IsNullOrWhiteSpace(raw))
            return new(false, "generic", "", "", "", true, true, true, false);
        try
        {
            var plain = DecryptRaw(raw);
            try { return JsonSerializer.Deserialize(plain, StorageJsonContext.Default.NotificationConfig) ?? new(false, "generic", "", "", "", true, true, true, false); }
            finally { CryptographicOperations.ZeroMemory(plain); }
        }
        catch { return new(false, "generic", "", "", "", true, true, true, false); }
    }

    public SystemSettingsView GetSystemSettings()
    {
        var n = GetNotificationConfig();
        return new(GetAuditRecordDetails(), GetAllowAdminPasswordForMcp(), MaskNotificationConfig(n));
    }

    public SystemSettingsView SaveSystemSettings(SystemSettingsInput input)
    {
        SetSetting("audit_record_details", input.AuditRecordDetails ? "1" : "0");
        SetSetting("allow_admin_password_mcp", input.AllowAdminPasswordForMcp ? "1" : "0");
        if (input.Notifications is not null)
        {
            var prev = GetNotificationConfig();
            var channel = (input.Notifications.Channel ?? "generic").Trim().ToLowerInvariant();
            if (channel is not ("generic" or "feishu" or "dingtalk" or "wecom" or "telegram"))
                throw new ArgumentException("通知渠道无效。");
            var webhookUrl = string.IsNullOrWhiteSpace(input.Notifications.WebhookUrl)
                ? (input.Notifications.WebhookUrl is null ? prev.WebhookUrl : "")
                : input.Notifications.WebhookUrl.Trim();
            if (webhookUrl == MaskUrl(prev.WebhookUrl) && !string.IsNullOrEmpty(prev.WebhookUrl))
                webhookUrl = prev.WebhookUrl;
            if (!string.IsNullOrEmpty(webhookUrl))
            {
                if (!Uri.TryCreate(webhookUrl, UriKind.Absolute, out var uri) || uri.Scheme is not ("http" or "https"))
                    throw new ArgumentException("Webhook 地址必须以 http:// 或 https:// 开头。");
            }
            var tgToken = string.IsNullOrWhiteSpace(input.Notifications.TelegramBotToken) ? prev.TelegramBotToken : input.Notifications.TelegramBotToken.Trim();
            var tgChatId = (input.Notifications.TelegramChatId ?? "").Trim();
            var next = new NotificationConfig(
                input.Notifications.Enabled, channel, webhookUrl, tgToken, tgChatId,
                input.Notifications.NotifyOnLogin, input.Notifications.NotifyOnPasswordChange,
                input.Notifications.NotifyOnServerAlert, input.Notifications.NotifyOnJobEvent);
            var plain = JsonSerializer.SerializeToUtf8Bytes(next, StorageJsonContext.Default.NotificationConfig);
            try { SetSetting("notification_config_enc", EncryptRaw(plain)); }
            finally { CryptographicOperations.ZeroMemory(plain); }
        }
        Audit("web", "-", "settings.update", "success");
        return GetSystemSettings();
    }

    private static NotificationConfigView MaskNotificationConfig(NotificationConfig c) => new(
        c.Enabled, c.Channel, MaskUrl(c.WebhookUrl), !string.IsNullOrEmpty(c.WebhookUrl),
        !string.IsNullOrEmpty(c.TelegramBotToken), c.TelegramChatId,
        c.NotifyOnLogin, c.NotifyOnPasswordChange, c.NotifyOnServerAlert, c.NotifyOnJobEvent);

    private static string MaskUrl(string url)
    {
        if (string.IsNullOrWhiteSpace(url)) return "";
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri)) return "***";
        var path = uri.AbsolutePath;
        var visible = path.Length > 12 ? path[..12] + "…" : path;
        return $"{uri.Scheme}://{uri.Authority}{visible}";
    }

    // --- OpenSSH ~/.ssh/config Parser ---
    public SshConfigParseResult ParseSshConfig(string configText)
    {
        if (string.IsNullOrWhiteSpace(configText) || configText.Length > 262144)
            throw new ArgumentException("SSH 配置内容为空或超过 256 KiB。");
        var existingNames = List().Select(s => s.Name).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var result = new List<ParsedSshHost>();
        string? currentName = null, hostName = null, user = null, identityFile = null, proxyJump = null;
        int port = 22;

        void Flush()
        {
            if (string.IsNullOrWhiteSpace(currentName)) return;
            var resolvedHost = string.IsNullOrWhiteSpace(hostName) ? currentName : hostName;
            result.Add(new ParsedSshHost(currentName, resolvedHost, port, string.IsNullOrWhiteSpace(user) ? "root" : user, identityFile, proxyJump, existingNames.Contains(currentName)));
        }

        foreach (var rawLine in configText.Split('\n'))
        {
            var line = rawLine.Trim();
            if (line.Length == 0 || line.StartsWith('#')) continue;
            var commentIx = line.IndexOf('#');
            if (commentIx > 0) line = line[..commentIx].Trim();
            var match = Regex.Match(line, @"^(\S+)[\s=]+(.+)$");
            if (!match.Success) continue;
            var key = match.Groups[1].Value.ToLowerInvariant();
            var val = match.Groups[2].Value.Trim().Trim('"');
            switch (key)
            {
                case "host":
                    Flush();
                    var firstToken = val.Split(' ', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault();
                    currentName = (firstToken is null || firstToken.Contains('*') || firstToken.Contains('?')) ? null : firstToken;
                    hostName = null; user = null; identityFile = null; proxyJump = null; port = 22;
                    break;
                case "hostname": if (currentName is not null) hostName = val; break;
                case "user": if (currentName is not null) user = val; break;
                case "port": if (currentName is not null && int.TryParse(val, out var p) && p is >= 1 and <= 65535) port = p; break;
                case "identityfile": if (currentName is not null && identityFile is null) identityFile = val; break;
                case "proxyjump": if (currentName is not null) proxyJump = val; break;
            }
        }
        Flush();
        return new(result);
    }

    // --- Encrypted Backup Export & Import ---
    public BackupEnvelope ExportBackup(string passphrase)
    {
        if (string.IsNullOrWhiteSpace(passphrase) || passphrase.Length is < 8 or > 1024)
            throw new ArgumentException("备份口令长度应在 8–1024 个字符之间。");

        var servers = new List<BackupServerRecord>();
        foreach (var view in List())
        {
            var stored = Get(view.Id);
            servers.Add(new(stored.View, stored.Credential));
        }

        var sharedKeys = new List<BackupSharedKeyRecord>();
        using (var c = Open())
        using (var cmd = c.CreateCommand())
        {
            cmd.CommandText = "SELECT id,name,credential,created_at,algorithm,fingerprint,public_key,has_passphrase,notes,updated_at FROM shared_keys ORDER BY name";
            using var r = cmd.ExecuteReader();
            while (r.Read())
                sharedKeys.Add(new(r.GetString(0), r.GetString(1), Decrypt(r.GetString(2)), r.GetString(3), r.GetString(4), r.GetString(5), r.GetString(6), r.GetInt32(7) != 0, r.GetString(8), r.GetString(9)));
        }

        var bundle = new BackupBundle(1, DateTimeOffset.UtcNow.ToString("O"), servers, sharedKeys, ListSnippets(), GetAuditRecordDetails(), GetAllowAdminPasswordForMcp());
        var plain = JsonSerializer.SerializeToUtf8Bytes(bundle, StorageJsonContext.Default.BackupBundle);
        var salt = RandomNumberGenerator.GetBytes(16);
        var nonce = RandomNumberGenerator.GetBytes(12);
        var tag = new byte[16];
        var cipher = new byte[plain.Length];
        var derivedKey = DeriveBackupKey(passphrase, salt);
        try
        {
            using var aes = new AesGcm(derivedKey, 16);
            aes.Encrypt(nonce, plain, cipher, tag);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plain);
            CryptographicOperations.ZeroMemory(derivedKey);
        }
        Audit("web", "-", "backup.export", "success");
        return new(1, DateTimeOffset.UtcNow.ToString("O"), Convert.ToBase64String(salt), Convert.ToBase64String(nonce), Convert.ToBase64String(tag), Convert.ToBase64String(cipher));
    }

    public BackupImportResult ImportBackup(string passphrase, string envelopeJson, bool overwriteExisting)
    {
        if (string.IsNullOrWhiteSpace(passphrase)) throw new ArgumentException("请输入备份口令。");
        if (string.IsNullOrWhiteSpace(envelopeJson) || envelopeJson.Length > 10 * 1024 * 1024)
            throw new ArgumentException("备份文件为空或过大。");

        BackupEnvelope envelope;
        try { envelope = JsonSerializer.Deserialize(envelopeJson, StorageJsonContext.Default.BackupEnvelope) ?? throw new ArgumentException("备份文件格式无效。"); }
        catch { throw new ArgumentException("备份文件 JSON 格式无效。"); }
        if (envelope.Version != 1) throw new ArgumentException("不支持的备份版本。");

        byte[] salt, nonce, tag, cipher;
        try
        {
            salt = Convert.FromBase64String(envelope.Salt);
            nonce = Convert.FromBase64String(envelope.Nonce);
            tag = Convert.FromBase64String(envelope.Tag);
            cipher = Convert.FromBase64String(envelope.Ciphertext);
        }
        catch { throw new ArgumentException("备份文件数据损坏。"); }

        var derivedKey = DeriveBackupKey(passphrase, salt);
        var plain = new byte[cipher.Length];
        BackupBundle bundle;
        try
        {
            using var aes = new AesGcm(derivedKey, 16);
            aes.Decrypt(nonce, cipher, tag, plain);
            bundle = JsonSerializer.Deserialize(plain, StorageJsonContext.Default.BackupBundle) ?? throw new ArgumentException("备份内容无效。");
        }
        catch (CryptographicException) { throw new ArgumentException("备份口令不正确或备份文件已损坏。"); }
        finally
        {
            CryptographicOperations.ZeroMemory(plain);
            CryptographicOperations.ZeroMemory(derivedKey);
        }

        int serversImported = 0, serversSkipped = 0, keysImported = 0, snippetsImported = 0;
        using var c = Open();
        using var tx = c.BeginTransaction();

        foreach (var k in bundle.SharedKeys)
        {
            using var cmd = c.CreateCommand(); cmd.Transaction = tx;
            cmd.CommandText = overwriteExisting
                ? "INSERT OR REPLACE INTO shared_keys(id,name,credential,created_at,algorithm,fingerprint,public_key,has_passphrase,notes,updated_at) VALUES($id,$name,$cred,$at,$alg,$fp,$pub,$hp,$notes,$upd)"
                : "INSERT OR IGNORE INTO shared_keys(id,name,credential,created_at,algorithm,fingerprint,public_key,has_passphrase,notes,updated_at) VALUES($id,$name,$cred,$at,$alg,$fp,$pub,$hp,$notes,$upd)";
            cmd.Parameters.AddWithValue("$id", k.Id);
            cmd.Parameters.AddWithValue("$name", k.Name);
            cmd.Parameters.AddWithValue("$cred", Encrypt(k.Credential));
            cmd.Parameters.AddWithValue("$at", k.CreatedAt);
            cmd.Parameters.AddWithValue("$alg", k.Algorithm ?? "");
            cmd.Parameters.AddWithValue("$fp", k.Fingerprint ?? "");
            cmd.Parameters.AddWithValue("$pub", k.PublicKey ?? "");
            cmd.Parameters.AddWithValue("$hp", k.HasPassphrase ? 1 : 0);
            cmd.Parameters.AddWithValue("$notes", k.Notes ?? "");
            cmd.Parameters.AddWithValue("$upd", string.IsNullOrEmpty(k.UpdatedAt) ? k.CreatedAt : k.UpdatedAt);
            keysImported += cmd.ExecuteNonQuery();
        }

        foreach (var sn in bundle.Snippets)
        {
            using var cmd = c.CreateCommand(); cmd.Transaction = tx;
            cmd.CommandText = overwriteExisting
                ? "INSERT OR REPLACE INTO snippets(id,name,category,command,description,updated_at) VALUES($id,$name,$cat,$cmd,$desc,$at)"
                : "INSERT OR IGNORE INTO snippets(id,name,category,command,description,updated_at) VALUES($id,$name,$cat,$cmd,$desc,$at)";
            cmd.Parameters.AddWithValue("$id", sn.Id);
            cmd.Parameters.AddWithValue("$name", sn.Name);
            cmd.Parameters.AddWithValue("$cat", sn.Category);
            cmd.Parameters.AddWithValue("$cmd", sn.Command);
            cmd.Parameters.AddWithValue("$desc", sn.Description);
            cmd.Parameters.AddWithValue("$at", sn.UpdatedAt);
            snippetsImported += cmd.ExecuteNonQuery();
        }

        foreach (var s in bundle.Servers)
        {
            var exists = false;
            using (var chk = c.CreateCommand())
            {
                chk.Transaction = tx;
                chk.CommandText = "SELECT COUNT(*) FROM servers WHERE id=$id OR name=$name COLLATE NOCASE";
                chk.Parameters.AddWithValue("$id", s.View.Id);
                chk.Parameters.AddWithValue("$name", s.View.Name);
                exists = (long)chk.ExecuteScalar()! > 0;
            }
            if (exists && !overwriteExisting) { serversSkipped++; continue; }
            using var cmd = c.CreateCommand(); cmd.Transaction = tx;
            cmd.CommandText = """
                INSERT OR REPLACE INTO servers (id,name,host,port,username,auth_type,host_fingerprint,tags,notes,credential,updated_at,use_service_key,try_keyboard,proxy,allowed_remote_paths,jump_server_id,shared_key_id,provider,region,expires_at,billing_cycle,renewal_price,traffic_limit_gb,traffic_reset_day)
                VALUES ($id,$name,$host,$port,$username,$auth,$fp,$tags,$notes,$cred,$at,$sk,$kb,$proxy,$allowed,$jump,$sharedKey,$provider,$region,$expiresAt,$billingCycle,$renewalPrice,$trafficLimit,$trafficReset)
                """;
            cmd.Parameters.AddWithValue("$id", s.View.Id);
            cmd.Parameters.AddWithValue("$name", s.View.Name);
            cmd.Parameters.AddWithValue("$host", s.View.Host);
            cmd.Parameters.AddWithValue("$port", s.View.Port);
            cmd.Parameters.AddWithValue("$username", s.View.Username);
            cmd.Parameters.AddWithValue("$auth", s.View.AuthType);
            cmd.Parameters.AddWithValue("$fp", s.View.HostFingerprint);
            cmd.Parameters.AddWithValue("$tags", s.View.Tags);
            cmd.Parameters.AddWithValue("$notes", s.View.Notes);
            cmd.Parameters.AddWithValue("$cred", Encrypt(string.IsNullOrEmpty(s.View.SharedKeyId) ? s.Credential : new Credential(null, null, null, s.Credential.ProxyUrl)));
            cmd.Parameters.AddWithValue("$at", s.View.UpdatedAt);
            cmd.Parameters.AddWithValue("$sk", s.View.UseServiceKey ? 1 : 0);
            cmd.Parameters.AddWithValue("$kb", s.View.TryKeyboard ? 1 : 0);
            cmd.Parameters.AddWithValue("$proxy", string.IsNullOrWhiteSpace(s.Credential.ProxyUrl) ? s.View.Proxy : MaskProxy(s.Credential.ProxyUrl));
            cmd.Parameters.AddWithValue("$allowed", s.View.AllowedRemotePaths);
            cmd.Parameters.AddWithValue("$jump", s.View.JumpServerId ?? "");
            cmd.Parameters.AddWithValue("$sharedKey", s.View.SharedKeyId ?? "");
            cmd.Parameters.AddWithValue("$provider", s.View.Provider ?? "");
            cmd.Parameters.AddWithValue("$region", s.View.Region ?? "");
            cmd.Parameters.AddWithValue("$expiresAt", s.View.ExpiresAt ?? "");
            cmd.Parameters.AddWithValue("$billingCycle", s.View.BillingCycle ?? "");
            cmd.Parameters.AddWithValue("$renewalPrice", s.View.RenewalPrice ?? "");
            cmd.Parameters.AddWithValue("$trafficLimit", (object?)s.View.TrafficLimitGb ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$trafficReset", (object?)s.View.TrafficResetDay ?? DBNull.Value);
            cmd.ExecuteNonQuery();
            serversImported++;
        }

        tx.Commit();
        SetSetting("audit_record_details", bundle.AuditRecordDetails ? "1" : "0");
        SetSetting("allow_admin_password_mcp", bundle.AllowAdminPasswordForMcp ? "1" : "0");
        foreach (var s in bundle.Servers) ServerChanged?.Invoke(s.View.Id);
        Audit("web", "-", "backup.import", "success", $"servers={serversImported},keys={keysImported},snippets={snippetsImported}");
        return new(serversImported, serversSkipped, keysImported, snippetsImported);
    }

    private static byte[] DeriveBackupKey(string passphrase, byte[] salt)
    {
        using var derive = new Rfc2898DeriveBytes(passphrase, salt, 150_000, HashAlgorithmName.SHA256);
        return derive.GetBytes(32);
    }

    // --- Encryption Helpers ---
    private string EncryptRaw(byte[] plain)
    {
        var nonce = RandomNumberGenerator.GetBytes(12); var tag = new byte[16]; var cipher = new byte[plain.Length];
        using var aes = new AesGcm(options.EncryptionKey, 16); aes.Encrypt(nonce, plain, cipher, tag);
        return Convert.ToBase64String(nonce.Concat(tag).Concat(cipher).ToArray());
    }

    private byte[] DecryptRaw(string text)
    {
        var data = Convert.FromBase64String(text); var plain = new byte[data.Length - 28];
        using var aes = new AesGcm(options.EncryptionKey, 16); aes.Decrypt(data.AsSpan(0, 12), data.AsSpan(28), data.AsSpan(12, 16), plain);
        return plain;
    }

    private string Encrypt(Credential value)
    {
        var plain = JsonSerializer.SerializeToUtf8Bytes(value, StorageJsonContext.Default.Credential);
        try { return EncryptRaw(plain); }
        finally { CryptographicOperations.ZeroMemory(plain); }
    }

    private Credential Decrypt(string text)
    {
        try
        {
            var plain = DecryptRaw(text);
            try { return JsonSerializer.Deserialize(plain, StorageJsonContext.Default.Credential) ?? throw new InvalidOperationException("无法读取凭据。"); }
            finally { CryptographicOperations.ZeroMemory(plain); }
        }
        catch (Exception e) when (e is CryptographicException or FormatException) { throw new InvalidOperationException("无法解密凭据，请确认加密密钥没有改变。"); }
    }

    private static string Required(string? v, string label, int max) => string.IsNullOrWhiteSpace(v) || v.Trim().Length > max ? throw new ArgumentException($"{label}不能为空且长度不能超过 {max}。") : v.Trim();
    private static string Optional(string? v, int max) => (v ?? "").Trim().Length > max ? throw new ArgumentException("输入内容过长。") : (v ?? "").Trim();

    public static void ValidateProxy(string proxy)
    {
        if (!Uri.TryCreate(proxy, UriKind.Absolute, out var uri) ||
            uri.Scheme is not ("socks4" or "socks5" or "http") ||
            string.IsNullOrWhiteSpace(uri.Host))
            throw new ArgumentException("代理应使用 socks5://、socks4:// 或 http:// 地址。HTTPS 代理请改用可用的 HTTP CONNECT 代理。");
        if (uri.Port is < 1 or > 65535) throw new ArgumentException("代理端口无效。");
        if (!string.IsNullOrEmpty(uri.AbsolutePath) && uri.AbsolutePath != "/") throw new ArgumentException("代理地址不应包含路径。");
    }

    public static string MaskProxy(string proxy)
    {
        if (string.IsNullOrWhiteSpace(proxy)) return "";
        if (!Uri.TryCreate(proxy, UriKind.Absolute, out var uri)) return proxy;
        if (string.IsNullOrEmpty(uri.UserInfo)) return $"{uri.Scheme}://{uri.Host}:{uri.Port}";
        var user = Uri.UnescapeDataString(uri.UserInfo.Split(':', 2)[0]);
        return $"{uri.Scheme}://{user}:***@{uri.Host}:{uri.Port}";
    }

    public static string NormalizeRemoteRoots(string? value)
    {
        var roots = (value ?? "").Split('\n', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries).Distinct(StringComparer.Ordinal).ToList();
        foreach (var root in roots)
            if (!root.StartsWith('/') || root.Length > 4096 || root.Contains('\0') || root.Contains("..", StringComparison.Ordinal))
                throw new ArgumentException("远端允许路径必须是 Linux 绝对路径，且不能包含 ..。每行一个。");
        return string.Join('\n', roots);
    }
}
