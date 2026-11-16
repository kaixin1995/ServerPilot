using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Data.Sqlite;

namespace ServerPilot;

public sealed record ServerInput(string? Name, string? Host, int Port, string? Username, string? AuthType, string? Password, string? PrivateKey, string? Passphrase, string? HostFingerprint, string? Tags, string? Notes);
public sealed record ServerView(string Id, string Name, string Host, int Port, string Username, string AuthType, string HostFingerprint, string Tags, string Notes, string UpdatedAt);
public sealed record Credential(string? Password, string? PrivateKey, string? Passphrase);
public sealed record StoredServer(ServerView View, Credential Credential);

public sealed class ServerStore(AppOptions options)
{
    private readonly string _connectionString = new SqliteConnectionStringBuilder { DataSource = Path.Combine(options.DataDirectory, "serverpilot.db"), Mode = SqliteOpenMode.ReadWriteCreate }.ToString();

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
                credential TEXT NOT NULL, updated_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS audit(
                id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT NOT NULL, actor TEXT NOT NULL,
                server_name TEXT NOT NULL, action TEXT NOT NULL, result TEXT NOT NULL);
            """;
        cmd.ExecuteNonQuery();
        if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(Path.Combine(options.DataDirectory, "serverpilot.db"), UnixFileMode.UserRead | UnixFileMode.UserWrite);
    }
    private static ServerView View(SqliteDataReader r) => new(r.GetString(0), r.GetString(1), r.GetString(2), r.GetInt32(3), r.GetString(4), r.GetString(5), r.GetString(6), r.GetString(7), r.GetString(8), r.GetString(9));
    public List<ServerView> List()
    {
        using var c = Open(); using var cmd = c.CreateCommand();
        cmd.CommandText = "SELECT id,name,host,port,username,auth_type,host_fingerprint,tags,notes,updated_at FROM servers ORDER BY name";
        using var r = cmd.ExecuteReader(); var rows = new List<ServerView>(); while (r.Read()) rows.Add(View(r)); return rows;
    }
    public StoredServer Get(string idOrName)
    {
        using var c = Open(); using var cmd = c.CreateCommand();
        cmd.CommandText = "SELECT id,name,host,port,username,auth_type,host_fingerprint,tags,notes,updated_at,credential FROM servers WHERE id=$id OR name=$id COLLATE NOCASE";
        cmd.Parameters.AddWithValue("$id", idOrName);
        using var r = cmd.ExecuteReader();
        if (!r.Read()) throw new ArgumentException("找不到指定服务器。请使用服务器 ID 或名称。");
        return new(View(r), Decrypt(r.GetString(10)));
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
        var sameAuth = previous?.View.AuthType == auth;
        var credential = auth == "password"
            ? new Credential(!string.IsNullOrEmpty(input.Password) ? input.Password : sameAuth ? previous?.Credential.Password : null, null, null)
            : new Credential(null, !string.IsNullOrWhiteSpace(input.PrivateKey) ? input.PrivateKey : sameAuth ? previous?.Credential.PrivateKey : null,
                !string.IsNullOrEmpty(input.PrivateKey) ? input.Passphrase : !string.IsNullOrEmpty(input.Passphrase) ? input.Passphrase : sameAuth ? previous?.Credential.Passphrase : null);
        if (auth == "password" && string.IsNullOrEmpty(credential.Password)) throw new ArgumentException("请输入 SSH 密码。");
        if (auth == "privateKey" && string.IsNullOrWhiteSpace(credential.PrivateKey)) throw new ArgumentException("请输入 SSH 私钥。");
        if ((credential.Password?.Length ?? 0) > 4096 || (credential.PrivateKey?.Length ?? 0) > 65536 || (credential.Passphrase?.Length ?? 0) > 4096) throw new ArgumentException("凭据过长。");
        id ??= Guid.NewGuid().ToString("N");
        var updated = DateTimeOffset.UtcNow.ToString("O");
        using var c = Open(); using var cmd = c.CreateCommand();
        cmd.CommandText = """
            INSERT INTO servers (id,name,host,port,username,auth_type,host_fingerprint,tags,notes,credential,updated_at)
            VALUES ($id,$name,$host,$port,$username,$auth,$fp,$tags,$notes,$credential,$updated)
            ON CONFLICT(id) DO UPDATE SET name=$name,host=$host,port=$port,username=$username,auth_type=$auth,
              host_fingerprint=$fp,tags=$tags,notes=$notes,credential=$credential,updated_at=$updated
            """;
        foreach (var (k,v) in new Dictionary<string, object> { ["$id"]=id, ["$name"]=name, ["$host"]=host, ["$port"]=input.Port, ["$username"]=username,
            ["$auth"]=auth, ["$fp"]=fingerprint, ["$tags"]=Optional(input.Tags, 300), ["$notes"]=Optional(input.Notes, 1000), ["$credential"]=Encrypt(credential), ["$updated"]=updated }) cmd.Parameters.AddWithValue(k,v);
        try { cmd.ExecuteNonQuery(); } catch (SqliteException e) when (e.SqliteErrorCode == 19) { throw new ArgumentException("服务器名称已存在。"); }
        Audit("web", name, previous is null ? "server.create" : "server.update", "success");
        return new(id, name, host, input.Port, username, auth, fingerprint, Optional(input.Tags, 300), Optional(input.Notes, 1000), updated);
    }
    public void Delete(string id)
    {
        var s = Get(id); using var c = Open(); using var cmd = c.CreateCommand(); cmd.CommandText = "DELETE FROM servers WHERE id=$id"; cmd.Parameters.AddWithValue("$id", s.View.Id); cmd.ExecuteNonQuery(); Audit("web", s.View.Name, "server.delete", "success");
    }
    public void Audit(string actor, string server, string action, string result)
    {
        using var c = Open(); using var cmd = c.CreateCommand();
        cmd.CommandText = "INSERT INTO audit(at,actor,server_name,action,result) VALUES ($at,$actor,$server,$action,$result)";
        cmd.Parameters.AddWithValue("$at", DateTimeOffset.UtcNow.ToString("O")); cmd.Parameters.AddWithValue("$actor", actor); cmd.Parameters.AddWithValue("$server", server);
        cmd.Parameters.AddWithValue("$action", action); cmd.Parameters.AddWithValue("$result", result); cmd.ExecuteNonQuery();
    }
    public List<object> AuditList()
    {
        using var c = Open(); using var cmd = c.CreateCommand(); cmd.CommandText = "SELECT at,actor,server_name,action,result FROM audit ORDER BY id DESC LIMIT 200";
        using var r = cmd.ExecuteReader(); var rows = new List<object>(); while (r.Read()) rows.Add(new { at=r.GetString(0), actor=r.GetString(1), server=r.GetString(2), action=r.GetString(3), result=r.GetString(4) }); return rows;
    }
    private string Encrypt(Credential value)
    {
        var plain = System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(value); var nonce = RandomNumberGenerator.GetBytes(12); var tag = new byte[16]; var cipher = new byte[plain.Length];
        using var aes = new AesGcm(options.EncryptionKey, 16); aes.Encrypt(nonce, plain, cipher, tag); CryptographicOperations.ZeroMemory(plain);
        return Convert.ToBase64String(nonce.Concat(tag).Concat(cipher).ToArray());
    }
    private Credential Decrypt(string text)
    {
        try
        {
            var data = Convert.FromBase64String(text); var plain = new byte[data.Length - 28];
            using var aes = new AesGcm(options.EncryptionKey, 16); aes.Decrypt(data.AsSpan(0,12), data.AsSpan(28), data.AsSpan(12,16), plain);
            try { return System.Text.Json.JsonSerializer.Deserialize<Credential>(plain) ?? throw new InvalidOperationException("无法读取凭据。"); }
            finally { CryptographicOperations.ZeroMemory(plain); }
        }
        catch (Exception e) when (e is CryptographicException or FormatException) { throw new InvalidOperationException("无法解密凭据，请确认加密密钥没有改变。"); }
    }
    private static string Required(string? v, string label, int max) => string.IsNullOrWhiteSpace(v) || v.Trim().Length > max ? throw new ArgumentException($"{label}不能为空且长度不能超过 {max}。") : v.Trim();
    private static string Optional(string? v, int max) => (v ?? "").Trim().Length > max ? throw new ArgumentException("输入内容过长。") : (v ?? "").Trim();
}
