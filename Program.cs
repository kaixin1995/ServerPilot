using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.RateLimiting;
using ModelContextProtocol.AspNetCore;
using ServerPilot;

var builder = WebApplication.CreateBuilder(args);
builder.WebHost.ConfigureKestrel(o => o.Limits.MaxRequestBodySize = 129L * 1024 * 1024);
builder.Services.Configure<FormOptions>(o => o.MultipartBodyLengthLimit = 129L * 1024 * 1024);
if (string.IsNullOrWhiteSpace(builder.Configuration["ASPNETCORE_URLS"]))
    builder.WebHost.UseUrls("http://127.0.0.1:5080");
var options = AppOptions.Load(builder.Configuration, builder.Environment.ContentRootPath);
Directory.CreateDirectory(options.DataDirectory);
Directory.CreateDirectory(options.StagingDirectory);
Directory.CreateDirectory(Path.Combine(options.DataDirectory, "cookie-keys"));
if (!OperatingSystem.IsWindows())
{
    File.SetUnixFileMode(options.DataDirectory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
    File.SetUnixFileMode(options.StagingDirectory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
    File.SetUnixFileMode(Path.Combine(options.DataDirectory, "cookie-keys"), UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
}
var keyCheckPath = Path.Combine(options.DataDirectory, ".keycheck");
var existingDb = new FileInfo(Path.Combine(options.DataDirectory, "serverpilot.db"));
if (!File.Exists(keyCheckPath) && existingDb is { Exists: true, Length: > 0 })
    throw new InvalidOperationException("Missing .keycheck for existing data; restore it together with the database and encryption key.");
using (var keyCheck = new FileStream(keyCheckPath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None))
{
    var expected = HMACSHA256.HashData(options.EncryptionKey, Encoding.UTF8.GetBytes("ServerPilot-key-check-v1"));
    if (keyCheck.Length == 0)
    {
        if (existingDb is { Exists: true, Length: > 0 })
            throw new InvalidOperationException("Missing .keycheck for existing data; restore it together with the database and encryption key.");
        keyCheck.Write(expected); keyCheck.Flush(true);
        if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(keyCheck.Name, UnixFileMode.UserRead | UnixFileMode.UserWrite);
    }
    else
    {
        var actual = new byte[32]; var count = keyCheck.Read(actual);
        if (count != 32 || keyCheck.Length != 32 || !CryptographicOperations.FixedTimeEquals(expected, actual))
            throw new InvalidOperationException("The encryption key does not match this data directory.");
    }
}
builder.Services.AddSingleton(options);
builder.Services.AddSingleton<ServerStore>();
builder.Services.AddSingleton<SshOperations>();
builder.Services.AddSingleton<JobService>();
builder.Services.Configure<ForwardedHeadersOptions>(o =>
{
    o.ForwardedHeaders = ForwardedHeaders.XForwardedProto;
    // Built-in trusted proxies/networks include only loopback. Do not clear those restrictions.
});
builder.Services.AddDataProtection().SetApplicationName("ServerPilot").PersistKeysToFileSystem(new DirectoryInfo(Path.Combine(options.DataDirectory, "cookie-keys")));
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme).AddCookie(o =>
{
    o.Cookie.Name = "serverpilot.session";
    o.Cookie.HttpOnly = true;
    o.Cookie.SameSite = SameSiteMode.Strict;
    o.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
    o.ExpireTimeSpan = TimeSpan.FromHours(8);
    o.SlidingExpiration = false;
    o.Events.OnRedirectToLogin = c => { c.Response.StatusCode = 401; return Task.CompletedTask; };
    o.Events.OnRedirectToAccessDenied = c => { c.Response.StatusCode = 403; return Task.CompletedTask; };
});
builder.Services.AddAuthorization();
builder.Services.AddRateLimiter(o => o.AddFixedWindowLimiter("login", l =>
{
    l.PermitLimit = 10; l.Window = TimeSpan.FromMinutes(1); l.QueueLimit = 0;
}));
builder.Services.AddMcpServer().WithHttpTransport(o => o.SessionMode = HttpServerSessionMode.Stateless).WithTools<SshTools>();

var app = builder.Build();
app.Services.GetRequiredService<ServerStore>().Initialize();
app.UseForwardedHeaders();
app.Use(async (ctx, next) =>
{
    ctx.Response.Headers.XContentTypeOptions = "nosniff";
    ctx.Response.Headers.XFrameOptions = "DENY";
    ctx.Response.Headers.ContentSecurityPolicy = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";
    ctx.Response.Headers.CacheControl = "no-store";
    // Defend local HTTP against DNS rebinding. Extra hosts require a trusted HTTPS proxy.
    if (!options.AllowedHosts.Contains(ctx.Request.Host.Host, StringComparer.OrdinalIgnoreCase))
    { ctx.Response.StatusCode = 400; await ctx.Response.WriteAsync("Invalid Host header."); return; }
    if (ctx.Request.Headers.TryGetValue("Origin", out var origin) &&
        !string.Equals(origin.ToString(), $"{ctx.Request.Scheme}://{ctx.Request.Host}", StringComparison.OrdinalIgnoreCase))
    { ctx.Response.StatusCode = 403; return; }
    if (ctx.Request.Path.StartsWithSegments("/mcp"))
    {
        var auth = ctx.Request.Headers.Authorization.ToString();
        if (!auth.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase) || !Secrets.Equal(auth[7..], options.McpToken))
        { ctx.Response.StatusCode = 401; ctx.Response.Headers.WWWAuthenticate = "Bearer"; return; }
    }
    else if (ctx.Request.Path.StartsWithSegments("/api") && !HttpMethods.IsGet(ctx.Request.Method))
    {
        if (ctx.Request.Headers["X-ServerPilot"].ToString() != "1") { ctx.Response.StatusCode = 403; return; }
    }
    await next();
});
app.UseRateLimiter();
app.UseAuthentication();
app.UseAuthorization();
app.UseDefaultFiles();
app.UseStaticFiles();

app.MapPost("/api/login", async (LoginInput input, HttpContext ctx) =>
{
    if (!Secrets.Equal(input.Password ?? "", options.AdminPassword)) return Results.Unauthorized();
    var identity = new ClaimsIdentity([new Claim(ClaimTypes.Name, "admin")], CookieAuthenticationDefaults.AuthenticationScheme);
    await ctx.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(identity));
    return Results.Ok(new { ok = true });
}).RequireRateLimiting("login");
app.MapGet("/api/session", (HttpContext ctx) => Results.Ok(new { authenticated = ctx.User.Identity?.IsAuthenticated == true }));
app.MapPost("/api/logout", async (HttpContext ctx) => { await ctx.SignOutAsync(); return Results.Ok(); }).RequireAuthorization();

var api = app.MapGroup("/api").RequireAuthorization();
api.MapGet("/servers", (ServerStore store) => Results.Ok(store.List()));
api.MapPost("/servers/probe", async (ProbeInput input, SshOperations ssh) => await SafeAsync(async () => Results.Ok(await ssh.Probe(input.Host, input.Port))));
api.MapPost("/servers", (ServerInput input, ServerStore store) => Safe(() => Results.Ok(store.Save(null, input))));
api.MapPut("/servers/{id}", (string id, ServerInput input, ServerStore store) => Safe(() => Results.Ok(store.Save(id, input))));
api.MapDelete("/servers/{id}", (string id, ServerStore store) => Safe(() => { store.Delete(id); return Results.Ok(); }));
api.MapPost("/servers/{id}/test", async (string id, SshOperations ssh) => await SafeAsync(async () => Results.Ok(await ssh.Test(id, "web"))));
api.MapPost("/servers/{id}/execute", async (string id, CommandInput input, SshOperations ssh, CancellationToken ct) => await SafeAsync(async () => Results.Ok(await ssh.Execute(id, input.Command, input.TimeoutSeconds, "web", ct))));
api.MapGet("/audit", (ServerStore store) => Results.Ok(store.AuditList()));
api.MapGet("/files", (SshOperations ssh) => Results.Ok(ssh.ListStaging()));
api.MapPost("/files", async (HttpRequest req, SshOperations ssh, CancellationToken ct) => await SafeAsync(async () =>
{
    if (!req.HasFormContentType) throw new ArgumentException("请选择文件。");
    var form = await req.ReadFormAsync(ct);
    var file = form.Files.GetFile("file") ?? throw new ArgumentException("请选择文件。");
    await using var stream = file.OpenReadStream();
    return Results.Ok(await ssh.StageFile(file.FileName, stream, file.Length, ct));
})).DisableAntiforgery();
api.MapGet("/files/{name}", (string name, SshOperations ssh) => Safe(() => Results.File(ssh.OpenStaged(name), "application/octet-stream", name)));
api.MapDelete("/files/{name}", (string name, SshOperations ssh) => Safe(() => { ssh.DeleteStaged(name); return Results.Ok(); }));
api.MapPost("/servers/{id}/upload", async (string id, TransferInput input, SshOperations ssh) => await SafeAsync(async () => Results.Ok(await ssh.Upload(id, input.StagingFile, input.RemotePath, "web"))));
api.MapPost("/servers/{id}/download", async (string id, TransferInput input, SshOperations ssh) => await SafeAsync(async () => Results.Ok(await ssh.Download(id, input.RemotePath, input.StagingFile, "web"))));
app.MapMcp("/mcp");
app.Run();

static IResult Safe(Func<IResult> action)
{
    try { return action(); }
    catch (Exception e) { return Results.BadRequest(new { error = Errors.Public(e) }); }
}
static async Task<IResult> SafeAsync(Func<Task<IResult>> action)
{
    try { return await action(); }
    catch (Exception e) { return Results.BadRequest(new { error = Errors.Public(e) }); }
}
record LoginInput(string? Password);
record CommandInput(string Command, int TimeoutSeconds = 60);
record TransferInput(string StagingFile, string RemotePath);
record ProbeInput(string Host, int Port);

namespace ServerPilot
{
    public sealed record AppOptions(string DataDirectory, string StagingDirectory, string AdminPassword, string McpToken, byte[] EncryptionKey, string[] AllowedHosts)
    {
        public static AppOptions Load(IConfiguration c, string root)
        {
            var admin = c["SERVERPILOT_ADMIN_PASSWORD"] ?? "";
            var token = c["SERVERPILOT_MCP_TOKEN"] ?? "";
            var key = c["SERVERPILOT_ENCRYPTION_KEY"] ?? "";
            if (admin.Length < 16 || token.Length < 32 || Secrets.Equal(admin, token))
                throw new InvalidOperationException("Set distinct SERVERPILOT_ADMIN_PASSWORD (at least 16 characters) and SERVERPILOT_MCP_TOKEN (at least 32 characters).");
            byte[] bytes;
            try { bytes = Convert.FromBase64String(key); } catch { throw new InvalidOperationException("SERVERPILOT_ENCRYPTION_KEY must be base64 for 32 random bytes."); }
            if (bytes.Length != 32) throw new InvalidOperationException("SERVERPILOT_ENCRYPTION_KEY must be base64 for 32 random bytes.");
            var dir = Path.GetFullPath(c["SERVERPILOT_DATA_DIR"] ?? Path.Combine(root, "data"));
            var hosts = (c["SERVERPILOT_ALLOWED_HOSTS"] ?? "localhost,127.0.0.1,::1").Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
            return new(dir, Path.Combine(dir, "staging"), admin, token, bytes, hosts);
        }
    }
    public static class Secrets
    {
        public static bool Equal(string a, string b) => CryptographicOperations.FixedTimeEquals(SHA256.HashData(Encoding.UTF8.GetBytes(a)), SHA256.HashData(Encoding.UTF8.GetBytes(b)));
    }
    public static class Errors
    {
        public static string Public(Exception e) => e switch
        {
            ArgumentException or InvalidOperationException or FileNotFoundException => e.Message,
            TimeoutException or OperationCanceledException => "操作超时或已取消；远程命令可能仍在运行。",
            Renci.SshNet.Common.SshAuthenticationException => "SSH 认证失败，请检查用户名和凭据。",
            Renci.SshNet.Common.SshException => "SSH 连接失败：请检查网络、主机指纹和 SSH 配置。",
            _ => "操作失败。请检查连接、路径及文件权限。"
        };
    }
}
