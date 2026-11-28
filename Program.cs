using System.Net.WebSockets;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.RateLimiting;
using ModelContextProtocol;
using ModelContextProtocol.AspNetCore;
using ServerPilot;

var useBaseDir = !File.Exists(Path.Combine(Directory.GetCurrentDirectory(), "appsettings.json"))
    && File.Exists(Path.Combine(AppContext.BaseDirectory, "appsettings.json"));
var builder = useBaseDir
    ? WebApplication.CreateBuilder(new WebApplicationOptions { Args = args, ContentRootPath = AppContext.BaseDirectory })
    : WebApplication.CreateBuilder(args);
builder.WebHost.ConfigureKestrel(o => o.Limits.MaxRequestBodySize = 513L * 1024 * 1024);
builder.Services.Configure<FormOptions>(o => o.MultipartBodyLengthLimit = 513L * 1024 * 1024);
builder.Services.ConfigureHttpJsonOptions(o =>
{
    o.SerializerOptions.TypeInfoResolverChain.Insert(0, ApiJsonContext.Default);
});
var hasExplicitUrls = !string.IsNullOrWhiteSpace(builder.Configuration["ASPNETCORE_URLS"])
    || !string.IsNullOrWhiteSpace(builder.Configuration["urls"])
    || builder.Configuration.GetSection("Kestrel:Endpoints").Exists();
if (!hasExplicitUrls)
{
    var host = (builder.Configuration["ServerPilot:Host"] ?? "*").Trim();
    if (string.IsNullOrEmpty(host)) host = "*";
    if (host.Contains(':') && !host.StartsWith('[')) host = $"[{host}]";
    var portText = builder.Configuration["ServerPilot:Port"];
    var port = 5080;
    if (!string.IsNullOrWhiteSpace(portText) && (!int.TryParse(portText, out port) || port is < 1 or > 65535))
        throw new InvalidOperationException("ServerPilot:Port 必须在 1–65535 之间。");
    builder.WebHost.UseUrls($"http://{host}:{port}");
}
var options = AppOptions.Load(builder.Configuration, builder.Environment.ContentRootPath);
Directory.CreateDirectory(options.DataDirectory);
Directory.CreateDirectory(options.StagingDirectory);
if (!OperatingSystem.IsWindows())
{
    File.SetUnixFileMode(options.DataDirectory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
    File.SetUnixFileMode(options.StagingDirectory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
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
builder.Services.AddSingleton<AdminPasswordStore>();
builder.Services.AddSingleton<ServerStore>();
builder.Services.AddSingleton<NotificationService>();
builder.Services.AddHostedService<AuditCleanupService>();
builder.Services.AddSingleton<SshOperations>();
builder.Services.AddSingleton<JobService>();
builder.Services.Configure<ForwardedHeadersOptions>(o =>
{
    o.ForwardedHeaders = ForwardedHeaders.XForwardedProto;
});
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme).AddCookie(o =>
{
    o.Cookie.Name = "serverpilot.session";
    o.Cookie.HttpOnly = true;
    o.Cookie.SameSite = SameSiteMode.Strict;
    o.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
    o.ExpireTimeSpan = TimeSpan.FromHours(8);
    o.SlidingExpiration = false;
    o.TicketDataFormat = new AesGcmTicketDataFormat(options.EncryptionKey);
    o.Events.OnRedirectToLogin = c => { c.Response.StatusCode = 401; return Task.CompletedTask; };
    o.Events.OnRedirectToAccessDenied = c => { c.Response.StatusCode = 403; return Task.CompletedTask; };
    o.Events.OnValidatePrincipal = async context =>
    {
        var passwords = context.HttpContext.RequestServices.GetRequiredService<AdminPasswordStore>();
        var version = passwords.Version;
        if (version is null || context.Principal?.FindFirst("password-version")?.Value != version)
        {
            context.RejectPrincipal();
            await context.HttpContext.SignOutAsync();
        }
    };
});
builder.Services.AddAuthorization();
builder.Services.AddRateLimiter(o => o.AddFixedWindowLimiter("login", l =>
{
    l.PermitLimit = 10; l.Window = TimeSpan.FromMinutes(1); l.QueueLimit = 0;
}));
var mcpJsonOptions = new JsonSerializerOptions(McpJsonUtilities.DefaultOptions);
mcpJsonOptions.TypeInfoResolverChain.Insert(0, ApiJsonContext.Default);
builder.Services.AddMcpServer().WithHttpTransport(o => o.SessionMode = HttpServerSessionMode.Stateless).WithTools<SshTools>(mcpJsonOptions);

var app = builder.Build();
app.Services.GetRequiredService<ServerStore>().Initialize();
var startupPasswords = app.Services.GetRequiredService<AdminPasswordStore>();
if (options.AutoGeneratedKey)
    app.Logger.LogInformation("未配置 SERVERPILOT_ENCRYPTION_KEY，已自动生成加密密钥并保存至数据目录。请妥善备份数据目录。");
if (!startupPasswords.IsConfigured)
    app.Logger.LogInformation("尚未设置管理员密码，请在浏览器打开管理后台完成首次密码设置。");

app.UseForwardedHeaders();
app.UseWebSockets(new WebSocketOptions { KeepAliveInterval = TimeSpan.FromSeconds(20) });
app.Use(async (ctx, next) =>
{
    ctx.Response.Headers.XContentTypeOptions = "nosniff";
    ctx.Response.Headers.XFrameOptions = "DENY";
    ctx.Response.Headers.ContentSecurityPolicy = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' ws: wss:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";
    ctx.Response.Headers.CacheControl = "no-store";
    if (!options.AllowedHosts.Contains("*", StringComparer.Ordinal) &&
        !options.AllowedHosts.Contains(ctx.Request.Host.Host, StringComparer.OrdinalIgnoreCase))
    { ctx.Response.StatusCode = 400; await ctx.Response.WriteAsync("Invalid Host header."); return; }
    if (ctx.Request.Headers.TryGetValue("Origin", out var origin) &&
        !string.Equals(origin.ToString(), $"{ctx.Request.Scheme}://{ctx.Request.Host}", StringComparison.OrdinalIgnoreCase))
    { ctx.Response.StatusCode = 403; return; }
    if (ctx.Request.Path.StartsWithSegments("/mcp"))
    {
        var auth = ctx.Request.Headers.Authorization.ToString();
        if (!auth.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        { ctx.Response.StatusCode = 401; ctx.Response.Headers.WWWAuthenticate = "Bearer"; return; }
        var rawToken = auth[7..].Trim();
        var store = ctx.RequestServices.GetRequiredService<ServerStore>();
        var passwords = ctx.RequestServices.GetRequiredService<AdminPasswordStore>();
        McpAuthContext? mcpAuth = null;
        if (rawToken.StartsWith("sp_", StringComparison.Ordinal))
        {
            var tokenView = store.AuthenticateMcpToken(rawToken);
            if (tokenView is not null) mcpAuth = McpAuthContext.FromToken(tokenView);
        }
        else if (store.GetAllowAdminPasswordForMcp() && passwords.Verify(rawToken))
        {
            mcpAuth = McpAuthContext.Admin;
        }
        if (mcpAuth is null)
        { ctx.Response.StatusCode = 401; ctx.Response.Headers.WWWAuthenticate = "Bearer"; return; }
        McpAuthContext.Current.Value = mcpAuth;
        try { await next(); }
        finally { McpAuthContext.Current.Value = null; }
        return;
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

app.MapPost("/api/setup", async Task<IResult> (PasswordSetupInput input, AdminPasswordStore passwords, ServerStore store, HttpContext ctx) =>
{
    var error = ValidatePassword(input.NewPassword, input.ConfirmPassword);
    if (error is not null) return TypedResults.BadRequest(new ErrorResponse(error));
    string? version;
    try { version = passwords.Initialize(input.NewPassword!); }
    catch (IOException) { return ServerError("密码保存失败，请检查数据目录权限。"); }
    catch (UnauthorizedAccessException) { return ServerError("密码保存失败，请检查数据目录权限。"); }
    if (version is null) return TypedResults.BadRequest(new ErrorResponse("管理员密码已设置，请直接登录。"));
    var identity = new ClaimsIdentity([new Claim(ClaimTypes.Name, "admin"), new Claim("password-version", version)], CookieAuthenticationDefaults.AuthenticationScheme);
    await ctx.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(identity));
    store.Audit("web", "-", "auth.setup", "success", null, null, null, ClientIp(ctx));
    return TypedResults.Ok(new OkResponse(true));
}).RequireRateLimiting("login");

app.MapPost("/api/login", async Task<IResult> (LoginInput input, AdminPasswordStore passwords, ServerStore store, NotificationService notifications, HttpContext ctx) =>
{
    if (!passwords.IsConfigured) return TypedResults.BadRequest(new ErrorResponse("尚未设置管理员密码，请先完成首次设置。"));
    var ip = ClientIp(ctx);
    var version = passwords.Authenticate(input.Password ?? "");
    if (version is null)
    {
        store.Audit("web", "-", "auth.login", "failed", null, null, null, ip);
        return TypedResults.Unauthorized();
    }
    var identity = new ClaimsIdentity([new Claim(ClaimTypes.Name, "admin"), new Claim("password-version", version)], CookieAuthenticationDefaults.AuthenticationScheme);
    await ctx.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(identity));
    store.Audit("web", "-", "auth.login", "success", null, null, null, ip);
    notifications.Fire("login", "ServerPilot 管理员登录", $"来源 IP：{ip}\n时间：{DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss}");
    return TypedResults.Ok(new OkResponse(true));
}).RequireRateLimiting("login");

app.MapGet("/api/session", (AdminPasswordStore passwords, HttpContext ctx) =>
    TypedResults.Ok(new SessionResponse(ctx.User.Identity?.IsAuthenticated == true, !passwords.IsConfigured)));
app.MapPost("/api/logout", async (HttpContext ctx) => { await ctx.SignOutAsync(); return TypedResults.Ok(); }).RequireAuthorization();

var api = app.MapGroup("/api").RequireAuthorization();

// --- Account & Settings ---
api.MapPost("/password", async Task<IResult> (PasswordChangeInput input, AdminPasswordStore passwords, ServerStore store, NotificationService notifications, HttpContext ctx) =>
{
    var error = ValidatePassword(input.NewPassword, input.ConfirmPassword);
    if (error is not null) return TypedResults.BadRequest(new ErrorResponse(error));
    try
    {
        if (!passwords.Change(input.CurrentPassword ?? "", input.NewPassword!)) return TypedResults.BadRequest(new ErrorResponse("当前密码不正确。"));
    }
    catch (IOException) { return ServerError("密码保存失败，请检查数据目录权限。"); }
    catch (UnauthorizedAccessException) { return ServerError("密码保存失败，请检查数据目录权限。"); }
    store.Audit("web", "-", "auth.password_change", "success", null, null, null, ClientIp(ctx));
    notifications.Fire("password", "ServerPilot 密码已修改", $"来源 IP：{ClientIp(ctx)}\n旧会话已失效。");
    await ctx.SignOutAsync();
    return TypedResults.Ok(new PasswordChangedResponse(true));
}).RequireRateLimiting("login");

api.MapGet("/settings", (ServerStore store) => TypedResults.Ok(store.GetSystemSettings()));
api.MapPut("/settings", (SystemSettingsInput input, ServerStore store) => Safe(() => TypedResults.Ok(store.SaveSystemSettings(input))));
api.MapPost("/notifications/test", async (NotificationService notifications, CancellationToken ct) => await SafeAsync(async () => TypedResults.Ok(await notifications.SendTestAsync(ct))));

// --- Backup Export / Import ---
api.MapPost("/backup/export", (BackupExportInput input, ServerStore store) => Safe(() => TypedResults.Ok(store.ExportBackup(input.Passphrase ?? ""))));
api.MapPost("/backup/import", (BackupImportInput input, ServerStore store) => Safe(() => TypedResults.Ok(store.ImportBackup(input.Passphrase ?? "", input.Payload ?? "", input.OverwriteExisting))));

// --- Servers, Snapshots, Import, Batch ---
api.MapGet("/servers", (ServerStore store) => TypedResults.Ok(store.List()));
api.MapPost("/servers/probe", async (ProbeInput input, SshOperations ssh) => await SafeAsync(async () => TypedResults.Ok(await ssh.Probe(input.Host, input.Port))));
api.MapPost("/servers/import-ssh-config", (SshConfigImportInput input, ServerStore store) => Safe(() => TypedResults.Ok(store.ParseSshConfig(input.ConfigText))));
api.MapGet("/servers/snapshots", (SshOperations ssh) => TypedResults.Ok(ssh.GetCachedSnapshots()));
api.MapPost("/servers/snapshots", async (SshOperations ssh, CancellationToken ct) => await SafeAsync(async () => TypedResults.Ok(await ssh.RefreshAllSnapshots("web", ct))));
api.MapPost("/servers/{id}/snapshot", async (string id, SshOperations ssh, CancellationToken ct) => await SafeAsync(async () => TypedResults.Ok(await ssh.GetSnapshot(id, "web", ct))));
api.MapPost("/servers/batch-execute", async (BatchExecuteInput input, ServerStore store, SshOperations ssh, CancellationToken ct) => await SafeAsync(async () =>
{
    var all = store.List();
    var targets = all;
    if (input.ServerIds is { Count: > 0 })
    {
        var set = input.ServerIds.ToHashSet(StringComparer.OrdinalIgnoreCase);
        targets = targets.Where(s => set.Contains(s.Id) || set.Contains(s.Name)).ToList();
    }
    if (!string.IsNullOrWhiteSpace(input.Tag))
    {
        var tag = input.Tag.Trim();
        targets = targets.Where(s => s.Tags.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries).Any(t => t.Equals(tag, StringComparison.OrdinalIgnoreCase))).ToList();
    }
    return TypedResults.Ok(await ssh.BatchExecute(targets, input.Command, input.TimeoutSeconds, "web", ct));
}));
api.MapPost("/servers", (ServerInput input, ServerStore store) => Safe(() => TypedResults.Ok(store.Save(null, input))));
api.MapPut("/servers/{id}", (string id, ServerInput input, ServerStore store) => Safe(() => TypedResults.Ok(store.Save(id, input))));
api.MapDelete("/servers/{id}", (string id, ServerStore store) => Safe(() => { store.Delete(id); return TypedResults.Ok(); }));
api.MapPost("/servers/{id}/test", async (string id, SshOperations ssh) => await SafeAsync(async () => TypedResults.Ok(await ssh.Test(id, "web"))));
api.MapPost("/servers/{id}/execute", async (string id, CommandInput input, SshOperations ssh, CancellationToken ct) => await SafeAsync(async () => TypedResults.Ok(await ssh.Execute(id, input.Command, input.TimeoutSeconds, "web", ct))));

// --- WebSSH Interactive Terminal (WebSocket) ---
api.MapGet("/servers/{id}/terminal", async (string id, SshOperations ssh, HttpContext ctx, int cols = 120, int rows = 32) =>
{
    if (!ctx.WebSockets.IsWebSocketRequest)
    {
        ctx.Response.StatusCode = 400;
        await ctx.Response.WriteAsync("WebSocket request required.");
        return;
    }
    using var ws = await ctx.WebSockets.AcceptWebSocketAsync();
    TerminalSession? session = null;
    try
    {
        session = await Task.Run(() => ssh.OpenTerminal(id, cols, rows, "web"), ctx.RequestAborted);
    }
    catch (Exception ex)
    {
        var msg = Encoding.UTF8.GetBytes($"\r\n\x1b[31m[连接失败] {Errors.Public(ex)}\x1b[0m\r\n");
        if (ws.State == WebSocketState.Open)
        {
            await ws.SendAsync(msg, WebSocketMessageType.Binary, true, CancellationToken.None);
            await ws.CloseAsync(WebSocketCloseStatus.NormalClosure, "Connect failed", CancellationToken.None);
        }
        return;
    }

    using (session)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ctx.RequestAborted);
        var sshToWs = Task.Run(async () =>
        {
            var buf = new byte[8192];
            try
            {
                while (!cts.IsCancellationRequested && ws.State == WebSocketState.Open)
                {
                    var n = await session.Stream.ReadAsync(buf, cts.Token);
                    if (n <= 0) break;
                    await ws.SendAsync(buf.AsMemory(0, n), WebSocketMessageType.Binary, true, cts.Token);
                }
            }
            catch { }
            finally { cts.Cancel(); }
        }, cts.Token);

        var wsToSsh = Task.Run(async () =>
        {
            var buf = new byte[8192];
            using var msgStream = new MemoryStream();
            try
            {
                while (!cts.IsCancellationRequested && ws.State == WebSocketState.Open)
                {
                    msgStream.SetLength(0);
                    WebSocketReceiveResult result;
                    do
                    {
                        result = await ws.ReceiveAsync(buf, cts.Token);
                        if (result.MessageType == WebSocketMessageType.Close) return;
                        if (result.Count > 0) msgStream.Write(buf, 0, result.Count);
                    } while (!result.EndOfMessage && msgStream.Length < 256 * 1024);

                    var data = msgStream.ToArray();
                    if (result.MessageType == WebSocketMessageType.Text)
                    {
                        try
                        {
                            var ctrl = JsonSerializer.Deserialize(data, ApiJsonContext.Default.TerminalControlMessage);
                            if (ctrl?.Type == "resize") session.Resize(ctrl.Cols, ctrl.Rows);
                        }
                        catch { }
                    }
                    else if (data.Length > 0)
                    {
                        await session.Stream.WriteAsync(data, cts.Token);
                        await session.Stream.FlushAsync(cts.Token);
                    }
                }
            }
            catch { }
            finally { cts.Cancel(); }
        }, cts.Token);

        await Task.WhenAny(sshToWs, wsToSsh);
        cts.Cancel();
        if (ws.State == WebSocketState.Open)
        {
            try { await ws.CloseAsync(WebSocketCloseStatus.NormalClosure, "Session ended", CancellationToken.None); } catch { }
        }
    }
});

// --- SFTP Visual File Browser & Patch ---
api.MapPost("/servers/{id}/sftp/list", async (string id, RemotePathInput input, SshOperations ssh) => await SafeAsync(async () => TypedResults.Ok(await ssh.ListDirectory(id, input.RemotePath, "web"))));
api.MapPost("/servers/{id}/sftp/mkdir", async (string id, RemotePathInput input, SshOperations ssh) => await SafeAsync(async () => TypedResults.Ok(await ssh.CreateDirectory(id, input.RemotePath, "web"))));
api.MapPost("/servers/{id}/sftp/rename", async (string id, RenameRemoteInput input, SshOperations ssh) => await SafeAsync(async () => TypedResults.Ok(await ssh.RenameRemote(id, input.OldPath, input.NewPath, "web"))));
api.MapPost("/servers/{id}/sftp/delete", async (string id, RemotePathInput input, SshOperations ssh) => await SafeAsync(async () => TypedResults.Ok(await ssh.DeleteRemote(id, input.RemotePath, "web"))));
api.MapPost("/servers/{id}/sftp/upload", async (string id, HttpRequest req, SshOperations ssh, CancellationToken ct) => await SafeAsync(async () =>
{
    if (!req.HasFormContentType) throw new ArgumentException("请选择文件。");
    var form = await req.ReadFormAsync(ct);
    var file = form.Files.GetFile("file") ?? throw new ArgumentException("请选择文件。");
    var dir = (form["directory"].ToString() ?? "/").Trim();
    if (!dir.StartsWith('/')) throw new ArgumentException("目标目录必须是绝对路径。");
    var overwrite = string.Equals(form["overwrite"].ToString(), "true", StringComparison.OrdinalIgnoreCase);
    var fileName = Path.GetFileName(file.FileName);
    if (string.IsNullOrWhiteSpace(fileName) || fileName.Contains('/') || fileName.Contains('\\'))
        throw new ArgumentException("文件名无效。");
    var remotePath = dir == "/" ? "/" + fileName : dir.TrimEnd('/') + "/" + fileName;
    await using var stream = file.OpenReadStream();
    return TypedResults.Ok(await ssh.DirectUpload(id, remotePath, stream, file.Length, overwrite, "web"));
})).DisableAntiforgery();
api.MapGet("/servers/{id}/sftp/download", (string id, string path, SshOperations ssh) => Safe(() =>
{
    var (stream, fileName) = ssh.DirectDownload(id, path, "web");
    return TypedResults.File(stream, "application/octet-stream", fileName);
}));
api.MapPost("/servers/{id}/patch-file", async (string id, PatchFileInput input, SshOperations ssh) => await SafeAsync(async () => TypedResults.Ok(await ssh.PatchFile(id, input.RemotePath, input.OldText, input.NewText, input.ReplaceAll, "web", input.ExpectedSha256))));

// --- Staging & File Transfer ---
api.MapGet("/files", (SshOperations ssh) => TypedResults.Ok(ssh.ListStaging()));
api.MapPost("/files", async (HttpRequest req, SshOperations ssh, CancellationToken ct) => await SafeAsync(async () =>
{
    if (!req.HasFormContentType) throw new ArgumentException("请选择文件。");
    var form = await req.ReadFormAsync(ct);
    var file = form.Files.GetFile("file") ?? throw new ArgumentException("请选择文件。");
    await using var stream = file.OpenReadStream();
    return TypedResults.Ok(await ssh.StageFile(file.FileName, stream, file.Length, ct));
})).DisableAntiforgery();
api.MapGet("/files/{name}", (string name, SshOperations ssh) => Safe(() => TypedResults.File(ssh.OpenStaged(name), "application/octet-stream", name)));
api.MapDelete("/files/{name}", (string name, SshOperations ssh) => Safe(() => { ssh.DeleteStaged(name); return TypedResults.Ok(); }));
api.MapPost("/servers/{id}/upload", async (string id, TransferInput input, SshOperations ssh) => await SafeAsync(async () => TypedResults.Ok(await ssh.Upload(id, input.StagingFile, input.RemotePath, "web"))));
api.MapPost("/servers/{id}/download", async (string id, TransferInput input, SshOperations ssh) => await SafeAsync(async () => TypedResults.Ok(await ssh.Download(id, input.RemotePath, input.StagingFile, "web"))));
api.MapPost("/servers/{id}/read-file", async (string id, ReadFileInput input, SshOperations ssh) => await SafeAsync(async () => TypedResults.Ok(await ssh.ReadFile(id, input.RemotePath, input.Offset, input.Length, "web"))));
api.MapPost("/servers/{id}/write-file", async (string id, WriteFileInput input, SshOperations ssh) => await SafeAsync(async () => TypedResults.Ok(await ssh.WriteFile(id, input.RemotePath, input.Content, input.Append, input.Mode, "web"))));

// --- Background Jobs ---
api.MapPost("/servers/{id}/jobs", (string id, JobInput input, JobService jobs) => Safe(() => TypedResults.Ok(jobs.Start(id, input.Command, input.TimeoutSeconds, "web-job"))));
api.MapGet("/servers/{id}/jobs", (string id, JobService jobs) => Safe(() => TypedResults.Ok(jobs.List(id, 50, "web-job"))));
api.MapGet("/servers/{id}/jobs/{jobId}", (string id, string jobId, JobService jobs, long? offset = null) => Safe(() => TypedResults.Ok(jobs.Status(id, jobId, offset, actor: "web-job"))));
api.MapPost("/servers/{id}/jobs/{jobId}/kill", (string id, string jobId, JobService jobs) => Safe(() => TypedResults.Ok(jobs.Kill(id, jobId, "web-job"))));
api.MapDelete("/servers/{id}/jobs/{jobId}", (string id, string jobId, JobService jobs) => Safe(() => TypedResults.Ok(jobs.Delete(id, jobId, "web-job"))));
api.MapPost("/servers/{id}/jobs/cleanup", (string id, JobCleanupInput input, JobService jobs) => Safe(() => TypedResults.Ok(jobs.Cleanup(id, input.OlderThanHours, "web-job"))));

// --- Shared Keys, Snippets, MCP Tokens, Audit ---
api.MapGet("/keys", (ServerStore store) => TypedResults.Ok(store.ListSharedKeys()));
api.MapPost("/keys", (SharedKeyInput input, ServerStore store) => Safe(() => TypedResults.Ok(store.AddSharedKey(input))));
api.MapPost("/keys/generate", (GenerateKeyInput input, ServerStore store) => Safe(() => TypedResults.Ok(store.GenerateSharedKey(input))));
api.MapPut("/keys/{id}", (string id, SharedKeyUpdateInput input, ServerStore store) => Safe(() => TypedResults.Ok(store.UpdateSharedKey(id, input))));
api.MapDelete("/keys/{id}", (string id, ServerStore store) => Safe(() => { store.DeleteSharedKey(id); return TypedResults.Ok(); }));
api.MapPost("/keys/{id}/deploy", async (string id, DeployKeyInput input, SshOperations ssh, CancellationToken ct) =>
    await SafeAsync(async () => TypedResults.Ok(await ssh.DeploySharedKey(id, input.ServerIds, input.BindAfterDeploy, "web", ct))));

api.MapGet("/snippets", (ServerStore store) => TypedResults.Ok(store.ListSnippets()));
api.MapPost("/snippets", (SnippetInput input, ServerStore store) => Safe(() => TypedResults.Ok(store.SaveSnippet(null, input))));
api.MapPut("/snippets/{id}", (string id, SnippetInput input, ServerStore store) => Safe(() => TypedResults.Ok(store.SaveSnippet(id, input))));
api.MapDelete("/snippets/{id}", (string id, ServerStore store) => Safe(() => { store.DeleteSnippet(id); return TypedResults.Ok(); }));

api.MapGet("/tokens", (ServerStore store) => TypedResults.Ok(store.ListMcpTokens()));
api.MapPost("/tokens", (McpTokenInput input, ServerStore store) => Safe(() => TypedResults.Ok(store.CreateMcpToken(input))));
api.MapPost("/tokens/{id}/revoke", (string id, ServerStore store) => Safe(() => { store.RevokeMcpToken(id); return TypedResults.Ok(new OkResponse(true)); }));
api.MapDelete("/tokens/{id}", (string id, ServerStore store) => Safe(() => { store.DeleteMcpToken(id); return TypedResults.Ok(new OkResponse(true)); }));

api.MapGet("/audit", (ServerStore store, int page = 1, int pageSize = 50, string? server = null, string? actor = null, string? result = null, string? q = null) =>
    Safe(() => TypedResults.Ok(store.AuditList(page, pageSize, server, actor, result, q))));
api.MapGet("/audit/export", (ServerStore store, string format = "json", string? server = null, string? actor = null, string? result = null, string? q = null) => Safe(() =>
{
    var rows = store.AuditExport(server, actor, result, q);
    if (string.Equals(format, "csv", StringComparison.OrdinalIgnoreCase))
    {
        var sb = new StringBuilder();
        sb.Append('\uFEFF').AppendLine("time,actor,server,action,result,exitCode,durationMs,clientIp,detail");
        foreach (var r in rows)
            sb.AppendLine($"{Csv(r.At)},{Csv(r.Actor)},{Csv(r.Server)},{Csv(r.Action)},{Csv(r.Result)},{r.ExitCode?.ToString() ?? ""},{r.DurationMs?.ToString() ?? ""},{Csv(r.ClientIp)},{Csv(r.Detail)}");
        return TypedResults.File(Encoding.UTF8.GetBytes(sb.ToString()), "text/csv; charset=utf-8", $"serverpilot-audit-{DateTime.UtcNow:yyyyMMdd}.csv");
    }
    var bytes = JsonSerializer.SerializeToUtf8Bytes(rows, ApiJsonContext.Default.ListAuditItem);
    return TypedResults.File(bytes, "application/json; charset=utf-8", $"serverpilot-audit-{DateTime.UtcNow:yyyyMMdd}.json");
}));

app.MapMcp("/mcp");
app.Run();

static string ClientIp(HttpContext ctx) => ctx.Connection.RemoteIpAddress?.ToString() ?? "";
static string Csv(string? v) => "\"" + (v ?? "").Replace("\"", "\"\"") + "\"";
static string? ValidatePassword(string? password, string? confirm)
{
    if (string.IsNullOrWhiteSpace(password) || password.Length is < 8 or > 1024) return "密码需要 8–1024 个字符，不能全为空格。";
    if (!Secrets.Equal(password, confirm ?? "")) return "两次输入的密码不一致。";
    if (password.Any(character => character < '!' || character > '~')) return "密码只能包含非空白的 ASCII 字符。";
    return null;
}
static IResult ServerError(string message) =>
    TypedResults.Content(JsonSerializer.Serialize(new ErrorResponse(message), ApiJsonContext.Default.ErrorResponse), "application/json; charset=utf-8", statusCode: 500);
static IResult Safe(Func<IResult> action)
{
    try { return action(); }
    catch (Exception e) { return TypedResults.BadRequest(new ErrorResponse(Errors.Public(e))); }
}
static async Task<IResult> SafeAsync(Func<Task<IResult>> action)
{
    try { return await action(); }
    catch (Exception e) { return TypedResults.BadRequest(new ErrorResponse(Errors.Public(e))); }
}

namespace ServerPilot
{
    public sealed class AuditCleanupService(ServerStore store, ILogger<AuditCleanupService> logger) : BackgroundService
    {
        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            using var timer = new PeriodicTimer(TimeSpan.FromHours(1));
            while (await timer.WaitForNextTickAsync(stoppingToken))
            {
                try { store.CleanupAudit(); }
                catch (Exception error) { logger.LogError(error, "清理过期操作记录失败。"); }
            }
        }
    }
    public sealed class AdminPasswordStore
    {
        private readonly string path;
        private string? salt;
        private string? hash;
        private readonly object gate = new();
        public AdminPasswordStore(AppOptions options)
        {
            path = Path.Combine(options.DataDirectory, "admin-password.json");
            if (File.Exists(path))
            {
                var saved = JsonSerializer.Deserialize(File.ReadAllText(path), StorageJsonContext.Default.PasswordFile);
                if (saved is null || string.IsNullOrWhiteSpace(saved.Salt) || string.IsNullOrWhiteSpace(saved.Hash)) throw new InvalidOperationException("管理员密码文件损坏。");
                salt = saved.Salt; hash = saved.Hash;
            }
            else if (!string.IsNullOrEmpty(options.AdminPassword))
            {
                salt = Convert.ToBase64String(RandomNumberGenerator.GetBytes(16));
                hash = Derive(options.AdminPassword, salt);
                Save(salt, hash);
            }
        }
        public bool IsConfigured { get { lock (gate) return salt is not null && hash is not null; } }
        public string? Version { get { lock (gate) return salt; } }
        public bool Verify(string value) => Authenticate(value) is not null;
        public string? Authenticate(string value)
        {
            if (value.Length > 1024) return null;
            lock (gate)
            {
                if (salt is null || hash is null) return null;
                return Secrets.Equal(hash, Derive(value, salt)) ? salt : null;
            }
        }
        public string? Initialize(string value)
        {
            lock (gate)
            {
                if (salt is not null || hash is not null) return null;
                var nextSalt = Convert.ToBase64String(RandomNumberGenerator.GetBytes(16));
                var nextHash = Derive(value, nextSalt);
                Save(nextSalt, nextHash);
                salt = nextSalt; hash = nextHash;
                return nextSalt;
            }
        }
        public bool Change(string current, string value)
        {
            lock (gate)
            {
                if (Authenticate(current) is null) return false;
                var nextSalt = Convert.ToBase64String(RandomNumberGenerator.GetBytes(16));
                var nextHash = Derive(value, nextSalt);
                Save(nextSalt, nextHash);
                salt = nextSalt; hash = nextHash;
                return true;
            }
        }
        private void Save(string savedSalt, string savedHash)
        {
            var temp = path + ".tmp";
            File.WriteAllText(temp, JsonSerializer.Serialize(new PasswordFile(savedSalt, savedHash), StorageJsonContext.Default.PasswordFile));
            if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(temp, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            File.Move(temp, path, true);
        }
        private static string Derive(string value, string salt)
        {
            using var derive = new Rfc2898DeriveBytes(value, Convert.FromBase64String(salt), 150_000, HashAlgorithmName.SHA256);
            return Convert.ToBase64String(derive.GetBytes(32));
        }
    }

    public sealed record AppOptions(string DataDirectory, string StagingDirectory, string? AdminPassword, byte[] EncryptionKey, string[] AllowedHosts,
        string? TwoFactorCode, string? ServiceKeyPath, string? ServiceKeyPassphrase, bool AutoGeneratedKey = false)
    {
        public static AppOptions Load(IConfiguration c, string root)
        {
            var dir = Path.GetFullPath(c["SERVERPILOT_DATA_DIR"] ?? c["ServerPilot:DataDir"] ?? Path.Combine(root, "data"));
            Directory.CreateDirectory(dir);
            if (!OperatingSystem.IsWindows())
                File.SetUnixFileMode(dir, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);

            var admin = c["SERVERPILOT_ADMIN_PASSWORD"] ?? c["ServerPilot:AdminPassword"];
            if (!string.IsNullOrEmpty(admin))
            {
                if (admin.Length < 8 || admin.Length > 1024 || admin.Any(character => character < '!' || character > '~'))
                    throw new InvalidOperationException("Set SERVERPILOT_ADMIN_PASSWORD to 8–1024 non-whitespace ASCII characters.");
            }
            else
            {
                admin = null;
            }

            var configuredKey = c["SERVERPILOT_ENCRYPTION_KEY"] ?? c["ServerPilot:EncryptionKey"];
            byte[] bytes;
            var autoGeneratedKey = false;
            if (!string.IsNullOrWhiteSpace(configuredKey))
            {
                try { bytes = Convert.FromBase64String(configuredKey.Trim()); }
                catch { throw new InvalidOperationException("SERVERPILOT_ENCRYPTION_KEY must be base64 for 32 random bytes."); }
                if (bytes.Length != 32) throw new InvalidOperationException("SERVERPILOT_ENCRYPTION_KEY must be base64 for 32 random bytes.");
            }
            else
            {
                var keyFilePath = Path.Combine(dir, ".encryption-key");
                if (File.Exists(keyFilePath))
                {
                    try { bytes = Convert.FromBase64String(File.ReadAllText(keyFilePath).Trim()); }
                    catch { throw new InvalidOperationException("数据目录中的 .encryption-key 文件格式损坏。"); }
                    if (bytes.Length != 32) throw new InvalidOperationException("数据目录中的 .encryption-key 文件长度无效。");
                }
                else
                {
                    var dbFile = new FileInfo(Path.Combine(dir, "serverpilot.db"));
                    var keyCheckFile = new FileInfo(Path.Combine(dir, ".keycheck"));
                    if (dbFile is { Exists: true, Length: > 0 } || keyCheckFile is { Exists: true, Length: > 0 })
                        throw new InvalidOperationException("检测到已有数据文件，但缺少加密密钥。请设置 SERVERPILOT_ENCRYPTION_KEY 或恢复数据目录中的 .encryption-key 文件。");
                    bytes = RandomNumberGenerator.GetBytes(32);
                    var tempKeyPath = keyFilePath + ".tmp";
                    File.WriteAllText(tempKeyPath, Convert.ToBase64String(bytes));
                    if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(tempKeyPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
                    File.Move(tempKeyPath, keyFilePath, true);
                    autoGeneratedKey = true;
                }
            }

            var allowedHostsRaw = new[] { c["SERVERPILOT_ALLOWED_HOSTS"], c["ServerPilot:AllowedHosts"], "*" }
                .First(value => !string.IsNullOrWhiteSpace(value))!;
            var hosts = allowedHostsRaw.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
            var twoFactor = c["SERVERPILOT_2FA_CODE"];
            if (!string.IsNullOrEmpty(twoFactor) && twoFactor.Length > 128) throw new InvalidOperationException("SERVERPILOT_2FA_CODE 过长。");
            var serviceKey = c["SERVERPILOT_SERVICE_KEY_PATH"] ?? c["SERVERPILOT_AGENT_KEY_PATH"];
            if (!string.IsNullOrWhiteSpace(serviceKey) && (!File.Exists(serviceKey) || serviceKey.Length > 2048))
                throw new InvalidOperationException("SERVERPILOT_SERVICE_KEY_PATH 指向的文件不存在。");
            var servicePassphrase = c["SERVERPILOT_SERVICE_KEY_PASSPHRASE"];
            if (!string.IsNullOrEmpty(servicePassphrase) && servicePassphrase.Length > 4096)
                throw new InvalidOperationException("SERVERPILOT_SERVICE_KEY_PASSPHRASE 过长。");
            return new(dir, Path.Combine(dir, "staging"), admin, bytes, hosts, string.IsNullOrWhiteSpace(twoFactor) ? null : twoFactor.Trim(),
                string.IsNullOrWhiteSpace(serviceKey) ? null : Path.GetFullPath(serviceKey), string.IsNullOrEmpty(servicePassphrase) ? null : servicePassphrase, autoGeneratedKey);
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
            System.Net.Sockets.SocketException se => $"网络连接失败（{se.SocketErrorCode}），请检查服务器地址、端口和网络。",
            _ => "操作失败。请检查连接、路径及文件权限。"
        };
    }
}
