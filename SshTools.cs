using System.ComponentModel;
using ModelContextProtocol;
using ModelContextProtocol.Server;

namespace ServerPilot;

public sealed record McpAuthContext(string Actor, bool ReadOnly, HashSet<string> AllowedTags, HashSet<string> AllowedServerIds)
{
    public static readonly AsyncLocal<McpAuthContext?> Current = new();

    public static McpAuthContext Admin => new("mcp:admin", false, new(StringComparer.OrdinalIgnoreCase), new(StringComparer.OrdinalIgnoreCase));

    public static McpAuthContext FromToken(McpTokenView token) => new(
        "mcp:" + token.Name,
        token.ReadOnly,
        token.AllowedTags.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries).ToHashSet(StringComparer.OrdinalIgnoreCase),
        token.AllowedServerIds.ToHashSet(StringComparer.OrdinalIgnoreCase));

    public bool CanAccessServer(ServerView server)
    {
        var hasTagScope = AllowedTags.Count > 0;
        var hasIdScope = AllowedServerIds.Count > 0;
        if (!hasTagScope && !hasIdScope) return true;
        if (hasIdScope && AllowedServerIds.Contains(server.Id)) return true;
        if (hasTagScope)
        {
            var serverTags = server.Tags.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
            if (serverTags.Any(t => AllowedTags.Contains(t))) return true;
        }
        return false;
    }
}

[McpServerToolType]
public sealed class SshTools
{
    private static McpAuthContext Auth => McpAuthContext.Current.Value ?? McpAuthContext.Admin;

    private static void RequireWrite()
    {
        if (Auth.ReadOnly) throw new McpException("当前 MCP 令牌为只读权限，禁止执行写入或命令修改操作。");
    }

    private static ServerView RequireServer(ServerStore store, string serverIdOrName)
    {
        var srv = store.Get(serverIdOrName).View;
        if (!Auth.CanAccessServer(srv))
            throw new McpException("当前 MCP 令牌无权访问该服务器。");
        return srv;
    }

    [McpServerTool(Name = "list_servers", ReadOnly = true), Description("List configured servers visible to the current MCP token. SSH credentials are never returned.")]
    public static List<ServerView> ListServers(ServerStore store) =>
        store.List().Where(s => Auth.CanAccessServer(s)).ToList();

    [McpServerTool(Name = "test_connection", ReadOnly = true), Description("Check SSH connectivity, latency and the pinned SSH host key for a configured server.")]
    public static Task<ConnectionTestResult> TestConnection(ServerStore store, SshOperations ssh, [Description("Server ID or name from list_servers")] string server)
        => Guard(() => { var s = RequireServer(store, server); return ssh.Test(s.Id, Auth.Actor); });

    [McpServerTool(Name = "server_snapshot", ReadOnly = true), Description("Collect structured health metrics for a server: OS, kernel, uptime, CPU, memory, swap, multi-mount disks, real-time network speed/traffic, load average, listening TCP ports, Docker and failed systemd services.")]
    public static Task<ServerSnapshot> ServerSnapshot(ServerStore store, SshOperations ssh, [Description("Server ID or name")] string server, CancellationToken cancellationToken = default)
        => Guard(() => { var s = RequireServer(store, server); return ssh.GetSnapshot(s.Id, Auth.Actor, cancellationToken); });

    [McpServerTool(Name = "tail_log", ReadOnly = true), Description("Read the last N lines of a remote UTF-8 text log file over SFTP (respects allowedRemotePaths). Safe for read-only inspection.")]
    public static Task<TailLogResult> TailLog(ServerStore store, SshOperations ssh, [Description("Server ID or name")] string server, [Description("Absolute path to the remote log file")] string remotePath, [Description("Number of trailing lines, 1 to 2000")] int lines = 100)
        => Guard(() => { var s = RequireServer(store, server); return ssh.TailLog(s.Id, remotePath, lines, Auth.Actor); });

    [McpServerTool(Name = "docker_status", ReadOnly = true), Description("List Docker containers (id, name, image, state, status, ports) in structured form without shell injection.")]
    public static Task<DockerStatusResult> DockerStatus(ServerStore store, SshOperations ssh, [Description("Server ID or name")] string server, [Description("Include stopped containers")] bool includeStopped = true, [Description("Optional container name filter")] string? filterName = null, CancellationToken cancellationToken = default)
        => Guard(() => { var s = RequireServer(store, server); return ssh.GetDockerStatus(s.Id, includeStopped, filterName, Auth.Actor, cancellationToken); });

    [McpServerTool(Name = "docker_logs", ReadOnly = true), Description("Fetch trailing logs of a specific Docker container without arbitrary shell execution.")]
    public static Task<DockerLogsResult> DockerLogs(ServerStore store, SshOperations ssh, [Description("Server ID or name")] string server, [Description("Container name or ID")] string container, [Description("Trailing lines, 1 to 2000")] int lines = 100, [Description("Optional relative duration like 10m, 2h, 1d")] string? since = null, CancellationToken cancellationToken = default)
        => Guard(() => { var s = RequireServer(store, server); return ssh.GetDockerLogs(s.Id, container, lines, since, Auth.Actor, cancellationToken); });

    [McpServerTool(Name = "service_status", ReadOnly = true), Description("List systemd service units (or inspect a specific unit) in structured form.")]
    public static Task<ServiceStatusResult> ServiceStatus(ServerStore store, SshOperations ssh, [Description("Server ID or name")] string server, [Description("Only return failed units when unit is omitted")] bool failedOnly = false, [Description("Optional specific systemd unit name, e.g. nginx or nginx.service")] string? unit = null, CancellationToken cancellationToken = default)
        => Guard(() => { var s = RequireServer(store, server); return ssh.GetServiceStatus(s.Id, failedOnly, unit, Auth.Actor, cancellationToken); });

    [McpServerTool(Name = "service_logs", ReadOnly = true), Description("Read recent journalctl logs for a specific systemd service unit.")]
    public static Task<ServiceLogsResult> ServiceLogs(ServerStore store, SshOperations ssh, [Description("Server ID or name")] string server, [Description("Systemd unit name, e.g. nginx or sshd")] string unit, [Description("Trailing lines, 1 to 2000")] int lines = 100, [Description("Optional relative duration like 30m, 2h, 1d")] string? since = null, CancellationToken cancellationToken = default)
        => Guard(() => { var s = RequireServer(store, server); return ssh.GetServiceLogs(s.Id, unit, lines, since, Auth.Actor, cancellationToken); });

    [McpServerTool(Name = "execute_command"), Description("Execute a non-interactive SSH command. Returns exit code, stdout and stderr. Maximum timeout is 1800 seconds.")]
    public static Task<CommandResult> ExecuteCommand(ServerStore store, SshOperations ssh, [Description("Server ID or name")] string server, [Description("Remote shell command")] string command, [Description("Timeout in seconds, 1 to 1800")] int timeoutSeconds = 60, CancellationToken cancellationToken = default)
        => Guard(() => { RequireWrite(); var s = RequireServer(store, server); return ssh.Execute(s.Id, command, timeoutSeconds, Auth.Actor, cancellationToken); });

    [McpServerTool(Name = "batch_execute"), Description("Execute one non-interactive command in parallel across multiple servers filtered by tag or server IDs/names.")]
    public static Task<BatchExecuteResult> BatchExecute(ServerStore store, SshOperations ssh,
        [Description("Remote shell command")] string command,
        [Description("Optional tag filter (matches servers having this tag)")] string? tag = null,
        [Description("Optional comma-separated server names or IDs")] string? servers = null,
        [Description("Timeout in seconds, 1 to 1800")] int timeoutSeconds = 60, CancellationToken cancellationToken = default)
        => Guard(() =>
        {
            RequireWrite();
            var visible = store.List().Where(s => Auth.CanAccessServer(s)).ToList();
            var targets = visible;
            if (!string.IsNullOrWhiteSpace(servers))
            {
                var wanted = servers.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries).ToHashSet(StringComparer.OrdinalIgnoreCase);
                targets = targets.Where(s => wanted.Contains(s.Id) || wanted.Contains(s.Name)).ToList();
            }
            if (!string.IsNullOrWhiteSpace(tag))
            {
                var t = tag.Trim();
                targets = targets.Where(s => s.Tags.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries).Any(x => x.Equals(t, StringComparison.OrdinalIgnoreCase))).ToList();
            }
            return ssh.BatchExecute(targets, command, timeoutSeconds, Auth.Actor, cancellationToken);
        });

    [McpServerTool(Name = "start_job"), Description("Start a long-running command in the background on the remote host and return a job id. State and output live under ~/.serverpilot-jobs.")]
    public static JobStartResult StartJob(ServerStore store, JobService jobs, [Description("Server ID or name")] string server, [Description("Remote command")] string command, [Description("Timeout in seconds, 1 to 86400")] int timeoutSeconds = 600)
        => GuardSync(() => { RequireWrite(); var s = RequireServer(store, server); return jobs.Start(s.Id, command, timeoutSeconds, Auth.Actor); });

    [McpServerTool(Name = "job_status", ReadOnly = true), Description("Show status (running/exited/killed/lost), exit code, total output size and output of a background job.")]
    public static JobStatusResult JobStatus(ServerStore store, JobService jobs, [Description("Server ID or name")] string server, [Description("Job id returned by start_job")] string jobId,
        [Description("Byte offset to read from; omit for the tail")] long? offset = null,
        [Description("Tail bytes when offset is omitted")] int tailBytes = 8192,
        [Description("Maximum bytes to return when offset is set")] int maxBytes = 65536)
        => GuardSync(() => { var s = RequireServer(store, server); return jobs.Status(s.Id, jobId, offset, tailBytes, maxBytes, Auth.Actor); });

    [McpServerTool(Name = "job_kill"), Description("Terminate a running background job safely by verifying process identity and signaling its process group.")]
    public static JobKillResult JobKill(ServerStore store, JobService jobs, [Description("Server ID or name")] string server, [Description("Job id")] string jobId)
        => GuardSync(() => { RequireWrite(); var s = RequireServer(store, server); return jobs.Kill(s.Id, jobId, Auth.Actor); });

    [McpServerTool(Name = "job_list", ReadOnly = true), Description("List recent background jobs stored on a remote server.")]
    public static JobListResult JobList(ServerStore store, JobService jobs, [Description("Server ID or name")] string server, [Description("Maximum jobs, 1-100")] int limit = 20)
        => GuardSync(() => { var s = RequireServer(store, server); return jobs.List(s.Id, limit, Auth.Actor); });

    [McpServerTool(Name = "job_cleanup"), Description("Remove completed background job directories older than the specified hours from ~/.serverpilot-jobs.")]
    public static JobCleanupResult JobCleanup(ServerStore store, JobService jobs, [Description("Server ID or name")] string server, [Description("Remove finished jobs older than N hours (0 = all finished)")] int olderThanHours = 24)
        => GuardSync(() => { RequireWrite(); var s = RequireServer(store, server); return jobs.Cleanup(s.Id, olderThanHours, Auth.Actor); });

    [McpServerTool(Name = "list_directory", ReadOnly = true), Description("List files and subdirectories in a remote directory over SFTP, respecting allowedRemotePaths.")]
    public static Task<DirectoryListResult> ListDirectory(ServerStore store, SshOperations ssh, [Description("Server ID or name")] string server, [Description("Absolute remote Linux directory path, e.g. /etc/nginx")] string remotePath = "/")
        => Guard(() => { var s = RequireServer(store, server); return ssh.ListDirectory(s.Id, remotePath, Auth.Actor); });

    [McpServerTool(Name = "list_staged_files", ReadOnly = true), Description("List files in the server-side staging area; these files are on the MCP host, not the AI client's computer.")]
    public static List<StagedFileInfo> ListStagedFiles(SshOperations ssh) => ssh.ListStaging();

    [McpServerTool(Name = "upload_file"), Description("Upload one existing file from the MCP host's staging area to an absolute remote Linux path. Files up to 512 MiB. Does not overwrite by default.")]
    public static Task<UploadResult> UploadFile(ServerStore store, SshOperations ssh, string server, [Description("Plain filename in staging, without any directory")] string stagingFile, [Description("Absolute destination path on the SSH server")] string remotePath, [Description("Set true to explicitly permit overwriting the remote file")] bool overwrite = false)
        => Guard(() => { RequireWrite(); var s = RequireServer(store, server); return ssh.Upload(s.Id, stagingFile, remotePath, Auth.Actor, overwrite); });

    [McpServerTool(Name = "download_file"), Description("Download a remote file into the MCP host's staging area. Existing staging files are never overwritten. Files up to 512 MiB.")]
    public static Task<DownloadResult> DownloadFile(ServerStore store, SshOperations ssh, string server, [Description("Absolute path on the SSH server")] string remotePath, [Description("New plain filename in staging")] string stagingFile)
        => Guard(() => { RequireWrite(); var s = RequireServer(store, server); return ssh.Download(s.Id, remotePath, stagingFile, Auth.Actor); });

    [McpServerTool(Name = "read_file", ReadOnly = true), Description("Read a UTF-8 text file over SFTP, paged by byte offset. Binary content is rejected; use download_file instead. Maximum 1 MiB per call.")]
    public static Task<TextReadResult> ReadFile(ServerStore store, SshOperations ssh, [Description("Server ID or name")] string server, [Description("Absolute path on the SSH server")] string remotePath,
        [Description("Byte offset, default 0")] long offset = 0, [Description("Maximum bytes to return, default 65536")] int length = 65536)
        => Guard(() => { var s = RequireServer(store, server); return ssh.ReadFile(s.Id, remotePath, offset, length, Auth.Actor); });

    [McpServerTool(Name = "write_file"), Description("Write UTF-8 text to a remote file over SFTP without shell quoting. Overwrites by default; append=true appends. Maximum 2 MiB per call.")]
    public static Task<WriteFileResult> WriteFile(ServerStore store, SshOperations ssh, [Description("Server ID or name")] string server, [Description("Absolute path on the SSH server")] string remotePath,
        [Description("Text content")] string content, [Description("Append instead of overwrite")] bool append = false, [Description("Optional POSIX mode for a newly created file, e.g. 420 for 0644")] int? mode = null)
        => Guard(() => { RequireWrite(); var s = RequireServer(store, server); return ssh.WriteFile(s.Id, remotePath, content, append, mode, Auth.Actor); });

    [McpServerTool(Name = "patch_file"), Description("Replace exact text inside a remote UTF-8 text file over SFTP without rewriting the entire file. Fails if oldText is not found, matches multiple locations unless replaceAll=true, or expectedSha256 mismatches.")]
    public static Task<PatchFileResult> PatchFile(ServerStore store, SshOperations ssh, [Description("Server ID or name")] string server, [Description("Absolute path on the SSH server")] string remotePath,
        [Description("Exact existing text to replace")] string oldText, [Description("Replacement text")] string newText, [Description("Replace all occurrences instead of requiring a unique match")] bool replaceAll = false, [Description("Optional SHA-256 hex from read_file to guard against concurrent edits")] string? expectedSha256 = null)
        => Guard(() => { RequireWrite(); var s = RequireServer(store, server); return ssh.PatchFile(s.Id, remotePath, oldText, newText, replaceAll, Auth.Actor, expectedSha256); });

    private static async Task<T> Guard<T>(Func<Task<T>> call) { try { return await call(); } catch (McpException) { throw; } catch (Exception e) { throw new McpException(Errors.Public(e)); } }
    private static T GuardSync<T>(Func<T> call) { try { return call(); } catch (McpException) { throw; } catch (Exception e) { throw new McpException(Errors.Public(e)); } }
}
