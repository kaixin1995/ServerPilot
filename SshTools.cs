using System.ComponentModel;
using ModelContextProtocol;
using ModelContextProtocol.Server;

namespace ServerPilot;

[McpServerToolType]
public sealed class SshTools
{
    [McpServerTool(Name = "list_servers", ReadOnly = true), Description("List configured servers with name, host, port, username and tags. SSH credentials are never returned.")]
    public static object ListServers(ServerStore store) => store.List();

    [McpServerTool(Name = "test_connection", ReadOnly = true), Description("Check SSH connectivity and the pinned SSH host key for a configured server.")]
    public static Task<object> TestConnection(SshOperations ssh, [Description("Server ID or name from list_servers")] string server) => Guard(() => ssh.Test(server, "mcp"));

    [McpServerTool(Name = "execute_command"), Description("Execute a non-interactive SSH command. Returns exit code, stdout and stderr; output may contain sensitive information. No command allowlist is applied. Maximum timeout is 1800 seconds.")]
    public static Task<CommandResult> ExecuteCommand(SshOperations ssh, [Description("Server ID or name")] string server, [Description("Remote shell command")] string command, [Description("Timeout in seconds, 1 to 1800")] int timeoutSeconds = 60, CancellationToken cancellationToken = default)
        => Guard(() => ssh.Execute(server, command, timeoutSeconds, "mcp", cancellationToken));

    [McpServerTool(Name = "start_job"), Description("Start a long-running command in the background on the remote host and return a job id. State and output live under ~/.serverpilot-jobs, so they survive MCP restarts. Use job_status, job_kill and job_list.")]
    public static object StartJob(JobService jobs, [Description("Server ID or name")] string server, [Description("Remote command")] string command, [Description("Timeout in seconds, 1 to 86400")] int timeoutSeconds = 600) => GuardSync(() => jobs.Start(server, command, timeoutSeconds));

    [McpServerTool(Name = "job_status", ReadOnly = true), Description("Show status (running/exited/lost), exit code, total output size and output of a background job. Without offset it returns the tail; with offset it returns only newer bytes.")]
    public static object JobStatus(JobService jobs, [Description("Server ID or name")] string server, [Description("Job id returned by start_job")] string jobId,
        [Description("Byte offset to read from; omit for the tail")] long? offset = null,
        [Description("Tail bytes when offset is omitted")] int tailBytes = 8192,
        [Description("Maximum bytes to return when offset is set")] int maxBytes = 65536) => GuardSync(() => jobs.Status(server, jobId, offset, tailBytes, maxBytes));

    [McpServerTool(Name = "job_kill"), Description("Currently unavailable pending remote process identity verification.")]
    public static object JobKill(JobService jobs, [Description("Server ID or name")] string server, [Description("Job id")] string jobId) => GuardSync(() => jobs.Kill(server, jobId));

    [McpServerTool(Name = "job_list", ReadOnly = true), Description("List recent background jobs stored on a remote server.")]
    public static object JobList(JobService jobs, [Description("Server ID or name")] string server, [Description("Maximum jobs, 1-100")] int limit = 20) => GuardSync(() => jobs.List(server, limit));

    [McpServerTool(Name = "list_staged_files", ReadOnly = true), Description("List files in the server-side staging area; these files are on the MCP host, not the AI client's computer.")]
    public static object ListStagedFiles(SshOperations ssh) => ssh.ListStaging();

    [McpServerTool(Name = "upload_file"), Description("Upload one existing file from the MCP host's staging area to an absolute remote Linux path. Files up to 512 MiB. Does not overwrite by default.")]
    public static Task<object> UploadFile(SshOperations ssh, string server, [Description("Plain filename in staging, without any directory")] string stagingFile, [Description("Absolute destination path on the SSH server")] string remotePath, [Description("Set true to explicitly permit overwriting the remote file")] bool overwrite = false)
        => Guard(() => ssh.Upload(server, stagingFile, remotePath, "mcp", overwrite));

    [McpServerTool(Name = "download_file"), Description("Download a remote file into the MCP host's staging area. Existing staging files are never overwritten. Files up to 512 MiB.")]
    public static Task<object> DownloadFile(SshOperations ssh, string server, [Description("Absolute path on the SSH server")] string remotePath, [Description("New plain filename in staging")] string stagingFile)
        => Guard(() => ssh.Download(server, remotePath, stagingFile, "mcp"));

    [McpServerTool(Name = "read_file", ReadOnly = true), Description("Read a UTF-8 text file over SFTP, paged by byte offset. Binary content is rejected; use download_file instead. Maximum 1 MiB per call.")]
    public static Task<TextReadResult> ReadFile(SshOperations ssh, [Description("Server ID or name")] string server, [Description("Absolute path on the SSH server")] string remotePath,
        [Description("Byte offset, default 0")] long offset = 0, [Description("Maximum bytes to return, default 65536")] int length = 65536)
        => Guard(() => ssh.ReadFile(server, remotePath, offset, length, "mcp"));

    [McpServerTool(Name = "write_file"), Description("Write UTF-8 text to a remote file over SFTP without shell quoting. Overwrites by default; append=true appends. Maximum 2 MiB per call.")]
    public static Task<object> WriteFile(SshOperations ssh, [Description("Server ID or name")] string server, [Description("Absolute path on the SSH server")] string remotePath,
        [Description("Text content")] string content, [Description("Append instead of overwrite")] bool append = false, [Description("Optional POSIX mode for a newly created file, e.g. 420 for 0644")] int? mode = null)
        => Guard(() => ssh.WriteFile(server, remotePath, content, append, mode, "mcp"));

    private static async Task<T> Guard<T>(Func<Task<T>> call) { try { return await call(); } catch (Exception e) { throw new McpException(Errors.Public(e)); } }
    private static T GuardSync<T>(Func<T> call) { try { return call(); } catch (Exception e) { throw new McpException(Errors.Public(e)); } }
}
