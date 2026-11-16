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

    [McpServerTool(Name = "start_job"), Description("Start a non-interactive command in the MCP service background. Poll job_status. Jobs exist only while this service runs, have no live output, and time out after at most 1800 seconds.")]
    public static object StartJob(JobService jobs, [Description("Server ID or name")] string server, [Description("Remote command")] string command, [Description("Timeout in seconds, 1 to 1800")] int timeoutSeconds = 600) => GuardSync(() => jobs.Start(server, command, timeoutSeconds));

    [McpServerTool(Name = "job_status", ReadOnly = true), Description("Get the status and final output of a background job.")]
    public static object JobStatus(JobService jobs, string jobId) => GuardSync(() => jobs.Status(jobId));

    [McpServerTool(Name = "list_staged_files", ReadOnly = true), Description("List files in the server-side staging area; these files are on the MCP host, not the AI client's computer.")]
    public static object ListStagedFiles(SshOperations ssh) => ssh.ListStaging();

    [McpServerTool(Name = "upload_file"), Description("Upload one existing file from the MCP host's staging area to an absolute remote Linux path. Files up to 128 MiB. Does not overwrite by default.")]
    public static Task<object> UploadFile(SshOperations ssh, string server, [Description("Plain filename in staging, without any directory")] string stagingFile, [Description("Absolute destination path on the SSH server")] string remotePath, [Description("Set true to explicitly permit overwriting the remote file")] bool overwrite = false)
        => Guard(() => ssh.Upload(server, stagingFile, remotePath, "mcp", overwrite));

    [McpServerTool(Name = "download_file"), Description("Download a remote file into the MCP host's staging area. Existing staging files are never overwritten. Files up to 128 MiB.")]
    public static Task<object> DownloadFile(SshOperations ssh, string server, [Description("Absolute path on the SSH server")] string remotePath, [Description("New plain filename in staging")] string stagingFile)
        => Guard(() => ssh.Download(server, remotePath, stagingFile, "mcp"));

    private static async Task<T> Guard<T>(Func<Task<T>> call) { try { return await call(); } catch (Exception e) { throw new McpException(Errors.Public(e)); } }
    private static T GuardSync<T>(Func<T> call) { try { return call(); } catch (Exception e) { throw new McpException(Errors.Public(e)); } }
}
