using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.WebUtilities;

namespace ServerPilot;

// --- Auth & Account Inputs/Outputs ---
public sealed record LoginInput(string? Password);
public sealed record PasswordSetupInput(string? NewPassword, string? ConfirmPassword);
public sealed record PasswordChangeInput(string? CurrentPassword, string? NewPassword, string? ConfirmPassword);
public sealed record OkResponse(bool Ok);
public sealed record SessionResponse(bool Authenticated, bool NeedsSetup);
public sealed record PasswordChangedResponse(bool Changed);
public sealed record ErrorResponse(string Error);

// --- Server & SSH Inputs/Outputs ---
public sealed record CommandInput(string Command, int TimeoutSeconds = 60);
public sealed record TransferInput(string StagingFile, string RemotePath);
public sealed record ProbeInput(string Host, int Port);
public sealed record JobInput(string Command, int TimeoutSeconds = 600);
public sealed record ReadFileInput(string RemotePath, long Offset = 0, int Length = 65536);
public sealed record WriteFileInput(string RemotePath, string Content, bool Append = false, int? Mode = null);
public sealed record PatchFileInput(string RemotePath, string OldText, string NewText, bool ReplaceAll = false);
public sealed record RemotePathInput(string RemotePath);
public sealed record RenameRemoteInput(string OldPath, string NewPath);
public sealed record JobCleanupInput(int OlderThanHours = 24);
public sealed record BatchExecuteInput(List<string>? ServerIds, string? Tag, string Command, int TimeoutSeconds = 60);
public sealed record SshConfigImportInput(string ConfigText);

public sealed record ConnectionTestResult(bool Connected, string Server, long LatencyMs = 0);
public sealed record ProbeResult(string Fingerprint, string Algorithm, string Warning);
public sealed record StagedFileInfo(string Name, long Size, DateTime UpdatedAt);
public sealed record StagedFileResult(string Name, long Size);
public sealed record UploadResult(bool Uploaded, string StagingFile, string RemotePath, long Bytes);
public sealed record DownloadResult(bool Downloaded, string StagingFile, string RemotePath, long Bytes);
public sealed record WriteFileResult(bool Written, string RemotePath, int Bytes, bool Appended, bool Created, string? Permissions);
public sealed record PatchFileResult(bool Patched, string RemotePath, int Replacements, int Bytes);
public sealed record RemoteFileEntry(string Name, string FullPath, bool IsDirectory, bool IsSymlink, long Size, string Permissions, string ModifiedAt);
public sealed record DirectoryListResult(string Path, string? ParentPath, List<RemoteFileEntry> Entries);
public sealed record JobStartResult(string JobId, string Server, string Directory, string Status, string Note);
public sealed record JobStatusResult(string JobId, string Server, string Status, int? ExitCode, string? StartedAt, string? Command, string Output, long Offset, long TotalBytes, long? NextOffset);
public sealed record JobListItem(string JobId, string State, int? ExitCode, string StartedAt, string Command);
public sealed record JobListResult(string Server, List<JobListItem> Jobs);
public sealed record JobKillResult(bool Killed, string JobId, string Server, string Message);
public sealed record JobCleanupResult(string Server, int Removed, string Message);

public sealed record ServerSnapshot(
    string ServerId,
    string ServerName,
    bool Online,
    long LatencyMs,
    string CheckedAt,
    string? Hostname,
    string? OsName,
    string? Kernel,
    string? Uptime,
    int? CpuCores,
    double? CpuPercent,
    long? MemTotalMb,
    long? MemUsedMb,
    double? MemPercent,
    long? DiskTotalGb,
    long? DiskUsedGb,
    double? DiskPercent,
    string? LoadAverage,
    int? ListeningPortsCount,
    string? ListeningPorts,
    int? DockerRunning,
    int? DockerTotal,
    int? FailedServices,
    string? Error);

public sealed record BatchItemResult(string ServerId, string ServerName, bool Success, int? ExitCode, string? ExitSignal, string Stdout, string Stderr, bool OutputTruncated, long DurationMs, string? Error);
public sealed record BatchExecuteResult(string Command, int Total, int Succeeded, int Failed, List<BatchItemResult> Results);

public sealed record ParsedSshHost(string Name, string Host, int Port, string Username, string? IdentityFile, string? ProxyJump, bool AlreadyExists);
public sealed record SshConfigParseResult(List<ParsedSshHost> Hosts);

// --- Audit, Keys, Snippets, Tokens, Settings, Notifications, Backup ---
public sealed record AuditItem(string At, string Actor, string Server, string Action, string Result, string Detail, int? ExitCode, long? DurationMs, string ClientIp);
public sealed record AuditPageResult(List<AuditItem> Items, int Page, int PageSize, long Total, long TotalPages);
public sealed record SharedKeySummary(string Id, string Name, string CreatedAt);
public sealed record SharedKeyCreatedResult(string Id, string Name);

public sealed record SnippetInput(string? Name, string? Category, string? Command, string? Description);
public sealed record SnippetView(string Id, string Name, string Category, string Command, string Description, string UpdatedAt);

public sealed record McpTokenInput(string? Name, bool ReadOnly = false, string? AllowedTags = null, List<string>? AllowedServerIds = null, int? ExpiresInDays = null);
public sealed record McpTokenView(string Id, string Name, string Prefix, bool ReadOnly, string AllowedTags, List<string> AllowedServerIds, string? ExpiresAt, string? LastUsedAt, string CreatedAt, bool Revoked);
public sealed record McpTokenCreatedResult(McpTokenView Token, string PlainToken);

public sealed record NotificationConfig(
    bool Enabled,
    string Channel, // generic | feishu | dingtalk | wecom | telegram
    string WebhookUrl,
    string TelegramBotToken,
    string TelegramChatId,
    bool NotifyOnLogin,
    bool NotifyOnPasswordChange,
    bool NotifyOnServerAlert,
    bool NotifyOnJobEvent);

public sealed record NotificationConfigView(
    bool Enabled,
    string Channel,
    string WebhookUrlMasked,
    bool HasWebhookUrl,
    bool HasTelegramToken,
    string TelegramChatId,
    bool NotifyOnLogin,
    bool NotifyOnPasswordChange,
    bool NotifyOnServerAlert,
    bool NotifyOnJobEvent);

public sealed record SystemSettingsView(bool AuditRecordDetails, bool AllowAdminPasswordForMcp, NotificationConfigView Notifications);
public sealed record SystemSettingsInput(bool AuditRecordDetails, bool AllowAdminPasswordForMcp, NotificationConfigInput? Notifications);
public sealed record NotificationConfigInput(
    bool Enabled,
    string? Channel,
    string? WebhookUrl,
    string? TelegramBotToken,
    string? TelegramChatId,
    bool NotifyOnLogin,
    bool NotifyOnPasswordChange,
    bool NotifyOnServerAlert,
    bool NotifyOnJobEvent);
public sealed record NotificationTestResult(bool Sent, string Message);

public sealed record BackupExportInput(string? Passphrase);
public sealed record BackupImportInput(string? Passphrase, string? Payload, bool OverwriteExisting = false);
public sealed record BackupEnvelope(int Version, string CreatedAt, string Salt, string Nonce, string Tag, string Ciphertext);
public sealed record BackupServerRecord(ServerView View, Credential Credential);
public sealed record BackupSharedKeyRecord(string Id, string Name, Credential Credential, string CreatedAt);
public sealed record BackupBundle(int Version, string ExportedAt, List<BackupServerRecord> Servers, List<BackupSharedKeyRecord> SharedKeys, List<SnippetView> Snippets, bool AuditRecordDetails, bool AllowAdminPasswordForMcp);
public sealed record BackupImportResult(int ServersImported, int ServersSkipped, int SharedKeysImported, int SnippetsImported);

// --- WebSSH Control Message ---
public sealed record TerminalControlMessage(string? Type, int Cols, int Rows);

// --- Webhook Payloads (AOT-safe) ---
public sealed record GenericWebhookPayload(string Source, string Event, string Title, string Message, string Timestamp);
public sealed record FeishuWebhookPayload(string MsgType, FeishuWebhookContent Content);
public sealed record FeishuWebhookContent(string Text);
public sealed record DingTalkWebhookPayload(string Msgtype, DingTalkTextContent Text);
public sealed record DingTalkTextContent(string Content);
public sealed record WeComWebhookPayload(string Msgtype, WeComTextContent Text);
public sealed record WeComTextContent(string Content);
public sealed record TelegramSendPayload(string ChatId, string Text);

// --- Internal Storage Records ---
internal sealed record PasswordFile(string Salt, string Hash);

[JsonSourceGenerationOptions(PropertyNameCaseInsensitive = true)]
[JsonSerializable(typeof(PasswordFile))]
[JsonSerializable(typeof(Credential))]
[JsonSerializable(typeof(NotificationConfig))]
[JsonSerializable(typeof(BackupBundle))]
[JsonSerializable(typeof(BackupEnvelope))]
internal sealed partial class StorageJsonContext : JsonSerializerContext;

[JsonSourceGenerationOptions(JsonSerializerDefaults.Web)]
[JsonSerializable(typeof(string))]
[JsonSerializable(typeof(int))]
[JsonSerializable(typeof(int?))]
[JsonSerializable(typeof(long))]
[JsonSerializable(typeof(long?))]
[JsonSerializable(typeof(bool))]
[JsonSerializable(typeof(List<string>))]
[JsonSerializable(typeof(LoginInput))]
[JsonSerializable(typeof(PasswordSetupInput))]
[JsonSerializable(typeof(PasswordChangeInput))]
[JsonSerializable(typeof(CommandInput))]
[JsonSerializable(typeof(TransferInput))]
[JsonSerializable(typeof(ProbeInput))]
[JsonSerializable(typeof(JobInput))]
[JsonSerializable(typeof(ReadFileInput))]
[JsonSerializable(typeof(WriteFileInput))]
[JsonSerializable(typeof(PatchFileInput))]
[JsonSerializable(typeof(RemotePathInput))]
[JsonSerializable(typeof(RenameRemoteInput))]
[JsonSerializable(typeof(JobCleanupInput))]
[JsonSerializable(typeof(BatchExecuteInput))]
[JsonSerializable(typeof(SshConfigImportInput))]
[JsonSerializable(typeof(ServerInput))]
[JsonSerializable(typeof(SharedKeyInput))]
[JsonSerializable(typeof(SnippetInput))]
[JsonSerializable(typeof(McpTokenInput))]
[JsonSerializable(typeof(SystemSettingsInput))]
[JsonSerializable(typeof(NotificationConfigInput))]
[JsonSerializable(typeof(BackupExportInput))]
[JsonSerializable(typeof(BackupImportInput))]
[JsonSerializable(typeof(OkResponse))]
[JsonSerializable(typeof(SessionResponse))]
[JsonSerializable(typeof(PasswordChangedResponse))]
[JsonSerializable(typeof(ErrorResponse))]
[JsonSerializable(typeof(ServerView))]
[JsonSerializable(typeof(List<ServerView>))]
[JsonSerializable(typeof(AuditItem))]
[JsonSerializable(typeof(List<AuditItem>))]
[JsonSerializable(typeof(AuditPageResult))]
[JsonSerializable(typeof(SharedKeySummary))]
[JsonSerializable(typeof(List<SharedKeySummary>))]
[JsonSerializable(typeof(SharedKeyCreatedResult))]
[JsonSerializable(typeof(SnippetView))]
[JsonSerializable(typeof(List<SnippetView>))]
[JsonSerializable(typeof(McpTokenView))]
[JsonSerializable(typeof(List<McpTokenView>))]
[JsonSerializable(typeof(McpTokenCreatedResult))]
[JsonSerializable(typeof(SystemSettingsView))]
[JsonSerializable(typeof(NotificationConfigView))]
[JsonSerializable(typeof(NotificationTestResult))]
[JsonSerializable(typeof(BackupEnvelope))]
[JsonSerializable(typeof(BackupImportResult))]
[JsonSerializable(typeof(ConnectionTestResult))]
[JsonSerializable(typeof(ProbeResult))]
[JsonSerializable(typeof(CommandResult))]
[JsonSerializable(typeof(TextReadResult))]
[JsonSerializable(typeof(StagedFileInfo))]
[JsonSerializable(typeof(List<StagedFileInfo>))]
[JsonSerializable(typeof(StagedFileResult))]
[JsonSerializable(typeof(UploadResult))]
[JsonSerializable(typeof(DownloadResult))]
[JsonSerializable(typeof(WriteFileResult))]
[JsonSerializable(typeof(PatchFileResult))]
[JsonSerializable(typeof(RemoteFileEntry))]
[JsonSerializable(typeof(DirectoryListResult))]
[JsonSerializable(typeof(JobStartResult))]
[JsonSerializable(typeof(JobStatusResult))]
[JsonSerializable(typeof(JobListItem))]
[JsonSerializable(typeof(JobListResult))]
[JsonSerializable(typeof(JobKillResult))]
[JsonSerializable(typeof(JobCleanupResult))]
[JsonSerializable(typeof(ServerSnapshot))]
[JsonSerializable(typeof(List<ServerSnapshot>))]
[JsonSerializable(typeof(BatchItemResult))]
[JsonSerializable(typeof(BatchExecuteResult))]
[JsonSerializable(typeof(ParsedSshHost))]
[JsonSerializable(typeof(SshConfigParseResult))]
[JsonSerializable(typeof(TerminalControlMessage))]
[JsonSerializable(typeof(GenericWebhookPayload))]
[JsonSerializable(typeof(FeishuWebhookPayload))]
[JsonSerializable(typeof(DingTalkWebhookPayload))]
[JsonSerializable(typeof(WeComWebhookPayload))]
[JsonSerializable(typeof(TelegramSendPayload))]
internal sealed partial class ApiJsonContext : JsonSerializerContext;

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.SnakeCaseLower)]
[JsonSerializable(typeof(FeishuWebhookPayload))]
[JsonSerializable(typeof(TelegramSendPayload))]
internal sealed partial class SnakeCaseJsonContext : JsonSerializerContext;

public sealed class AesGcmTicketDataFormat : ISecureDataFormat<AuthenticationTicket>
{
    private static readonly byte[] AssociatedData = "serverpilot.session.v1"u8.ToArray();
    private readonly byte[] key;

    public AesGcmTicketDataFormat(byte[] masterEncryptionKey)
    {
        key = HMACSHA256.HashData(masterEncryptionKey, "ServerPilot-cookie-ticket-v1"u8);
    }

    public string Protect(AuthenticationTicket data) => Protect(data, null);

    public string Protect(AuthenticationTicket data, string? purpose)
    {
        var plain = TicketSerializer.Default.Serialize(data);
        var payload = new byte[12 + 16 + plain.Length];
        var nonce = payload.AsSpan(0, 12);
        var tag = payload.AsSpan(12, 16);
        var cipher = payload.AsSpan(28);
        RandomNumberGenerator.Fill(nonce);
        try
        {
            using var aes = new AesGcm(key, 16);
            aes.Encrypt(nonce, plain, cipher, tag, AssociatedData);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plain);
        }
        return WebEncoders.Base64UrlEncode(payload);
    }

    public AuthenticationTicket? Unprotect(string? protectedText) => Unprotect(protectedText, null);

    public AuthenticationTicket? Unprotect(string? protectedText, string? purpose)
    {
        if (string.IsNullOrEmpty(protectedText)) return null;
        try
        {
            var payload = WebEncoders.Base64UrlDecode(protectedText);
            if (payload.Length < 29) return null;
            var plain = new byte[payload.Length - 28];
            try
            {
                using var aes = new AesGcm(key, 16);
                aes.Decrypt(payload.AsSpan(0, 12), payload.AsSpan(28), payload.AsSpan(12, 16), plain, AssociatedData);
                return TicketSerializer.Default.Deserialize(plain);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(plain);
            }
        }
        catch
        {
            return null;
        }
    }
}
