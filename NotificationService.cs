using System.Text;
using System.Text.Json;

namespace ServerPilot;

public sealed class NotificationService(ServerStore store, ILogger<NotificationService> logger) : IDisposable
{
    private readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(10) };

    public void Fire(string eventType, string title, string message)
    {
        _ = Task.Run(async () =>
        {
            try { await SendIfEnabledAsync(eventType, title, message); }
            catch (Exception ex) { logger.LogWarning("发送通知失败 ({Event}): {Type}", eventType, ex.GetType().Name); }
        });
    }

    public async Task<NotificationTestResult> SendTestAsync(CancellationToken ct = default)
    {
        var cfg = store.GetNotificationConfig();
        if (cfg.Channel == "telegram")
        {
            if (string.IsNullOrWhiteSpace(cfg.TelegramBotToken) || string.IsNullOrWhiteSpace(cfg.TelegramChatId))
                throw new ArgumentException("请先填写 Telegram Bot Token 和 Chat ID 并保存。");
        }
        else if (string.IsNullOrWhiteSpace(cfg.WebhookUrl))
        {
            throw new ArgumentException("请先填写 Webhook 地址并保存。");
        }
        await DispatchAsync(cfg, "test", "ServerPilot 通知测试", $"这是一条来自 ServerPilot 的测试通知（{DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss}）。", ct);
        return new(true, "测试通知已发送。");
    }

    private async Task SendIfEnabledAsync(string eventType, string title, string message)
    {
        var cfg = store.GetNotificationConfig();
        if (!cfg.Enabled) return;
        var shouldSend = eventType switch
        {
            "login" => cfg.NotifyOnLogin,
            "password" => cfg.NotifyOnPasswordChange,
            "alert" => cfg.NotifyOnServerAlert,
            "job" => cfg.NotifyOnJobEvent,
            _ => true
        };
        if (!shouldSend) return;
        await DispatchAsync(cfg, eventType, title, message, CancellationToken.None);
    }

    private async Task DispatchAsync(NotificationConfig cfg, string eventType, string title, string message, CancellationToken ct)
    {
        string url;
        string json;
        var combined = $"[{title}]\n{message}";

        switch (cfg.Channel)
        {
            case "feishu":
                url = cfg.WebhookUrl;
                json = JsonSerializer.Serialize(new FeishuWebhookPayload("text", new FeishuWebhookContent(combined)), SnakeCaseJsonContext.Default.FeishuWebhookPayload);
                break;
            case "dingtalk":
                url = cfg.WebhookUrl;
                json = JsonSerializer.Serialize(new DingTalkWebhookPayload("text", new DingTalkTextContent(combined)), ApiJsonContext.Default.DingTalkWebhookPayload);
                break;
            case "wecom":
                url = cfg.WebhookUrl;
                json = JsonSerializer.Serialize(new WeComWebhookPayload("text", new WeComTextContent(combined)), ApiJsonContext.Default.WeComWebhookPayload);
                break;
            case "telegram":
                url = $"https://api.telegram.org/bot{cfg.TelegramBotToken}/sendMessage";
                json = JsonSerializer.Serialize(new TelegramSendPayload(cfg.TelegramChatId, combined), SnakeCaseJsonContext.Default.TelegramSendPayload);
                break;
            default:
                url = cfg.WebhookUrl;
                json = JsonSerializer.Serialize(new GenericWebhookPayload("ServerPilot", eventType, title, message, DateTimeOffset.UtcNow.ToString("O")), ApiJsonContext.Default.GenericWebhookPayload);
                break;
        }

        if (string.IsNullOrWhiteSpace(url)) return;
        using var content = new StringContent(json, Encoding.UTF8, "application/json");
        using var resp = await _http.PostAsync(url, content, ct);
        if (!resp.IsSuccessStatusCode)
            throw new InvalidOperationException($"通知服务返回 HTTP {(int)resp.StatusCode}。");
    }

    public void Dispose() => _http.Dispose();
}
