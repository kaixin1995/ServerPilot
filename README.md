# ServerPilot

一个基于 .NET 8 的轻量级 SSH 服务器管理后台与 MCP（Model Context Protocol）服务。通过网页后台统一管理服务器、使用 WebSSH 终端、浏览 SFTP 文件、监控主机健康状态并执行批量运维；同时通过 Streamable HTTP MCP 让 Codex、Claude Code 等 AI 客户端安全受控地调用同一批服务器。

## 功能概览

- **网页管理后台**：
  - 管理员首次网页引导设置密码与登录认证（Cookie 会话 + 登录限流）。
  - 服务器增删改查、标签分组、SSH Config 批量导入、候选主机指纹探测与连接测试。
  - **WebSSH 交互式终端**：基于 `xterm.js` + WebSocket 的浏览器内实时交互终端。
  - **SFTP 文件浏览器与文本编辑**：可视化浏览远端目录、新建目录、重命名、删除、直传/下载（单文件上限 512 MiB），以及远端 UTF-8 文本读取、写入和精确局部替换（`patch`）。
  - **主机监控快照（Snapshot）**：一键或批量采集系统版本、内核、运行时间、CPU、内存、磁盘、负载、TCP 监听端口、Docker 状态与异常 systemd 服务。
  - **命令执行与批量运维**：单机执行、多机并行批量执行（`batch_execute`）、常用命令片段（Snippets）管理。
  - **后台任务管理**：在远端 `~/.serverpilot-jobs` 中持久化运行长耗时任务，支持查看状态与增量输出、安全终止（`job_kill`）以及过期任务清理（`job_cleanup`）。
  - **文件暂存区**：网页与 AI 客户端共享的服务端文件中转区（单文件上限 512 MiB）。
- **独立 SSH 密钥库（Key Vault）与认证**：
  - 支持在线生成 OpenSSH `Ed25519` / `RSA-4096` 密钥对、导入或轮换已有私钥（可选口令），自动提取算法、公钥与 SHA-256 指纹。
  - 支持一键将公钥下发至目标主机 `~/.ssh/authorized_keys`，并可自动绑定为共享密钥认证（密钥轮换时引用该密钥的服务器自动生效）。
  - 支持密码、私钥、共享密钥引用、服务端统一密钥文件、键盘交互式 2FA/MFA、跳板机（Jump Server）以及 SOCKS/HTTP 代理；每台服务器强制校验固定的 SHA-256 主机指纹。
  - 凭据使用 AES-256-GCM 加密存储于 SQLite，网页接口、API 与 MCP 列表永不返回明文凭据。
- **独立作用域 MCP 令牌与 17 个 MCP 工具**：
  - 通过 `/mcp` 提供无状态 Streamable HTTP MCP 服务。
  - 支持签发独立 MCP 令牌（`sp_` 前缀），可配置只读权限、允许访问的标签/服务器范围、有效期与吊销；也可在系统设置中按需开启或关闭“允许管理员密码直接作为 MCP 令牌”。
  - 内置工具：`list_servers`、`test_connection`、`server_snapshot`、`execute_command`、`batch_execute`、`start_job`、`job_status`、`job_kill`、`job_list`、`job_cleanup`、`list_directory`、`list_staged_files`、`upload_file`、`download_file`、`read_file`、`write_file`、`patch_file`。
- **通知推送、加密备份与操作审计**：
  - 支持通用 Webhook (JSON)、飞书机器人、钉钉机器人、企业微信机器人与 Telegram Bot 通知。
  - 支持在网页端使用口令导出/导入加密配置备份（服务器、密钥库等），或进行数据目录冷备。
  - 操作审计日志保留 30 天，支持分页、多条件检索以及 JSON / CSV 导出。

> **安全提示**：MCP 客户端与网页命令执行不设命令白名单限制，AI 或操作者将拥有对应服务器 SSH 账号的权限。SFTP 允许路径仅约束 SFTP 文件操作，不能替代远端操作系统级权限隔离。请妥善保管管理员密码、MCP 令牌与数据加密密钥，并通过内网、SSH 隧道或受信任的 HTTPS 反向代理访问。

---

## 一、快速启动

项目支持 Windows 与 Linux，需安装 [.NET 8 SDK](https://learn.microsoft.com/dotnet/core/install/)。

### 1. 直接运行（推荐初次使用）

进入项目目录后直接启动：

```bash
dotnet restore
dotnet run --no-launch-profile
```

默认行为：
- 监听地址由 [appsettings.json](appsettings.json) 中的 `ServerPilot:Host`（`*`）和 `ServerPilot:Port`（`5080`）控制，可通过 `ASPNETCORE_URLS` 环境变量覆盖（例如 `http://127.0.0.1:5080`）。
- 数据默认存放在项目下的 `data/` 目录（可通过 `SERVERPILOT_DATA_DIR` 自定义）。
- 若未设置 `SERVERPILOT_ENCRYPTION_KEY`，首次启动会自动生成 32 字节随机密钥并保存至数据目录的 `.encryption-key` 中。
- 首次启动若尚未配置管理员密码，在浏览器打开 `http://127.0.0.1:5080` 即可在引导页面完成管理员密码设置。

### 2. 环境变量说明（可选）

| 变量名 | 说明 |
| --- | --- |
| `ASPNETCORE_URLS` | 覆盖监听地址，如 `http://127.0.0.1:5080` |
| `SERVERPILOT_DATA_DIR` | 数据目录路径（存放 SQLite 数据库、密钥校验文件、暂存区等） |
| `SERVERPILOT_ENCRYPTION_KEY` | 32 字节随机数的 Base64 字符串（如 `openssl rand -base64 32`），用于数据库与会话加密 |
| `SERVERPILOT_ADMIN_PASSWORD` | 预设管理员密码（8–1024 个非空白 ASCII 字符） |
| `SERVERPILOT_ALLOWED_HOSTS` | 逗号分隔的允许 Host 白名单（默认取配置或允许 `*`） |
| `SERVERPILOT_SERVICE_KEY_PATH` | 服务端统一 SSH 私钥文件路径，供服务器配置“使用服务端 SSH 密钥”使用 |
| `SERVERPILOT_SERVICE_KEY_PASSPHRASE` | 服务端统一 SSH 私钥口令（可选） |
| `SERVERPILOT_2FA_CODE` | 键盘交互式认证的非密码提示验证码（可选） |

> **重要**：`.keycheck`、`.encryption-key`（若自动生成）与 `serverpilot.db` 必须成套保存。丢失加密密钥将导致已保存的服务器凭据无法解密。

### 3. 远程访问建议

若服务部署在远端管理机且仅监听回环地址 `127.0.0.1:5080`，可在本地通过 SSH 隧道安全访问：

```bash
ssh -N -L 5080:127.0.0.1:5080 管理机用户名@管理机地址
```

保持隧道运行后，在本地浏览器打开 `http://127.0.0.1:5080` 即可。如需通过域名直接访问，请在前方配置 HTTPS 反向代理（Nginx / Caddy 等）并限制来源访问。

---

## 二、日常使用指南

### 1. 添加服务器与主机指纹校验

1. 点击**添加服务器**，填写名称、主机地址、SSH 端口、用户名、标签，或直接通过 **导入 SSH Config** 粘贴 `~/.ssh/config` 批量解析。
2. 选择认证方式：**SSH 密钥库引用**、**独立私钥**、**SSH 密码**或**服务端统一密钥**；如需通过堡垒机连接，可选择已配置好的**跳板机**或填写 SOCKS/HTTP 代理。
3. 填写 SSH 主机的 SHA-256 指纹：可点击**获取候选指纹**探测当前网络返回的指纹，并通过服务器控制台等独立可信渠道核对（例如在目标机执行 `sudo ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`）。
4. 保存后点击**测试**，确认指纹匹配且认证成功。

### 2. SSH 密钥库管理

在网页**密钥库**页面可以：
- **在线生成**：在服务端生成标准的 OpenSSH `Ed25519` 或 `RSA-4096` 密钥对并加密存储。
- **导入 / 轮换**：上传或粘贴已有私钥，自动计算算法类型、公钥和 SHA-256 指纹；更新密钥后，所有引用该密钥的服务器会自动使用新密钥。
- **一键下发公钥**：选择多台目标服务器，将公钥写入远端 `~/.ssh/authorized_keys`，并可勾选在下发成功后自动将服务器切换绑定为该密钥认证。

### 3. 终端、文件与监控

- **WebSSH 终端**：在服务器操作栏打开实时交互终端，支持自适应窗口大小。
- **SFTP 浏览器**：支持目录导航、新建文件夹、重命名、删除、本地文件上传与下载（单文件最大 512 MiB），以及文本文件在线查看与编辑。
- **批量执行与后台任务**：支持按标签/多选服务器并行执行命令；长耗时任务可作为后台任务启动，随时查看输出、安全终止或清理历史任务目录。

---

## 三、接入 MCP 客户端

建议在网页后台 **MCP 令牌** 页面为不同客户端签发独立令牌（`sp_...`），按需限制为**只读**或仅允许特定标签/服务器。

### 接入 Codex

在 `~/.codex/config.toml`（Windows 为 `%USERPROFILE%\.codex\config.toml`）中添加：

```toml
[mcp_servers.serverpilot]
url = "http://127.0.0.1:5080/mcp"
bearer_token_env_var = "SERVERPILOT_MCP_TOKEN"
```

在启动 Codex 前设置环境变量 `SERVERPILOT_MCP_TOKEN` 为签发的 MCP 令牌即可。

### 接入 Claude Code

```bash
claude mcp add --transport http serverpilot http://127.0.0.1:5080/mcp \
  --header "Authorization: Bearer 你的MCP令牌"
claude mcp list
```

### MCP 工具清单

| 类别 | 工具名称 | 说明 |
| --- | --- | --- |
| 服务器与健康 | `list_servers`、`test_connection`、`server_snapshot` | 列出可见服务器、测试连接、采集系统与服务健康快照 |
| 命令执行 | `execute_command`、`batch_execute` | 单机非交互式命令执行（最长 1800 秒）、多机并行批量执行 |
| 后台任务 | `start_job`、`job_status`、`job_kill`、`job_list`、`job_cleanup` | 启动远端后台任务、查询进度与输出、安全终止进程组、列表与清理 |
| 文件与文本 | `list_directory`、`list_staged_files`、`upload_file`、`download_file`、`read_file`、`write_file`、`patch_file` | SFTP 目录浏览、暂存区互传（最大 512 MiB）、UTF-8 文本分页读写（读 1 MiB / 写 2 MiB）与精确替换 |

---

## 四、Linux 生产部署示例（systemd）

项目已启用请求委托生成器与 JSON 源生成（AOT 兼容），可使用 Release 模式发布运行：

```bash
sudo useradd --system --create-home --shell /usr/sbin/nologin serverpilot
cd /opt/serverpilot/src
sudo dotnet publish -c Release -o /opt/serverpilot/app
sudo install -d -o serverpilot -g serverpilot -m 700 /var/lib/serverpilot
sudo install -d -m 700 /etc/serverpilot
```

创建环境配置文件 `/etc/serverpilot/serverpilot.env`（权限设为 `600`）：

```ini
SERVERPILOT_DATA_DIR=/var/lib/serverpilot
ASPNETCORE_URLS=http://127.0.0.1:5080
# 建议显式固定加密密钥（使用 openssl rand -base64 32 生成）：
SERVERPILOT_ENCRYPTION_KEY=替换为32字节Base64加密密钥
```

创建 `/etc/systemd/system/serverpilot.service`：

```ini
[Unit]
Description=ServerPilot SSH Management & MCP Service
After=network-online.target
Wants=network-online.target

[Service]
User=serverpilot
Group=serverpilot
WorkingDirectory=/opt/serverpilot/app
EnvironmentFile=/etc/serverpilot/serverpilot.env
ExecStart=/usr/bin/dotnet /opt/serverpilot/app/ServerPilot.dll
Restart=on-failure
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/serverpilot
UMask=0077

[Install]
WantedBy=multi-user.target
```

启用并启动服务：

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now serverpilot
sudo systemctl status serverpilot
```

---

## 五、备份与恢复

- **网页加密备份**：在系统设置中使用自定义口令导出加密备份 JSON，需要时可在新环境导入恢复（支持选择是否覆盖同名条目）。
- **数据目录冷备**：停止服务后，完整备份 `data/` 目录（包含 `serverpilot.db`、`.keycheck`、`.encryption-key`、`admin-password.json` 及需要保留的 `staging/`）。若通过环境变量指定了 `SERVERPILOT_ENCRYPTION_KEY`，请将其与数据库分开安全保管。
