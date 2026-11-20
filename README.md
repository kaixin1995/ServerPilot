# ServerPilot

一个基于 .NET 8 的 SSH 服务器管理后台和 MCP 服务。通过网页维护服务器、测试连接、执行命令、交换文件；通过 MCP 让 Codex、Claude Code 等客户端调用同一批服务器。

> 这是可运行的第一版，适合在隔离环境先行试用；未经独立安全审计，也未完成真实 Linux 主机上的验收，**请先用测试机，不要直接暴露公网或用于关键生产环境**。

## 功能概览

- 网页后台：管理员登录；添加、编辑、删除、搜索服务器；候选主机指纹获取；连接测试；执行命令；文件暂存、上传下载；最近 30 天的操作记录及分页。
- 服务器认证：SSH 密码或私钥（可带口令），可选 SSH 密钥文件、键盘交互式 2FA/MFA 和 SOCKS/HTTP 代理；每台必须固定 SHA-256 主机指纹，每次连接都会校验。凭据 AES-256-GCM 加密后存 SQLite，网页列表、API 列表和 MCP 列表不返回凭据。
- MCP：Streamable HTTP `/mcp`；`list_servers`、`test_connection`、`execute_command`、`start_job`、`job_status`、`job_kill`、`job_list`、`read_file`、`write_file`、`list_staged_files`、`upload_file`、`download_file`。
- 默认仅监听 `127.0.0.1:5080`。MCP Bearer 令牌始终使用当前后台登录密码。

命令不做白名单限制；AI 可以按 SSH 用户权限管理远端服务器。每台服务器可设置 SFTP 允许路径；该限制不约束 SSH 命令，且不能防止远端用户并发替换路径，因此不能作为隔离边界。MCP 令牌持有者拥有相应操作能力，必须像密码一样保护。

## 一、Linux 快速启动

以下命令以 Debian / Ubuntu 为例，项目代码复制到 Linux 后执行。需要 .NET 8 SDK、`openssl`、`curl`：

```bash
dotnet --version
openssl version
```

如果尚未安装 .NET SDK，请按照 [微软 .NET 8 安装说明](https://learn.microsoft.com/dotnet/core/install/linux)选择你的发行版安装。项目的 NuGet 包在首次构建时需要从 NuGet 下载。

进入项目目录，准备管理员密码和独立的数据加密密钥。下面命令会在终端中显示新生成的值，请自己复制并安全保存，不要粘贴到 AI 对话中：

```bash
openssl rand -base64 32   # 管理员密码
openssl rand -base64 32   # 数据加密密钥（必须正好 32 随机字节的 Base64）
```

交互式输入，避免把具体值写进 shell 命令历史：

```bash
read -rsp '管理员密码：' SERVERPILOT_ADMIN_PASSWORD; echo
read -rsp '数据加密密钥：' SERVERPILOT_ENCRYPTION_KEY; echo
export SERVERPILOT_ADMIN_PASSWORD SERVERPILOT_ENCRYPTION_KEY
export SERVERPILOT_DATA_DIR="$PWD/data"

dotnet restore
dotnet run --no-launch-profile
```

要求：管理员密码为 8–1024 个非空白 ASCII 字符；加密密钥必须解码为 32 字节。**保存好加密密钥**：数据库只有和原来的密钥一起才能解密。程序会在数据目录保存密钥校验文件，启动时检查密钥是否匹配；不要删除该文件。

MCP Bearer 令牌始终是当前管理员密码；更改管理员密码会立即使旧令牌失效，必须更新所有 MCP 客户端。共用凭据降低安全隔离，建议仅在可信环境使用强密码。已有部署的独立 `SERVERPILOT_MCP_TOKEN` 将不再生效，升级后请将客户端令牌改为当前管理员密码。

可选的环境变量：

- `SERVERPILOT_SERVICE_KEY_PATH`：服务端统一 SSH 密钥文件的绝对路径，供服务器表单里的“使用服务端 SSH 密钥文件认证”选项使用；旧名 `SERVERPILOT_AGENT_KEY_PATH` 仍兼容。
- `SERVERPILOT_SERVICE_KEY_PASSPHRASE`：上述服务端密钥的口令（可选）。
- `SERVERPILOT_2FA_CODE`：键盘交互式认证的非密码提示验证码。它是服务级的短时值，轮换后需要重启服务。

浏览器打开：

```text
http://127.0.0.1:5080
```

输入管理员密码登录。运行时的 `data/` 目录包括数据库、校验文件、Cookie 密钥和文件暂存区。Linux 下程序将目录设为仅运行账户可访问；仍应使用专门的 Linux 用户运行并妥善保护主机。

### 远程查看后台

如果服务运行在另一台 Linux 管理机，从你的电脑先建立 SSH 隧道：

```bash
ssh -N -L 5080:127.0.0.1:5080 管理机用户名@管理机地址
```

保持隧道运行，在自己电脑浏览器访问 `http://127.0.0.1:5080`。Windows PowerShell 的 `ssh` 也可使用同一条命令。

为了实现凭据隔离，AI 所在账户不要拥有管理机的普通 shell 或读服务数据目录的权限；隧道身份也应单独配置为仅允许所需的端口转发。不要把管理员密码、加密密钥或 SSH 私钥传入 AI 对话。

这个版本没有包含公网反向代理的完整配置。确需远程网页访问，应由熟悉网络安全的管理员配置可信 HTTPS 反向代理或 VPN、主机名白名单、来源访问控制并验证。可以用 `SERVERPILOT_ALLOWED_HOSTS` 配置逗号分隔的允许 Host；默认仅允许 `localhost,127.0.0.1,::1`。直接暴露 HTTP 会泄露登录信息。

## 二、添加服务器

1. 登录后台，点击“添加服务器”。填写名称、地址、SSH 端口、用户名和标签。
2. 选择 **SSH 私钥**或 **SSH 密码**，在网页中输入对应凭据。编辑时对应字段留空表示沿用旧凭据；切换认证类型时必须提供新凭据。
3. 填写 SSH 主机的 SHA-256 指纹。可点击“获取候选指纹”，它展示的是当前网络连接获得的指纹，**不能单凭这个结果认定服务器身份**。请通过服务器控制台、可信运维人员或其他独立可信渠道确认，再手动粘贴。
4. 保存后点击“测试”。只有主机指纹匹配且认证成功才会连接。实际协商的密钥算法会影响所呈现的指纹，以候选指纹所标出的算法为准核对。

在有可信控制台访问权限时，Linux 服务器常见主机密钥可通过以下方式查看：

```bash
sudo ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
sudo ssh-keygen -lf /etc/ssh/ssh_host_rsa_key.pub
```

输出形如：

```text
256 SHA256:... root@host (ED25519)
```

填写 `SHA256:` 开始的完整部分。主机密钥轮换时，需要重新通过可信渠道核对，并在网页编辑指纹。

## 三、网页日常使用

- 在服务器列表点击“操作”，输入命令和超时时间，可查看退出码、标准输出和标准错误。支持普通非交互式命令；需要交互输入密码、终端控制的程序不适用。
- 后台任务：在“操作 → 后台任务”启动，状态和输出保存在远端 `~/.serverpilot-jobs/<jobId>/`；`job_list` 列出最近任务。任务终止暂不可用。
- 文本文件：在“操作 → 文本文件”直接读取或写入远端 UTF-8 文本；单次读取最多 1 MiB、写入最多 2 MiB，二进制文件请走文件传输。
- 在“文件暂存”将本机浏览器里的文件上传到**管理服务所在机器**。进入服务器操作的“文件传输”，填写暂存文件名和远端绝对路径，上传或下载。单文件上限 512 MiB，超过限制的文件会被拒绝；不支持断点续传或递归目录传输。上传默认不覆盖远端，下载不覆盖暂存文件。大文件需保证管理机和目标服务器有足够磁盘空间，网页上传还可能占用临时磁盘空间。
- 暂存区文件可以在网页下载到浏览器所在电脑。管理机与 AI 客户端不在同一台机器时，暂存路径不是客户端本地路径。
- 操作记录保留 30 天；启动、查看记录及运行时定期清理过期记录，网页按每页 50 条显示全部未过期记录。记录仅保留类型、来源、服务器、时间和成功/失败；不记录命令文本、输出，也不等同于可回放的完整审计。记录存储在本地 SQLite，可被管理机有权限的人员修改。
- 添加或编辑服务器时可上传并保存共享 SSH 私钥，之后多台服务器可以选择同一密钥。保存服务器时会复制一份加密凭据，因此删除共享私钥不会影响已保存的服务器；密钥轮换时需要重新为各服务器选择新密钥。

## 四、接入 Codex

以下假设客户端访问地址为 `http://127.0.0.1:5080/mcp`：如果服务在另一台机器上，先按前面的方法建立 SSH 隧道。

将以下内容添加到运行 Codex 用户的 `~/.codex/config.toml`（Windows 通常为用户目录下 `.codex/config.toml`）：

```toml
[mcp_servers.serverpilot]
url = "http://127.0.0.1:5080/mcp"
bearer_token_env_var = "SERVERPILOT_MCP_TOKEN"
```

在启动 Codex 的进程环境中注入当前管理员密码作为 MCP 令牌：

```bash
read -rsp '管理员密码：' SERVERPILOT_MCP_TOKEN; echo
export SERVERPILOT_MCP_TOKEN
codex
```

桌面应用需要在其启动环境中提供变量；新开的终端设置变量不会自动改变已经运行的桌面应用环境。配置格式以 [Codex 官方 MCP 文档](https://developers.openai.com/codex/mcp/)为准。

## 五、接入 Claude Code

Claude Code 可连接 HTTP MCP。以下使用交互式输入，避免令牌进入 shell 历史：

```bash
read -rsp '管理员密码：' SP_CLIENT_TOKEN; echo
claude mcp add --transport http serverpilot http://127.0.0.1:5080/mcp \
  --header "Authorization: Bearer $SP_CLIENT_TOKEN"
unset SP_CLIENT_TOKEN
claude mcp list
```

注意：上面命令仍会让令牌短暂出现在本机进程参数中，Claude Code 也会保存连接配置。确保客户端所在机器和配置文件受保护。生产使用可根据你的环境采用更安全的凭据注入机制。参见 [Claude Code MCP 文档](https://code.claude.com/docs/en/mcp)。OpenClaw 的接入取决于实际版本及其 MCP 插件，项目未验证所有客户端。

连接后可以给 AI 发送：

```text
列出已配置服务器，查看 test-web 的系统版本、CPU、内存和磁盘使用率。
```

```text
将暂存区中的 app.tar.gz 上传到 test-web 的 /tmp/app.tar.gz，然后告诉我结果。
```

```text
检查 test-web 上 nginx 服务的状态和最近日志。
```

## 六、Linux 持续运行示例

以下是 systemd 思路，实际安装路径、用户和权限需要按你的机器调整。先创建专用用户，把项目复制到 `/opt/serverpilot/src`，然后用有 SDK 的环境发布：

```bash
sudo useradd --system --create-home --shell /usr/sbin/nologin serverpilot
cd /opt/serverpilot/src
sudo dotnet publish -c Release -o /opt/serverpilot/app
sudo install -d -o serverpilot -g serverpilot -m 700 /var/lib/serverpilot
sudo install -d -m 700 /etc/serverpilot
```

以 root 创建 `/etc/serverpilot/serverpilot.env`，填入自己生成的值：

```ini
SERVERPILOT_ADMIN_PASSWORD=替换为管理员密码
SERVERPILOT_ENCRYPTION_KEY=替换为32字节Base64加密密钥
SERVERPILOT_DATA_DIR=/var/lib/serverpilot
# 可选：服务端统一 SSH 密钥文件
# SERVERPILOT_SERVICE_KEY_PATH=/etc/serverpilot/id_ed25519
ASPNETCORE_URLS=http://127.0.0.1:5080
```

以上示例中不要在值两侧添加额外空格。然后限制该文件：

```bash
sudo chown root:root /etc/serverpilot/serverpilot.env
sudo chmod 600 /etc/serverpilot/serverpilot.env
```

创建 `/etc/systemd/system/serverpilot.service`：

```ini
[Unit]
Description=ServerPilot SSH management and MCP
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

确认 `dotnet` 路径与本机实际安装一致（`command -v dotnet`），然后：

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now serverpilot
sudo systemctl status serverpilot
sudo journalctl -u serverpilot -f
```

这里的环境文件是 root 可读的明文配置。环境变量也不是强隔离密钥库；请限制主机 root、进程调试和文件访问权限。不要把 `/etc/serverpilot/serverpilot.env`、数据库或数据目录提交 Git。初始密码来自环境变量；首次启动后密码以加盐哈希保存在数据目录中，不是可管理多用户的身份系统。

## 七、备份和恢复

停止服务后，备份整个数据目录（包括 `.keycheck`、`admin-password.json`、SQLite 数据库、`cookie-keys/` 和需要保留的 `staging/`）。**加密密钥需要单独安全备份**；不要和数据库一起放在公开位置。恢复时使用原来的数据加密密钥和完整数据目录，再启动服务。修改管理员密码后旧网页会话和旧 MCP 凭据失效，需要更新客户端配置。

## 八、当前边界

- 非交互式 SSH `exec` 和单文件 SFTP；无完整交互式终端、跳板机、端口转发、递归目录传输。
- 后台任务状态保存在远端主机的 `~/.serverpilot-jobs`，服务重启或断线不会丢失；任务没有实时推送，需要轮询 `job_status`。超时或取消不能保证远程进程一定终止。
- 命令输出的 stdout、stderr 各最多返回 512 KiB；后台任务输出保存在远端磁盘，需自行管理空间。请结合退出码与远端实际状态判断结果。
- 后台任务需要远端 Linux 提供 `setsid`、`timeout` 和 `base64`；终止功能暂不可用，需在测试机验证进程树和服务重启行为。
- 单个管理员和单个全局 MCP 令牌；没有多用户角色、逐服务器授权、令牌轮换界面、专用审计平台或完整的多次 MFA 交互（仅支持服务级 2FA 验证码）。
- AI 具有任意命令及其服务器账号能访问的文件权限，仍可能读取服务器上的其他密钥、机密或数据；命令输出也会进入客户端/模型上下文。管理服务的 root、服务进程及其系统账户均可使用或读取凭据。
- 浏览器到服务端传入的 SSH 凭据需要经过受信任的本机连接、SSH 隧道或正确部署的 HTTPS；数据库加密不能替代传输加密及系统权限隔离。
- 本项目没有把参考项目的源码直接复制过来；采用官方 MCP .NET SDK、SSH.NET 和 SQLite 重新实现基础能力。
- 与参考项目相比，MCP 工具名称和参数不同，不能直接替换其客户端配置；服务器状态采集、自动重连、后台任务自动清理及任务终止等能力尚未完整复刻。
