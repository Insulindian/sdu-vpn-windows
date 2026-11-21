# SDU VPN for Windows

Windows 端的独立校园连接客户端。整体思路沿用 macOS 版，数据面来自上游
[zju-connect](https://github.com/Mythologyli/zju-connect)，并针对山东大学的
CAS 与 aTrust 网关做了修改（详见[根目录 README](../README.md)）。

```
真实 CAS 登录（Chromium，由你输入学号 / 密码 / 短信）
        ↓ 单次 ticket（登录后从 CASTGC 重新取一张，避免被浏览器消费）
aTrust 客户端认证（复用官方客户端已授信的终端 ID）
        ↓ sid + device-id + resource
zju-connect.exe（SOCKS5 :1080 / HTTP :1081）
```

运行时不调用官方 aTrust 应用、SDK 或后台服务。密码只在学校的 CAS 页面输入。

## 界面

- **直连 / 代理** 两个大按钮，没有服务器地址、端口等设置。
- 连接状态、内网 IP、在线时长、当前会话来源。
- **手动测速**：学校主页、校内门户、各 SSH 服务器的延迟。
- 本地代理地址一键复制。
- 运行日志抽屉。

界面使用 `pywebview` + WebView2（Windows 11 自带），不是旧的 Tkinter 界面。

### 固定到开始屏幕

`windows\SDU VPN.exe` 是一个真正的 Windows 程序（带图标），不是 `.bat`：

1. 打开开始菜单，搜索 **SDU VPN**；
2. 右键 → **固定到“开始”屏幕**（或“固定到任务栏”）。

安装脚本会把 `SDU VPN.lnk` 写进
`%APPDATA%\Microsoft\Windows\Start Menu\Programs\SDU VPN\`，
所以开始菜单里可以直接找到。桌面快捷方式也指向这个 exe。

## 安装

需要 Python 3.11+、WebView2 Runtime（Windows 11 已内置）。

```powershell
# 在仓库根目录执行
powershell -ExecutionPolicy Bypass -File windows\install.ps1
```

`install.ps1` 会安装 `windows\requirements.txt`、下载 Playwright 的 Chromium，并把
`SDU VPN.lnk` 写进
`%APPDATA%\Microsoft\Windows\Start Menu\Programs\SDU VPN\` 和桌面。
想手动来一遍：

```powershell
python -m pip install -r windows\requirements.txt
python -m playwright install chromium
```

`client/bin/zju-connect.exe` 不随仓库分发：`install.ps1` 会从上游
[zju-connect](https://github.com/Mythologyli/zju-connect) 的 release 下载
v1.3.1（Windows amd64）并校验 SHA-256，放到 `client/bin/`。只使用 SOCKS5/HTTP
代理模式，不需要 `wintun.dll`。也可以自己下载后放到同一位置。

启动器 `windows\SDU VPN.exe` 是从 `launcher.cs` 编译出来的；改了启动器之后用
`powershell -ExecutionPolicy Bypass -File windows\build-launcher.ps1` 重新生成。

## 运行

双击 `windows\start.bat`，或桌面快捷方式 `SDU VPN`。

1. 点击「代理」；
2. 首次会弹出 Chromium 的山东大学统一身份认证页；
3. 输入学号 / 密码（新设备可能需要短信验证码）；
4. 程序完成 aTrust 认证并启动 `zju-connect.exe`；
5. 看到「已连接」后，代理地址为：
   - SOCKS5 `127.0.0.1:1080`
   - HTTP `127.0.0.1:1081`

点击「直连」会停止隧道并恢复原来的系统代理。

## 自动登录

点击侧边栏的 **「设置自动登录」**，输入一次学号和密码：

- 密码使用 Windows DPAPI 加密保存（`credentials.dat`），只有当前 Windows 用户能解密；
- 网页界面永远拿不到密码；
- 网关会话过期时，程序**优先复用浏览器保存的 CAS 会话（CASTGC）**：不输密码、不发短信；
- 只有 CASTGC 也过期时，才打开**真实的 Chromium CAS 页面**，用保存的账号自动填入并点击登录；
- 页面自己计算浏览器指纹、走 `/cas/device` 设备信任流程，所以不会被当成新设备；
- 如果出现短信/图形验证码，请在弹出的 CAS 页面里完成，程序会继续等待并接收回调；
- 旧版用程序内合成指纹直接提交表单，会被 CAS 当成新设备并产生**假的“学号或密码错误”**，该路径已废弃。

> 如果你确认密码正确但仍然报错，请先看弹出的 CAS 页面上的真实提示；那里才是学校的原始错误。

没有配置自动登录时，行为与之前一致：会话过期后打开 Chromium 的 CAS 页面手动登录。

## 代理范围

- **默认不修改 Windows 系统代理**，Clash 继续作为系统代理，二者不再互相覆盖。
- 需要系统级 PAC 时，勾选「同时设置 Windows 系统代理」：
  `*.sdu.edu.cn`、`vpn.sdu.edu.cn` 和 `10/8`、`172.16/12`、`192.168/16`
  走本地 VPN，其他流量仍交给原代理（Clash）。
  程序只会恢复自己设置的 PAC；如果 Clash 之后改过系统代理，不会覆盖它。
- 使用 Clash 的用户可以在 Clash Verge 的 `Merge.yaml` 中把学校域名指向本地 HTTP 代理
  （**仅在 SDU VPN 连接时有效**；示例，按你的 Merge 模板格式调整）：

  ```yaml
  prepend-proxies:
    - name: SDU-VPN
      type: http
      server: 127.0.0.1
      port: 1081

  prepend-rules:
    - DOMAIN-SUFFIX,sdu.edu.cn,SDU-VPN
    - IP-CIDR,10.0.0.0/8,SDU-VPN,no-resolve
    - IP-CIDR,172.16.0.0/12,SDU-VPN,no-resolve
    - IP-CIDR,192.168.0.0/16,SDU-VPN,no-resolve
  ```

- SSH：第一次连接时会生成 `~/.ssh/sdu-vpn.conf`，并在 `~/.ssh/config` 顶部加入
  `Include ~/.ssh/sdu-vpn.conf`。你现有的 SSH 主机（`Host` 条目）会自动通过
  `windows\ssh-proxy.cmd` 走本地代理；直连模式下自动回落为直连。
  - 优先使用 **SOCKS5 `127.0.0.1:1080`**：它没有 HTTP CONNECT 1081 那条路径的空闲断连问题；
  - HTTP CONNECT 1081 仅作为旧版数据面的兜底；
  - 生成的配置带 `ServerAliveInterval 2` / `ServerAliveCountMax 3`，避免长时间无数据时被代理掐断；
  - VSCode Remote-SSH 的 server 安装/端口转发已验证可用；
  - 如果不想改 SSH 配置，删除 `~/.ssh/config` 里的 Include 行即可。
- 学校网关的“可信终端”策略：程序会从
  `%APPDATA%\Sangfor\aTrust\database\aTrustAuth\AppConfig` 读取官方客户端已授信的
  终端 ID，避免 `75500503`（网页登录不能新增可信终端）。

## 重启免登录

- 登录后的网关 Cookie 写入 `client_data.json`，隧道资源写入 `resource.json`。
- 代理模式会记录在 `ui-state.json`；下次启动时自动尝试复用会话，不打开浏览器。
- 如果配置了自动登录，网关会话过期后会直接用保存的账号自动登录 CAS；只有短信验证码
  需要你输入。
- CAS 的 `CASTGC` 保存在 Chromium 配置目录中；即使自动登录失败，CAS 也通常会 SSO。
- 没有任何保存的会话和自动登录时，界面会提示“点击「代理」重新登录”。

## 状态文件

都在 `%APPDATA%\sdu-connect`：

| 文件 | 内容 |
| --- | --- |
| `client_data.json` | 会话 Cookie、终端 ID（删除后需重新登录） |
| `resource.json` | 隧道节点和资源（较大） |
| `endpoint_identity.json` | 当前终端 ID |
| `credentials.dat` | DPAPI 加密的自动登录账号（若已配置） |
| `ui-state.json` | 上次使用直连还是代理 |
| `zju-connect.log` | 数据面日志 |
| `windows-app.log` | 界面与登录流程日志 |
| `browser/` | Chromium 的 CAS 登录状态 |

这些文件都是本机运行状态，仓库里不含任何一份。

## 手动测速

界面里的“测速”会对每个 SSH 主机实际执行一次
`ssh -o BatchMode=yes <host> true`（走和 VSCode 相同的 ProxyCommand）：

- 绿色 = 登录成功，显示连接 + 认证延迟；
- 黄色“认证失败” = 端口通，但服务器拒绝密钥/密码（检查 `IdentityFile` 或密码）；
- 红色“不可达” = 端口/服务没有响应，可能是服务未启动、端口被防火墙拦截，或主机不在 VPN 路由内。

`BatchMode=yes` 不会弹出密码提示；需要密码的主机会显示“认证失败”，这是预期行为。

如果某些主机不希望出现在测速里（仍然保留 SSH 代理配置），把它们加入环境变量
`SDU_SKIP_SSH`（逗号分隔，不区分大小写），例如：

```powershell
set SDU_SKIP_SSH=hostA,hostB
```

## 常见问题

**连接失败，日志里是 `client is not installed or the user logged in on Web` / `75500503`**
学校网关不允许通过网页登录新增可信终端。程序会自动复用官方 aTrust 客户端的终端 ID；
如果读不到，请先在官方客户端完成一次终端绑定，再回来连接。

**`zju-connect` 启动后立即退出**
查看 `%APPDATA%\sdu-connect\zju-connect.log`。常见原因：ticket 被消费、网关策略拒绝、
端口被占用。

**SSH 连接超时 / 登录失败**
先确认代理模式已连接，然后执行 `ssh -G <host>` 确认有 `proxycommand` 行。
直连模式下 SSH 会直接连接，校内主机不可达是正常的。

**系统代理勾选后无法上网**
程序退出时会恢复原代理；异常退出时下次启动会自动恢复。也可以检查注册表
`HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings` 下的
`AutoConfigURL` 是否还指向 `127.0.0.1:18769`。

## 免责声明

个人学习用途的客户端复刻，与山东大学、深信服（Sangfor）、浙江大学及 zju-connect
作者均无关。请遵守学校网络使用规定，仅使用自己的账号。
