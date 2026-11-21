# SDU VPN for Windows

山东大学校园网的独立 Windows 客户端。用真实 CAS 登录换到 aTrust 会话，再通过本地
SOCKS5 / HTTP 代理访问校园网，不安装也不调用官方 aTrust 客户端。

- **登录**：弹出真实 Chromium 统一身份认证页，学号、密码、短信验证码都在学校页面上输入。
- **界面**：直连 / 代理两个按钮，另有在线时长、内网 IP、手动测速和运行日志。
- **代理**：SOCKS5 `127.0.0.1:1080`、HTTP `127.0.0.1:1081`，可选设置系统 PAC。
- **隐私**：密码、Cookie、终端标识只留在本机 `%APPDATA%\sdu-connect`。

> 仅用于你自己的账号，不绕过任何认证。它不是全系统 TUN，不读系统代理的程序需要
> 手动指向 `127.0.0.1:1080` 或 `127.0.0.1:1081`。

## 快速开始

要求 Windows 10/11、Python 3.11+、WebView2 Runtime（Windows 11 自带）。

```powershell
git clone https://github.com/Insulindian/sdu-vpn-windows.git
cd sdu-vpn-windows
powershell -ExecutionPolicy Bypass -File windows\install.ps1
```

`install.ps1` 会下载数据面 `zju-connect`（上游 release，校验 SHA-256）、安装 Python
依赖、下载 Playwright 的 Chromium，并在开始菜单和桌面创建 `SDU VPN` 快捷方式。

启动后：

1. 点「代理」；
2. 在跳出的认证页输入学号 / 密码，按提示完成短信或设备验证；
3. 看到「已连接」后，把需要走校园网的程序指向 `127.0.0.1:1080`（SOCKS5）或
   `127.0.0.1:1081`（HTTP）；
4. 点「直连」断开，并恢复原来的系统代理。

自动登录、系统 PAC / Clash、SSH 代理、测速和排错见 [`windows/README.md`](windows/README.md)。

## 工作原理

```
浏览器（真实 CAS 页面）
   │ ticket
   ▼
sdu_connect（本机 Python）—— ticket → aTrust 网关 → sid + device-id + resource
   │
   ▼
zju-connect.exe —— SOCKS5 127.0.0.1:1080 / HTTP 127.0.0.1:1081
```

票据只换一次会话，换到的 sid 交给数据面复用，浏览器再刷新也不会把会话踢掉。

## 参考与改动

数据面来自 [Mythologyli/zju-connect](https://github.com/Mythologyli/zju-connect)
（AGPL-3.0），本仓库不重新分发它，`install.ps1` 安装时从上游下载。CAS 登录、aTrust
会话交换和终端信息上报的做法参考了它公开的实现。在此之上，针对山东大学做了这些修改：

| 方面 | 通用做法 | 本项目的修改 |
| --- | --- | --- |
| 认证 | 直接调 aTrust 登录接口 | 走学校 CAS（`pass.sdu.edu.cn`），在真实 Chromium 页面完成登录与验证码 |
| 票据 | 复用一个 ticket | 登录后从 `CASTGC` 另取一张单次 ticket，避免被浏览器消费 |
| 终端授信 | 网页登录登记新终端 | 复用官方客户端已授信的终端 ID，绕开 `75500503` |
| 系统代理 | 全局改系统代理 | 默认不动（与 Clash 共存），勾选后才写 HKCU PAC 且只恢复自己写的 |
| SSH | 无 | 生成 `~/.ssh/sdu-vpn.conf`，已有 Host 自动走代理，直连时自动回落 |

## 目录结构

```
windows/         启动器、安装脚本、SSH 助手、图标
client/          sdu_connect（CAS / 网关 / 代理 / 界面）与单元测试
```

数据面 `client/bin/zju-connect.exe` 不入库，由 `install.ps1` 下载。

## 隐私

- 仓库里没有任何账号、密码、Cookie、终端 ID、SSH 私钥或个人路径。
- 自动登录是可选的，密码用 Windows DPAPI 加密，只有当前 Windows 用户能解密。
- 运行状态只写本机用户目录，本地监听只在 `127.0.0.1`。

## 已知限制

- 只提供 SOCKS5 / HTTP 代理，不做 TUN。
- 依赖官方客户端已授信的终端；没装过官方客户端时，网关会拒绝网页登录（`75500503`）。
- 学校网关随时可能改接口，本项目不保证长期可用。

## 开发

```powershell
cd client
python -m pip install requests
python -m unittest discover -s tests
```

## 免责声明

个人学习用途的客户端复刻，与山东大学、深信服（Sangfor）、浙江大学及 zju-connect
作者均无关。请遵守学校网络使用规定，仅使用自己的账号登录。
