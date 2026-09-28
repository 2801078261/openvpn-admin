# OpenVPN Admin Panel（自研图形化管理后台）

中文界面的 OpenVPN 服务管理面板，无需安装 OpenVPN Access Server，直接管理原生 OpenVPN（openvpn-server@server）。

单文件 Python 后端（零外部依赖）+ 单文件 HTML 前端（零外部依赖），仿 OpenVPN Access Server 布局，支持中英切换。

## 功能

- **状态概览**：服务开关 / 版本 / 允许连接数 / 活跃用户 / 认证方式 / 监听端口 / OSI 层
- **当前用户**：在线列表（真实 IP、虚拟 IP、时长、流量），一键断开
- **日志报告**：关键字过滤实时日志
- **网络设置**：服务器域名、监听网卡、UDP/TCP/Both（双开）、端口、多守护进程、DNS；改完自动重写配置并重启
- **VPN 设置**：加密算法（cipher/auth）、全局路由模式
- **网页管理**：面板内修改管理员密码
- **服务服务器**：多实例增删（自动生成 serverN.conf、补端口）
- **配置备份**：一键导出 tar.gz（主配置 + ccd 路由 + 面板数据）
- **用户账户**：增删用户、静态 IP、路由、分组、证书状态、客户端配置下载
- **组权限**：组级网络路由 + 带宽，自动注入客户端配置
- **认证设置**：Local / PAM / RADIUS / LDAP / SAML 配置存档（RADIUS/LDAP/SAML 需对接对应服务端）
- **客户端导出**：按用户下载 .ovpn，全平台通用
- **证书 / 调试 / 资源监控**：证书状态、服务状态 + 路由表、CPU / 内存 / 连接数实时曲线

## 部署

前置要求（已在服务器装好的）：
- Ubuntu + `openvpn`（openvpn-server@server 运行中）
- `easy-rsa` 生成的 PKI（客户端证书 + CCD 目录）
- 可写目录 `/opt/ovpn-admin`，服务以普通用户（如 `chenxiaoc`）运行

```bash
sudo mkdir -p /opt/ovpn-admin
sudo cp app.py index.html /opt/ovpn-admin/
sudo chown -R <your-user>:<your-user> /opt/ovpn-admin
```

systemd 服务（/etc/systemd/system/ovpn-admin.service）：

```ini
[Unit]
Description=OpenVPN Admin Panel
After=network.target openvpn-server@server.service

[Service]
User=<your-user>
Group=<your-user>
ExecStart=/usr/bin/python3 /opt/ovpn-admin/app.py
Restart=always

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now ovpn-admin
```

## 登录

浏览器访问 `http://<server>:8080`。

- 默认用户名：`admin`
- 默认密码：`changeme`（**首次登录后在「网页管理」里修改**）

面板写 OpenVPN 配置时需要通过 sudo（面板服务用户需有 sudo 权限，建议在 `/etc/sudoers.d/` 里配 NOPASSWD）。

## 环境变量（可选）

| 变量 | 作用 | 默认值 |
|---|---|---|
| `OVPN_HOST` | 客户端配置里的服务器地址 | 空（在面板「网络设置」里配置） |
| `EASY_RSA_DIR` | easy-rsa PKI 路径 | `/etc/openvpn/easy-rsa` |

## 结构

```
app.py        # Python 后端（http.server，约 800 行）
index.html    # 前端（单 HTML，中英双语）
```

数据文件（运行时生成，请勿提交到 Git）：
- `/opt/ovpn-admin/users.json` 用户与密码
- `/opt/ovpn-admin/settings.json` 面板配置
- `/opt/ovpn-admin/audit.log` 审计日志

## 安全说明

- 面板自带 Basic 认证，生产环境建议置于内网或再加一层反向代理 TLS
- 客户端证书吊销通过 `easy-rsa` revoke 操作完成
