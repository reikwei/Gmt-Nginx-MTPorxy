# MTG + Nginx 完整部署记录（含所有踩坑）

**目标**: 部署抗封锁 MTProxy (FakeTLS)，保留 TLS 伪装的同时将延迟压到最低。

- **系统**: Ubuntu 22.04
- **域名**: `你的域名`（已有 Let's Encrypt 证书）
- **服务器公网 IP**: `1xx.2xx.8x.xx`
- **mtg 版本**: 2.1.7

---

## 最终架构

```
外部客户端
  → 我的ip:443  (nginx stream，公网唯一入口)
  → 127.0.0.1:2026   (mtg，处理 MTProxy FakeTLS 流量)
  → Telegram DC

mtg 伪装回落 (非 MTProxy 流量)
  → DoH 查询: https://127.0.0.1/dns-query  (nginx 127.0.0.1:443)
  → http://127.0.0.1:8053                  (doh-local.py Python 服务)
  → 返回 127.0.0.1，本地握手 0ms

  → TLS 回落: 127.0.0.1:8443              (nginx 正常响应伪装页面)
```

---

## 一、安装 mtg

```bash
wget https://github.com/9seconds/mtg/releases/download/v2.1.7/mtg-2.1.7-linux-amd64.tar.gz
tar -zxvf mtg-2.1.7-linux-amd64.tar.gz
mv mtg-2.1.7-linux-amd64/mtg /usr/local/bin/mtg
chmod +x /usr/local/bin/mtg
```

---

## 二、生成 Secret

```bash
mtg generate-secret --hex 域名地址
# 得到: eec242c928b533db313878792ec286168f74676d742e79756562这个是一串 生成的
```

**Secret 格式解析**：
```
ee                                    ← FakeTLS 标识前缀（必须 ee 开头）
c242c928c286168f生成的      ← 16字节随机数（hex）
74676d742e797565生成的  ← "域名地址" 的 hex 编码
```

> ⚠️ **坑 1 — secret/domain/cert 三者必须一致**
> secret 里编码的域名、`[server-tls] domain`、TLS 证书的 CN 必须完全相同。
> 曾因把 domain 改成 `23.192.45.240`（Bing IP 做伪装）但 secret 仍绑定域名，
> 导致 TLS SNI 不匹配，客户端握手失败重试，延迟从 160ms 飙升到 450ms。

---

## 三、mtg 配置文件 `/etc/mtg.toml`

```toml
bind-to = "0.0.0.0:2026"
secret = "eec242c928b533db313878792ec286168f74676d742e79756562这个是一串 生成的"

[network]
# ⚠️ 关键：强制 mtg 使用本地 DoH 服务解析域名（详见第五节）
doh-ip = "127.0.0.1"

[server-tls]
domain = "域名地址"
# ⚠️ 关键：伪装回落端口指向 8443（nginx 本地监听），
#          不能用 443，因为 443 被 stream 占用
domain-fronting-port = 8443
cert = "/etc/letsencrypt/live/域名地址/fullchain.pem"
key = "/etc/letsencrypt/live/域名地址/privkey.pem"
```

---

## 四、Systemd 服务 `/etc/systemd/system/mtg.service`

```ini
[Unit]
Description=mtg
After=network.target

[Service]
Environment=GODEBUG=netdns=go
ExecStart=/usr/local/bin/mtg run /etc/mtg.toml
Restart=always
User=root

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload
systemctl enable mtg
systemctl start mtg
```

---

## 五、解决 DNS 解析失败（最核心的坑）

### 问题现象

mtg 日志不断刷：
```
cannot resolve dns names: cannot find any ips for tcp:域名地址
cannot dial to the fronting domain
```

### 根本原因

mtg 2.1.7 内部用 **DNS-over-HTTPS (DoH)** 解析 fronting domain，默认上游硬编码为 `9.9.9.9 (Quad9)`。
它**完全绕过**系统所有 DNS 机制：

| 机制 | 是否有效 | 原因 |
|------|---------|------|
| `/etc/hosts` | ❌ | mtg 不调用 glibc getaddrinfo |
| `/etc/resolv.conf` | ❌ | mtg 不读此文件 |
| `nsswitch.conf` | ❌ | 同上 |
| `GODEBUG=netdns=cgo` | ❌ | mtg 静态编译，无 cgo |
| `GODEBUG=netdns=go` | ❌ | mtg 用自己的 DoH 客户端，绕过 Go 标准库 |
| 安装 dnsmasq 监听 127.0.0.1:53 | ❌ | mtg 不走 UDP 53，走 HTTPS DoH |

### 正确解决方案

mtg 有 `doh-ip` 配置项，指定 DoH 服务器 IP。配置 `doh-ip = "127.0.0.1"` 后，
mtg 向 `https://127.0.0.1/dns-query` 发 DoH 查询。

**部署本地 Python DoH 服务** (`/usr/local/bin/doh-local.py`)：
- 监听 `127.0.0.1:8053` HTTP
- `域名地址` → 直接返回 `127.0.0.1`（0ms 本地握手）
- 其他域名 → 转发 `https://9.9.9.9/dns-query`

**Nginx `127.0.0.1:443`** 的 `/dns-query` location 代理到 `127.0.0.1:8053`，终止 TLS。

**Systemd 服务** `/etc/systemd/system/doh-local.service`（已 enable 开机自启）。

---

## 六、Nginx 配置

### `/etc/nginx/nginx.conf` — stream 模块

```nginx
# ⚠️ 坑 2 — stream 必须绑定公网 IP，不能用 0.0.0.0
# 若用 listen 443 (即 0.0.0.0:443)，会占用所有接口，
# 导致 http 块无法 listen 127.0.0.1:443，本地 DoH 链路失效。
# 改完后必须 systemctl restart nginx，reload 不生效。
stream {
    server {
        listen 我的ip:443;
        proxy_pass 127.0.0.1:2026;
        proxy_timeout 300s;
        proxy_connect_timeout 5s;
    }
}
```

### `/etc/nginx/conf.d/域名地址.conf`

```nginx
server {
    # 127.0.0.1:443 供 mtg DoH 查询（本地回环，无循环风险）
    listen 127.0.0.1:443 ssl http2;
    # 127.0.0.1:8443 供 mtg 伪装回落
    listen 127.0.0.1:8443 ssl http2;
    server_name 域名地址;

    ssl_certificate /etc/letsencrypt/live/域名地址/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/域名地址/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256;
    ssl_prefer_server_ciphers on;

    # DoH 端点：供 mtg 内部 DNS 解析
    location /dns-query {
        proxy_pass http://127.0.0.1:8053;
        proxy_set_header Host $host;
        proxy_connect_timeout 2s;
        proxy_read_timeout 5s;
    }

    # 伪装页面
    location / {
        default_type text/html;
        return 200 '<h1>不要连我</h1>';
    }
}
```

---

## 七、本地 DoH 服务文件

| 文件 | 说明 |
|------|------|
| `/usr/local/bin/doh-local.py` | Python DoH 服务主体 |
| `/etc/systemd/system/doh-local.service` | systemd 服务，开机自启 |

**验证 DoH 链路是否正常**：
```bash
python3 -c "
import base64, urllib.request, ssl
name = b'\x04tgmt\x09yuebanshu\x03com\x00'
q = b'\xab\xcd\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00' + name + b'\x00\x01\x00\x01'
b64 = base64.urlsafe_b64encode(q).rstrip(b'=').decode()
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
resp = urllib.request.urlopen(f'https://127.0.0.1/dns-query?dns={b64}', context=ctx, timeout=5)
print('解析到 IP:', '.'.join(str(b) for b in resp.read()[-4:]))
# 预期输出: 解析到 IP: 127.0.0.1
"
```

---

## 八、客户端连接信息

| 项目 | 值 |
|------|----|
| 服务器 | `域名地址` |
| 端口 | `443` |
| 密钥 | `eec242c928b533db313878792ec28679756562这个是一串 生成的` |

**Telegram 一键链接**：
```
https://t.me/proxy?server=域名地址&port=443&secret=eec242c928b533db313878792ec242e79756562这个是一串 生成的
```

---

## 九、运维命令

```bash
# 查看 mtg 实时日志（正常状态只有启动消息，无 cannot resolve 报错）
journalctl -u mtg -f

# 检查所有服务状态
systemctl is-active mtg nginx doh-local

# 检查端口监听
ss -tlnp | grep -E ':443|:2026|:8053|:8443'
# 期望：
#   我的ip:443  → nginx stream（公网入口）
#   127.0.0.1:443    → nginx http（DoH + 回落）
#   127.0.0.1:8443   → nginx http（回落备用）
#   127.0.0.1:8053   → doh-local.py
#   0.0.0.0:2026     → mtg

# 重启全部
systemctl restart doh-local && systemctl restart nginx && systemctl restart mtg
```

---

## 十、常见问题速查

| 现象 | 原因 | 解决 |
|------|------|------|
| `cannot resolve dns names` 刷屏 | DoH 链路断了 | `systemctl status doh-local nginx`，检查 127.0.0.1:443 和 8053 |
| 延迟 450ms+ | secret/domain/cert 不一致，或未配置 `doh-ip` | 确认三者都是 `域名地址`，确认 `doh-ip = "127.0.0.1"` |
| nginx restart 后 127.0.0.1:443 没监听 | stream 绑了 `0.0.0.0:443` 占用所有接口 | stream 改为 `listen 我的ip:443` |
| 修改 hosts/resolv.conf 无效 | mtg 静态编译，自带 DoH，不走系统 DNS | 只有 `doh-ip` 配置项有效 |
| dnsmasq 安装后仍无效 | mtg 不走 UDP 53 | dnsmasq 对 mtg 无用，用 doh-local.py |
| nginx reload 后端口绑定没变 | stream 改绑 IP 后 reload 不生效 | 必须 `systemctl restart nginx` |
