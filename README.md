# dsh-lan-auth

**给 DeepSeek Harness 的 Web GUI 加一道「共享密码」门禁：局域网 / Tailscale 里的设备输一次密码就能用，登录状态记住一年。**

> 一个基于 [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness)（DSH）的**二次开发**项目：
> 自研的独立密码门禁进程 + 对第三方配对插件 [`@linxin666/dsh-remote-web-ui`](https://github.com/zhu1090093659/dsh-web) 的一处运行时改造。
> 不修改、也不重新分发 DSH 本体。

---

## 为什么需要它

DSH 的 Web GUI 只监听 `127.0.0.1`，而且它的 webserver 会直接拒绝 `0.0.0.0`（`webserver: host "0.0.0.0" is an unspecified (wildcard) address`）。
这是有意的安全设计，但也意味着：

- 手机、平板、另一台电脑**默认完全访问不到**这个 GUI；
- 生态里的配对插件走的是「一次性配对链接 + 二维码」路线 —— 适合自己给自己配对，不适合「家里/团队里几台设备都想用」的场景；
- 想改 `--host` 绑到 LAN，既会打断 `127.0.0.1` 上的内部链路（配对插件自己要用），又会把整个 GUI 暴露给同网段的所有人。

所以这个项目把「认证」放到 GUI 前面一层可替换的进程里：**共享密码 + 长期会话 cookie**。

## 它做什么

```
   手机 / 平板 / 另一台电脑
            │  http://<lan-ip>:3080  或  http://<tailscale-ip>:3080
            ▼
   ┌──────────────────────────┐
   │  dsh-lan-auth（本项目）   │
   │  · 密码页 / 验证码限速    │
   │  · 一年期签名 cookie      │
   │  · Host/Origin 改写       │
   │  · 注入 harness 会话 cookie│
   └────────────┬─────────────┘
                │  127.0.0.1:3080（只有本机可达）
                ▼
        DeepSeek Harness Web GUI
```

关键点：

1. **不改 harness 的监听**。它继续只绑 `127.0.0.1`，外部一律经过门禁。
2. **设备只持有门禁 cookie**（`HttpOnly`，默认 365 天）。harness 自己的浏览器会话 cookie 由门禁进程在服务端持有并注入；需要时它从 `journalctl --user -u dsh-web` 里取当前进程的启动 token 重新兑换，所以 `dsh web` 重启后门禁自动恢复。
3. **监听地址自动跟随网卡**。每 60 秒枚举一次非回环 IPv4（跳过 `lo` / `docker*` / `br-*` / `veth*`），路由器重新分配 IP、Tailscale 重连都不需要改配置。
4. **顺手去掉配对遮罩**。已经用密码认证了，再弹「此设备未配对，无法访问工作区数据」就是多余的 —— `scripts/patch-remote-web-ui.js` 对插件做一处最小改造，让客户端不再强制走配对通道。

## 特性

- 零依赖（只用 Node 内置模块），单文件服务
- 密码用 **scrypt**（N=16384, r=8, p=1，随机盐）存储，文件 `0600`
- 会话 cookie **HMAC-SHA256** 签名、常量时间校验、可设置有效期
- 失败限速：同一来源 IP 10 分钟内最多 8 次
- 完整代理：普通 HTTP、流式响应、**WebSocket upgrade**（GUI 的实时通道）
- 深链接：未登录访问 `/settings?tab=x` → 登录后回到原地址
- 改密码即时生效（每次登录重读密码文件）
- systemd 用户单元，开机自启

## 快速开始

```bash
git clone <this repo> dsh-lan-auth
cd dsh-lan-auth

# 安装 + 设置访问密码 + 起服务（systemd user）
./install.sh

# 去掉配对插件那层「未配对」遮罩（改动 lib/client.js，插件升级后需重跑）
node scripts/patch-remote-web-ui.js

# 看状态
systemctl --user status dsh-lan-auth.service
ss -tln | grep 3080
```

然后在同一网络（或同一 Tailscale 网络）的设备上打开 `http://<本机地址>:3080`，输入密码即可。

不想用 systemd：

```bash
./install.sh --no-systemd
DSH_LAN_AUTH_UNIT=dsh-web node ~/.local/share/dsh-lan-auth/server.js
```

## 配置

全部通过环境变量（systemd 单元里用 `Environment=` 或 drop-in 覆盖）：

| 变量 | 默认值 | 说明 |
|---|---|---|
| `DSH_LAN_AUTH_PORT` | `3080` | 对外监听端口（与 harness 的端口相同，不同地址） |
| `DSH_LAN_AUTH_UPSTREAM` | `127.0.0.1:3080` | 被代理的 harness 地址，必须是回环权威 |
| `DSH_LAN_AUTH_UNIT` | `dsh-web` | systemd 用户单元名，用于取启动 token |
| `DSH_LAN_AUTH_EXTRA_HOSTS` | 空 | 额外监听的地址，逗号分隔，例如固定 IP |
| `DSH_LAN_AUTH_STATE_DIR` | `~/.config/dsh-lan-auth` | 密钥 / 密码记录 / cookie 缓存目录 |
| `DSH_LAN_AUTH_COOKIE` | `dsh_lan_auth` | cookie 名 |
| `DSH_LAN_AUTH_MAX_AGE_DAYS` | `365` | 登录有效期（天） |

改密码：

```bash
node ~/.local/share/dsh-lan-auth/server.js --set-password '<new-password>'
```

想让所有已登录设备立即失效（重新输密码），轮换签名密钥：

```bash
rm ~/.config/dsh-lan-auth/secret
systemctl --user restart dsh-lan-auth.service
```

## 关于「二开」

这个仓库里的两部分性质不同，这里说清楚：

1. **`packages/lan-auth`**：原创代码，MIT。
2. **`scripts/patch-remote-web-ui.js`**：针对第三方插件 `@linxin666/dsh-remote-web-ui`（Apache-2.0）**已构建产物**的一处运行时补丁，
   作用是让 `remoteChannelRequired()` 直接返回 `false`。本仓库**不包含也不分发**该插件的任何源码或产物，
   脚本只在你本机已安装的副本上做字符串替换，并保留 `client.js.orig-<时间戳>` 备份。
   插件升级会覆盖补丁，重跑脚本即可。

配对插件本身是个很完整的实现（二维码配对、设备名册、Cloudflare 隧道、移动端适配层等），本项目的改造只关掉它的「配对闸门」，
其余能力（尤其是手机竖屏适配）保持不变。如果你需要的是「一对一授权」，直接用上游插件即可。

## 安全模型与边界

- 密码是**共享的**：知道密码的任何人都能拿到完整 GUI 控制权，包括工作区文件与终端。请按此评估风险。
- 局域网这一跳是明文 HTTP；Tailscale 链路本身加密。需要端到端 TLS 时，给 harness 配证书或在门禁前再套一层 HTTPS 反代。
- 门禁进程以你的用户身份运行，能读 `~/.dsh`、`journalctl`，也就能拿到 harness 的启动 token —— 这是设计使然（它必须代表你完成认证）。
- 失败限速按来源 IP，重启服务会清零；没有做账号体系，也没有做 2FA。
- 本项目与 DeepSeek 官方无关，也未被打包进任何官方发行版。

## 目录结构

```
packages/lan-auth/server.js     门禁 + 反向代理（单文件，零依赖）
scripts/patch-remote-web-ui.js  配对插件运行时补丁
deploy/dsh-lan-auth.service     systemd 用户单元模板
install.sh                      安装脚本
```

## 故障排查

| 现象 | 检查 |
|---|---|
| 502 / `harness 认证不可用` | `journalctl --user -u dsh-web \| grep 'dsh web:'` 是否有启动 token；门禁重启后会自动重新兑换 |
| 打不开 | `ss -tln \| grep 3080` 应看到 `127.0.0.1:3080` 与 LAN/Tailscale 地址上的 3080 |
| 登录后又回到密码页 | 检查浏览器是否禁用 cookie；cookie 名是否与 `DSH_LAN_AUTH_COOKIE` 一致 |
| 仍然弹「此设备未配对」 | 没跑 `scripts/patch-remote-web-ui.js`，或浏览器缓存了旧 bundle（强制刷新） |
| 换网后访问不了 | 等 60 秒让门禁重新枚举网卡，或 `systemctl --user restart dsh-lan-auth` |
| 忘记密码 | 删除 `~/.config/dsh-lan-auth/password` 后重新 `--set-password` |

## 许可

本项目代码以 [MIT](LICENSE) 发布。第三方组件的许可与归属见 [NOTICE](NOTICE)。

不提供任何担保，使用前请自行评估暴露面。
