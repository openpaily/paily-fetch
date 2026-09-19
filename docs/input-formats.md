# 输入格式

本文档介绍 Paily Fetch 如何解析订阅源内容、识别内容类型，以及支持哪些代理协议与节点表示。

## 订阅源内容语法

订阅源的 `content` 按行处理，每个非空行是一条独立指令。支持以下四种形式：

| 形式 | 行为 |
| --- | --- |
| `https://` 或 `http://` | 直接下载该地址，作为订阅内容。 |
| `expr:` | 使用 expr-lang 计算出一个 URL，再下载该地址。 |
| `exprdate:` | 把 URL 模板中的 `{y}`、`{m}`、`{d}` 替换为当前 UTC 日期后下载。 |
| `extract:` | 下载页面，从正文中提取 HTTP(S) 地址和代理分享链接。 |

示例：

```text
https://example.com/subscription.yaml
https://example.com/another-subscription
exprdate: https://example.com/sub/{y}{m}{d}.txt
expr: "https://example.com/sub/" + date.year + date.month + date.day
extract: https://example.com/landing-page
```

规则说明：

- `expr:` 的表达式运行在 UTC 日期上下文中，可引用 `date.year`、`date.month`、`date.day`（均为零填充字符串），返回值必须是 URL 字符串。
- `exprdate:` 是 `expr:` 的简化形式，只做日期占位符替换。
- `extract:` 提取出的 HTTP(S) 地址会作为订阅继续下载；提取出的代理分享链接会组合成一个内联列表，直接进入解析阶段。
- 同一来源的多条地址顺序下载，部分失败不影响其他地址；只有全部失败时该来源才视为抓取失败。

下载请求使用配置的 User-Agent，仅接受 2xx 响应，单个响应体最多读取 32 MiB。

## 散源内容语法

散源（`node`）不下载远程内容，直接解析 `content`。支持两种形式：

1. 单个代理分享链接。
2. Paily 节点封装 JSON：

```json
{
  "type": "mixed",
  "content": "vless://...\ntrojan://..."
}
```

其中 `type` 决定 `content` 的格式：

| `type` | `content` 格式 |
| --- | --- |
| `clash` | Clash/Mihomo YAML。 |
| `singbox` | Sing-box JSON。 |
| `mixed` | 每行一个代理分享链接。 |

若 JSON 封装解析失败，内容会作为单个代理分享链接处理。

## 内容识别顺序

对于下载得到的订阅内容，Paily Fetch 按以下顺序识别类型，识别失败时尝试对内容做 Base64 解码后再重复识别：

1. Paily 节点封装 JSON。
2. Sing-box JSON（顶层含 `outbounds`）。
3. Clash/Mihomo YAML（顶层含 `proxies`，或含 Clash 特征键）。
4. 分享链接列表（以已知协议开头）。
5. 上述内容的 Base64 编码。

## 支持的输入格式

除上述容器格式外，Paily Fetch 还能解析各类代理分享链接，并统一转换为 Clash/Mihomo 兼容表示。

支持解析的协议包括：

| 协议 | Scheme |
| --- | --- |
| VMess | `vmess://` |
| VLESS | `vless://` |
| Trojan | `trojan://` |
| Shadowsocks | `ss://` |
| ShadowsocksR | `ssr://` |
| Hysteria | `hysteria://`、`hy://` |
| Hysteria2 | `hysteria2://`、`hy2://` |
| TUIC | `tuic://` |
| WireGuard | `wireguard://`、`wg://` |
| SOCKS | `socks://`、`socks5://` |
| HTTP / HTTPS 代理 | `http://`、`https://` |
| AnyTLS | `anytls://` |
| Mieru | `mieru://`、`mierus://` |
| Sudoku | `sudoku://` |

## 校验与输出

每个解析出的节点都会经过 Mihomo 校验，未通过的节点会被丢弃。通过校验的节点统一转换为 Clash/Mihomo 兼容表示后上报给 Paily 主服务。
