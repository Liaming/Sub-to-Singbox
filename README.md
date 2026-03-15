
# Sing-box Subscription Converter 🚀

一个专为 [Sing-box](https://sing-box.sagernet.org/) 打造的高阶 Python 订阅转换与管理脚本。

本项目旨在将传统的机场订阅链接（Base64 格式）安全、高效地转换为 **Sing-box 1.13+** 兼容的 `config.json` 配置文件。彻底抛弃了已被官方废弃的 FakeIP 机制，全面拥抱 **"真实 DNS + Sniff"** 的最佳实践架构，确保防泄漏、高兼容与极致的网络性能。

## ✨ 核心特性

- **🚀 完美适配最新内核**：严格符合 Sing-box 1.13.x 标准，采用最新的真实 DNS 分流与嗅探机制（Sniffing），解决 FakeIP 导致的银行/企业 APP 阻断及 UDP/WebRTC 异常。
- **🌐 全协议深度解析**：支持 `VMess`, `VLESS`, `Trojan`, `Shadowsocks`, `Hysteria2`, `TUIC`。
- **🛡️ 进阶参数支持**：精准提取并转换 `Reality` (pbk, sid), `ECH`, 官方合规的 `uTLS` 指纹, `ALPN`, `WS/gRPC` 传输层配置及主机名（SNI）伪装回退。
- **⚙️ 工业级健壮性**：
  - 内置多端随机 User-Agent 池，防机场 WAF 拦截。
  - 网络波动 3 次指数退避重试机制。
  - 隐形 BOM 头清洗与畸形节点安全过滤。
  - 精准的深度去重逻辑（协议+IP+端口防重），防止机场恶意“凑数”。
- **📊 智能统计反馈**：运行结束自动分类统计节点协议数量，并提供解析建议。
- **☁️ Gist 云端同步**：支持一键将生成的配置文件自动同步至 GitHub Gist，方便多端设备通过 Raw 链接远程在线订阅。
- **🔒 安全隐私**：核心敏感信息（订阅链接、Token）全部通过 `.env` 环境变量注入，代码完全开源无惧隐私泄漏。

## 📦 安装与配置

### 1. 环境要求

- Python 3.8+
- [Git](https://git-scm.com/)

### 2. 克隆项目

```bash
git clone [https://github.com/Liaming/Sub-to-Singbox.git](https://github.com/Liaming/Sub-to-Singbox.git)
cd Sub-to-Singbox
```

### 3. 配置虚拟环境并安装依赖

```bash
# 创建虚拟环境
python -m venv venv

# 激活虚拟环境 (Windows)
.\venv\Scripts\activate

# 激活虚拟环境 (Mac/Linux)
source venv/bin/activate

# 安装依赖模块
pip install requests python-dotenv

```

### 4. 配置环境变量

在项目根目录下创建一个名为 `.env` 的文件，填入以下内容：

```env
# 必须：你的机场订阅链接
SUB_URL=[https://your-subscription-link.com/xxx](https://your-subscription-link.com/xxx)

# 可选：GitHub Gist 同步配置 (如不需要同步到云端，请留空)
GIST_ID=你的Gist_ID (例如: e5c829...)
GIST_TOKEN=你的GitHub_Personal_Access_Token (例如: ghp_xxxx...)

```

> **注意**：如需使用 Gist 同步，请先在您的 GitHub Gist 创建一个名为 `config.json` 的机密片段 (Secret Gist)，获取其 ID 并生成对应的 Token。

## 🚀 使用方法

确保虚拟环境已激活，在终端运行以下命令：

```bash
python sub_to_singbox.py

```

运行成功后，脚本会在当前目录下生成 `config.json` 文件，并自动在终端输出协议统计详情。如果您配置了 Gist，终端会提示云端同步成功。

### 在 GUI 客户端中导入

- **[GUI.for.SingBox](https://github.com/GUI-for-Cores/GUI.for.SingBox)**：直接将生成的 `config.json` 导入，或替换原有配置即可。
- **[Clash Verge Rev](https://github.com/clash-verge-rev/clash-verge-rev)**：配置 -> 新建 -> 类型选择 `Sing-box` -> `本地文件`（选择生成的 config.json）或 `远程订阅`（填入您的 Gist Raw 链接）。

## 💡 常见问题 (FAQ)

**Q: 为什么运行后提示某些高级协议（如 Hysteria2 / TUIC）数量为 0？**
A: 脚本严格遵循主流 URI scheme 标准进行正则解析。如果数量为 0，通常是因为机场下发的 URI 格式非标准，或者机场后端的订阅转换器主动过滤了这类协议。这并非脚本解析错误或节点作假。

**Q: 为什么出站路由配置使用 1420 MTU 而不是标准的 1500或者9000？**
A: 虽然 9000 (Jumbo Frames) 理论上在纯局域网内吞吐量更大，但在广域网翻墙场景下，极易在运营商骨干网路由处遭遇分片（Fragmentation）或直接丢包。1500 是互联网绝对的工业标准，能提供最稳健的性能表现，但是需要注意的是当开启了代理后，虽然 1500 是物理网卡标准，但在代理场景下，加密报头会占用空间。如果设为 1500，封包后会超过公网限制导致丢包和分片，直接表现为视频缓冲转圈。1420 为加密留出了空间，确保了最高效的传输。。

## 📝 声明

本项目仅供学习与交流网络协议解析原理使用，请遵守当地法律法规，切勿用于任何非法用途。

```

```
