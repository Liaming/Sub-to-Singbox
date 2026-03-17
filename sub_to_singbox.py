import requests
import base64
import json
import urllib.parse
import uuid
import os
import copy
import logging
import random
import time
import sys
from dotenv import load_dotenv

# ==========================================
# 0. 环境变量与基础配置
# ==========================================
# 优先加载同目录下的 .env 文件
load_dotenv()

SUB_URL = os.environ.get("SUB_URL", "")
OUTPUT_FILE = "config.json"
DEBUG_MODE = False  # 设为 True 可查看详细行号和解析日志

# Gist 云端同步配置
GIST_ID = os.environ.get("GIST_ID", "")
GIST_TOKEN = os.environ.get("GIST_TOKEN", "")

# 日志配置
log_level = logging.DEBUG if DEBUG_MODE else logging.INFO
logging.basicConfig(level=log_level, format='%(levelname)s: %(message)s')

# 随机 UA 池 (防机场 WAF 拦截)
UA_LIST = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36"
]

VALID_FINGERPRINTS = {"chrome", "firefox", "edge", "safari", "360", "qq", "ios", "android", "random", "randomized"}

# ==========================================
# 1. Sing-box 核心模板 (1.13+ 标准)
# ==========================================
TEMPLATE = {
    "log": {"level": "warn", "timestamp": True},
    "experimental": {
        "clash_api": {
            "external_controller": "127.0.0.1:9090",
            "external_ui": "ui",
            "external_ui_download_url": "https://github.com/MetaCubeX/Yacd-meta/archive/gh-pages.zip",
            "external_ui_download_detour": "proxy",
            "default_mode": "rule"
        },
        "cache_file": {"enabled": True, "path": "cache.db"}
    },
    "dns": {
        "listen": "127.0.0.1:5353",
        "servers": [
            {"tag": "remote_dns", "address": "https://1.1.1.1/dns-query", "detour": "proxy"},
            {"tag": "local_dns", "address": "https://dns.alidns.com/dns-query", "address_resolver": "bootstrap_dns", "detour": "direct"},
            {"tag": "bootstrap_dns", "address": "223.5.5.5", "detour": "direct"}
        ],
        "rules": [
            {"domain_suffix": [".local", ".lan"], "server": "local_dns"},
            {"clash_mode": "direct", "server": "local_dns"},
            {"clash_mode": "global", "server": "remote_dns"},
            {"rule_set": "geosite-cn", "server": "local_dns"},
            {"rule_set": "geosite-geolocation-!cn", "server": "remote_dns"}
        ],
        "independent_cache": True,
        "final": "remote_dns",
        "strategy": "ipv4_only" 
    },
    "inbounds": [
        {
            "type": "tun", "tag": "tun-in", "interface_name": "singbox-tun",
            "inet4_address": "198.18.0.1/16", "mtu": 1420, "auto_route": True,
            "strict_route": True, "stack": "system", "sniff": True, "sniff_override_destination": True
        },
        {
            "type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1",
            "listen_port": 2080, "sniff": True
        }
    ],
    "outbounds": [
        {"type": "selector", "tag": "proxy", "outbounds": ["auto"], "default": "auto"},
        {"type": "urltest", "tag": "auto", "outbounds": [], "url": "https://www.gstatic.com/generate_204", "interval": "10m", "tolerance": 50},
        {"type": "direct", "tag": "direct"},
        {"type": "block", "tag": "block"},
        {"type": "dns", "tag": "dns-out"}
    ],
    "route": {
        "rule_set": [
            {
                "type": "remote", "tag": "geosite-cn", "format": "binary", 
                "url": "https://testingcf.jsdelivr.net/gh/SagerNet/sing-geosite@rule-set/geosite-cn.srs", 
                "download_detour": "direct"
            },
            {
                "type": "remote", "tag": "geosite-geolocation-!cn", "format": "binary", 
                "url": "https://testingcf.jsdelivr.net/gh/SagerNet/sing-geosite@rule-set/geosite-geolocation-!cn.srs", 
                "download_detour": "direct"
            },
            {
                "type": "remote", "tag": "geosite-category-ads-all", "format": "binary", 
                "url": "https://testingcf.jsdelivr.net/gh/SagerNet/sing-geosite@rule-set/geosite-category-ads-all.srs", 
                "download_detour": "direct"
            },
            {
                "type": "remote", "tag": "geoip-cn", "format": "binary", 
                "url": "https://testingcf.jsdelivr.net/gh/SagerNet/sing-geoip@rule-set/geoip-cn.srs", 
                "download_detour": "direct"
            }
        ],
        "rules": [
            # --- 1. 底层核心防线 (防漏水、防超时) ---
            { "protocol": "dns", "action": "hijack-dns" },
            { "port": 53, "action": "hijack-dns" },
            { "protocol": ["stun", "quic"], "action": "reject" },
            { "port": 853, "action": "reject" },
            { "network": "udp", "port": [443, 784, 8853], "action": "reject" },

            # --- 2. 🌟 手动添加自定义规则的位置 🌟 ---
            # 规则匹配是从上到下的，越靠上优先级越高。你的个性化规则应该写在这里。
            
            # 示例 A：按进程名分流 (雷电模拟器直连)
            { "process_name": ["dnplayer.exe", "LdVBoxHeadless.exe", "leidian.exe"], "outbound": "direct" },
            
            # 示例 B：按域名后缀阻断 (拦截 Autodesk 验证)
            { "domain_suffix": ["autodesk.com"], "action": "reject" },
            
            # 示例 C：按域名后缀强制直连 (清华大学、本地测试域名)
            { "domain_suffix": ["tsinghua.edu.cn", "localhost", "ttek.site"], "outbound": "direct" },
            
            # 示例 D：按域名强制走代理 (AI 工具)
            { "domain_suffix": ["trae.ai"], "outbound": "proxy" },
            
            # 示例 E：放行 ICMP 协议 (让你在终端 ping 网址时能通，方便测试网络)
            { "network": "icmp", "outbound": "direct" },

            # --- 3. 宏观规则集 (补全你漏掉的两个规则) ---
            # 补全漏掉的广告拦截 (丢进黑洞)
            { "rule_set": "geosite-category-ads-all", "outbound": "block" },
            
            { "ip_is_private": True, "outbound": "direct" },
            { "rule_set": "geosite-cn", "outbound": "direct" },
            
            # 补全漏掉的国内 IP 直连 (防止某些国内 App 走代理)
            { "rule_set": "geoip-cn", "outbound": "direct" },
            
            { "rule_set": "geosite-geolocation-!cn", "outbound": "proxy" },
            
            # --- 4. 最终兜底 ---
            { "outbound": "proxy" }
        ],
        "auto_detect_interface": True
    }
}

# ==========================================
# 2. 核心解码与解析功能
# ==========================================
def safe_base64_decode(data):
    data = data.strip().replace('\n', '').replace('\r', '')
    missing = len(data) % 4
    if missing: data += "=" * (4 - missing)
    try:
        return base64.urlsafe_b64decode(data).decode('utf-8-sig')
    except Exception:
        try: return base64.b64decode(data).decode('utf-8-sig')
        except Exception: return ""

def validate_port(port):
    if not port: return False
    try:
        p = int(port)
        return 1 <= p <= 65535
    except ValueError:
        return False

def parse_vmess(url, line_no):
    try:
        raw = url.replace("vmess://", "")
        data_str = safe_base64_decode(raw)
        if not data_str: return None
        data = json.loads(data_str)
        
        if not validate_port(data.get("port")): return None
        
        node = {
            "type": "vmess",
            "tag": data.get("ps", "vmess-" + str(uuid.uuid4())[:6]),
            "server": data["add"],
            "server_port": int(data["port"]),
            "uuid": data["id"],
            "alter_id": int(data.get("aid", 0)),
            "security": "auto"
        }
        if data.get("net") == "ws":
            target_host = data.get("host") or data.get("sni") or data.get("add")
            node["transport"] = {"type": "ws", "path": data.get("path", "/"), "headers": {"Host": target_host}}
        if data.get("tls") == "tls":
            node["tls"] = {"enabled": True, "server_name": data.get("sni", data.get("host", data["add"]))}
            fp = str(data.get("fp", "")).lower()
            if fp in VALID_FINGERPRINTS: node["tls"]["utls"] = {"enabled": True, "fingerprint": fp}
        return node
    except Exception as e:
        logging.debug(f"[Line {line_no}] VMESS 解析失败: {e}")
        return None

def parse_vless(url, line_no):
    try:
        u = urllib.parse.urlparse(url)
        q = urllib.parse.parse_qs(u.query)
        if not validate_port(u.port): return None
        
        node = {
            "type": "vless",
            "tag": urllib.parse.unquote(u.fragment or "vless"),
            "server": u.hostname,
            "server_port": u.port,
            "uuid": u.username
        }
        
        if q.get("flow"): node["flow"] = q.get("flow")[0]

        if q.get("security") in [["tls"], ["reality"]]:
            node["tls"] = {"enabled": True, "server_name": q.get("sni", [u.hostname])[0]}
            if q.get("alpn"): 
                alpn_list = [a.strip() for a in q.get("alpn")[0].split(",") if a.strip()]
                if alpn_list: node["tls"]["alpn"] = alpn_list
                
            fp = q.get("fp", [""])[0].lower()
            if fp in VALID_FINGERPRINTS: node["tls"]["utls"] = {"enabled": True, "fingerprint": fp}
            if q.get("ech") and q.get("ech")[0] != "0": node["tls"]["ech"] = {"enabled": True}
                
            if q.get("security") == ["reality"]:
                node["tls"]["reality"] = {"enabled": True}
                if q.get("pbk"): node["tls"]["reality"]["public_key"] = q.get("pbk")[0]
                if q.get("sid"): node["tls"]["reality"]["short_id"] = q.get("sid")[0]
                
        t = q.get("type", ["tcp"])[0]
        if t == "ws":
            target_host = q.get("host", [q.get("sni", [u.hostname])[0]])[0]
            node["transport"] = {"type": "ws", "path": q.get("path", ["/"])[0], "headers": {"Host": target_host}}
        elif t == "grpc":
            if q.get("serviceName"): node["transport"] = {"type": "grpc", "service_name": q.get("serviceName")[0]}
        return node
    except Exception as e:
        logging.debug(f"[Line {line_no}] VLESS 解析失败: {e}")
        return None

def parse_trojan(url, line_no):
    try:
        u = urllib.parse.urlparse(url)
        q = urllib.parse.parse_qs(u.query)
        if not validate_port(u.port): return None
        
        sni_val = q.get("sni", [u.hostname])[0]
        node = {
            "type": "trojan", "tag": urllib.parse.unquote(u.fragment or "trojan"),
            "server": u.hostname, "server_port": u.port, "password": u.username,
            "tls": {"enabled": True, "server_name": sni_val}
        }
        
        fp = q.get("fp", [""])[0].lower()
        if fp in VALID_FINGERPRINTS: node["tls"]["utls"] = {"enabled": True, "fingerprint": fp}
        if q.get("ech") and q.get("ech")[0] != "0": node["tls"]["ech"] = {"enabled": True}
            
        t = q.get("type", ["tcp"])[0]
        if t == "ws":
            target_host = q.get("host", [sni_val])[0]
            node["transport"] = {"type": "ws", "path": q.get("path", ["/"])[0], "headers": {"Host": target_host}}
        elif t == "grpc":
            if q.get("serviceName"): node["transport"] = {"type": "grpc", "service_name": q.get("serviceName")[0]}
        return node
    except Exception as e:
        logging.debug(f"[Line {line_no}] TROJAN 解析失败: {e}")
        return None

def parse_ss(url, line_no):
    try:
        u = urllib.parse.urlparse(url)
        if not validate_port(u.port): return None
        raw = urllib.parse.unquote(u.username)
        try:
            cred = safe_base64_decode(raw)
            if ":" not in cred: cred = raw
        except Exception:
            cred = raw
            
        try: method, password = cred.split(":", 1)
        except ValueError: return None
            
        return {
            "type": "shadowsocks", "tag": urllib.parse.unquote(u.fragment or "ss"),
            "server": u.hostname, "server_port": u.port, "method": method, "password": password
        }
    except Exception as e:
        logging.debug(f"[Line {line_no}] SS 解析失败: {e}")
        return None

def parse_hysteria2(url, line_no):
    try:
        u = urllib.parse.urlparse(url)
        q = urllib.parse.parse_qs(u.query)
        if not validate_port(u.port): return None
        
        auth = u.password or u.username
        auth = urllib.parse.unquote(auth) if auth else ""
        
        node = {
            "type": "hysteria2", "tag": urllib.parse.unquote(u.fragment) or "hy2-" + str(uuid.uuid4())[:6],
            "server": u.hostname, "server_port": u.port, "password": auth,
            "tls": {"enabled": True, "server_name": q.get("sni", [u.hostname])[0]}
        }
        if q.get("insecure") == ["1"]: node["tls"]["insecure"] = True
        if q.get("obfs"): node["obfs"] = {"type": q.get("obfs")[0], "password": q.get("obfs-password", [""])[0]}
        return node
    except Exception as e:
        logging.debug(f"[Line {line_no}] Hysteria2 解析失败: {e}")
        return None

def parse_tuic(url, line_no):
    try:
        u = urllib.parse.urlparse(url)
        q = urllib.parse.parse_qs(u.query)
        if not validate_port(u.port): return None
        
        node = {
            "type": "tuic", "tag": urllib.parse.unquote(u.fragment) or "tuic-" + str(uuid.uuid4())[:6],
            "server": u.hostname, "server_port": u.port,
            "uuid": urllib.parse.unquote(u.username) if u.username else "",
            "password": urllib.parse.unquote(u.password) if u.password else "",
            "tls": {"enabled": True, "server_name": q.get("sni", [u.hostname])[0]},
            "congestion_control": q.get("congestion_control", ["bbr"])[0]
        }
        alpn_list = [a.strip() for a in q.get("alpn", ["h3"])[0].split(",") if a.strip()]
        if alpn_list: node["tls"]["alpn"] = alpn_list
        return node
    except Exception as e:
        logging.debug(f"[Line {line_no}] TUIC 解析失败: {e}")
        return None

# ==========================================
# 3. 核心流程控制 (含重试机制)
# ==========================================
def fetch_nodes():
    if not SUB_URL:
        raise ValueError("未读取到有效的订阅链接 (SUB_URL)，请检查 .env 文件。")

    max_retries = 3
    resp = None
    
    for attempt in range(max_retries):
        try:
            headers = {"User-Agent": random.choice(UA_LIST)}
            logging.info(f"正在下载订阅 (尝试 {attempt + 1}/{max_retries})...")
            resp = requests.get(SUB_URL, headers=headers, timeout=15)
            resp.raise_for_status()
            break
        except Exception as e:
            if attempt < max_retries - 1:
                time.sleep(2 ** attempt)
                continue
            raise RuntimeError(f"订阅下载失败，已重试 {max_retries} 次: {e}")

    if len(resp.text) > 10_000_000:
        raise RuntimeError("订阅内容异常庞大(>10MB)，为防止内存溢出拒绝解析。")

    data = safe_base64_decode(resp.text)
    nodes = []
    physical_seen = {}
    name_seen = {}

    logging.info("正在解析节点...")
    for line_no, line in enumerate(data.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#") or line.startswith(";"): continue
            
        n = None
        if line.startswith("vmess://"): n = parse_vmess(line, line_no)
        elif line.startswith("vless://"): n = parse_vless(line, line_no)
        elif line.startswith("trojan://"): n = parse_trojan(line, line_no)
        elif line.startswith("ss://"): n = parse_ss(line, line_no)
        elif line.startswith("hysteria2://") or line.startswith("hy2://"): n = parse_hysteria2(line, line_no)
        elif line.startswith("tuic://"): n = parse_tuic(line, line_no)
        elif DEBUG_MODE:
            logging.debug(f"[Line {line_no}] 未知或不支持的协议前缀。")

        if n:
            physical_id = f"{n['type']}:{n['server']}:{n['server_port']}:{n.get('uuid','')}"
            if physical_id in physical_seen: 
                logging.debug(f"[Line {line_no}] 发现物理重复节点已跳过: {physical_id}")
                continue 
            physical_seen[physical_id] = True

            tag = n["tag"]
            if tag in name_seen:
                name_seen[tag] += 1
                n["tag"] = f"{tag}_{name_seen[tag]}"
            else:
                name_seen[tag] = 1
                
            nodes.append(n)

    if not nodes:
        raise RuntimeError("解析完成，但未提取到任何有效节点。")

    return nodes

def is_real_node(node):
    """
    智能判断是否为真实的物理节点，用于过滤机场的提示/广告节点。
    """
    tag = str(node.get("tag", "")).lower()
    server = str(node.get("server", "")).lower()

    # 1. 过滤常见提示词 (拦截大部分常规提示词)
    ignore_keywords = [
        "剩余", "到期", "过期", "官网", "重置", "流量", "套餐", 
        "联系", "群", "频道", "公告", "通知", "获取", "请勿", "dont", "更新"
    ]
    if any(kw in tag for kw in ignore_keywords):
        return False

    # 2. 过滤虚假服务器地址 (直击底层，拦截率极高)
    fake_servers = ["127.0.0.1", "0.0.0.0", "8.8.8.8", "1.1.1.1", "localhost", "example.com"]
    if server in fake_servers:
        return False
        
    # 3. 拦截带有明显占位符特征的域名
    if "dont" in server or "fake" in server or "traffic" in server:
        return False

    return True

def build_config(nodes):
    config = copy.deepcopy(TEMPLATE)
    
    # 获取所有节点标签 (用于 proxy 手动选择组，让你依然能在面板看到通知)
    all_tags = [n["tag"] for n in nodes]
    
    # 筛选出真实的节点标签 (用于 auto 测速组，防止 DNS 解析报错)
    auto_tags = [n["tag"] for n in nodes if is_real_node(n)]
    
    # 智能分配策略组
    for out in config["outbounds"]:
        if out.get("tag") == "proxy":
            out["outbounds"].extend(all_tags)
        elif out.get("tag") == "auto":
            out["outbounds"].extend(auto_tags)
            
    # 将节点详情追加到配置末尾
    config["outbounds"].extend(nodes)
    return config

# ==========================================
# 4. 主程序入口
# ==========================================
if __name__ == "__main__":
    try:
        nodes = fetch_nodes()
        cfg = build_config(nodes)
        
        json_str = json.dumps(cfg, indent=2, ensure_ascii=False)
        json_str = json_str.replace('\u00a0', ' ')

        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            f.write(json_str)
        logging.info(f"✅ 成功: 共解析出 {len(nodes)} 个节点，本地文件已生成: {OUTPUT_FILE}")

        # --- 新增：协议统计与提示说明 ---
        stats = {}
        for n in nodes:
            proto = n.get('type', 'unknown')
            stats[proto] = stats.get(proto, 0) + 1
            
        logging.info("=" * 45)
        logging.info("📊 节点协议解析统计:")
        # 按数量倒序排列打印
        for proto, count in sorted(stats.items(), key=lambda x: x[1], reverse=True):
            logging.info(f"   - {proto.upper().ljust(12)}: {count} 个")
        logging.info("-" * 45)
        logging.info("💡 温馨提示：")
        logging.info("   如果您发现某些协议（如 Hysteria2 / TUIC 等）数量为 0，")
        logging.info("   通常是因为机场提供的 URI 格式非标准，或者您的订阅转")
        logging.info("   换规则过滤了该类高级协议。这并非脚本解析错误或机场")
        logging.info("   节点作假，请放心使用。")
        logging.info("=" * 45)
        # ---------------------------------

        if GIST_ID and GIST_TOKEN:
            logging.info(f">>> 检测到 Gist 配置，正在同步到 GitHub ({GIST_ID[:6]}...)...")
            
            upload_headers = {
                "Authorization": f"token {GIST_TOKEN}",
                "Accept": "application/vnd.github.v3+json"
            }
            payload = {
                "files": {
                    "config.json": {"content": json_str}
                }
            }
            
            r = requests.patch(
                f"https://api.github.com/gists/{GIST_ID}", 
                headers=upload_headers, 
                json=payload, 
                timeout=15
            )
            r.raise_for_status()
            logging.info("✅ Gist 远程同步成功！你的 Raw 链接已更新。")
        else:
            logging.info(">>> 未配置 GIST_ID 或 TOKEN，跳过云端同步。")
            
    except Exception as e:
        logging.error(f"执行中断: {e}")
        sys.exit(1)