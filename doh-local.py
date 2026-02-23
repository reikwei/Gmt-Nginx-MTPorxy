#!/usr/bin/env python3
"""
极简本地 DoH 服务器 (RFC 8484)
- 域名.com -> 127.0.0.1 (本地直答，0ms)
- 其他域名 -> 转发 9.9.9.9
监听 HTTP 127.0.0.1:8053，由 nginx 提供 TLS
"""
import base64
import struct
import socket
import urllib.request
import ssl
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

# 本地覆盖记录 (域名小写 -> IP)
LOCAL_RECORDS = {
    "www.域名.com": "127.0.0.1",
}
UPSTREAM_DOH = "https://9.9.9.9/dns-query"


def parse_qname(data, offset):
    """解析 DNS 查询中的 QNAME，返回 (域名, 结束offset)"""
    labels = []
    visited = set()
    while True:
        if offset in visited:
            break
        visited.add(offset)
        length = data[offset]
        if length == 0:
            offset += 1
            break
        elif (length & 0xC0) == 0xC0:
            # 压缩指针
            ptr = ((length & 0x3F) << 8) | data[offset + 1]
            offset += 2
            sub, _ = parse_qname(data, ptr)
            labels.append(sub)
            break
        else:
            offset += 1
            labels.append(data[offset:offset + length].decode())
            offset += length
    return ".".join(labels), offset


def build_a_response(query_data, ip_str):
    """为 query_data 构造 A 记录 DNS 应答，返回 bytes"""
    txid = query_data[:2]
    question = query_data[12:]  # 从 QDCOUNT 后开始（header 12字节）
    # 找到 question 结尾：name + 4字节(qtype+qclass)
    i = 0
    while i < len(question):
        ln = question[i]
        if ln == 0:
            i += 1
            break
        i += ln + 1
    q_section = question[:i + 4]  # name + qtype(2) + qclass(2)

    ip_bytes = socket.inet_aton(ip_str)
    # DNS Header: ID, FLAGS=0x8180, QDCOUNT=1, ANCOUNT=1, NSCOUNT=0, ARCOUNT=0
    header = txid + b'\x81\x80' + b'\x00\x01' + b'\x00\x01' + b'\x00\x00' + b'\x00\x00'
    # Answer: 压缩指针指向 offset 12 (question name)
    answer = (b'\xc0\x0c'              # name ptr to offset 12
              + b'\x00\x01'            # type A
              + b'\x00\x01'            # class IN
              + b'\x00\x00\x01\x2c'   # TTL 300
              + b'\x00\x04'            # rdlength 4
              + ip_bytes)
    return header + q_section + answer


def forward_doh(raw_query):
    """把 DNS 二进制转发给 9.9.9.9 DoH，返回原始响应"""
    ctx = ssl.create_default_context()
    req = urllib.request.Request(
        UPSTREAM_DOH,
        data=raw_query,
        method="POST",
        headers={
            "Content-Type": "application/dns-message",
            "Accept": "application/dns-message",
        }
    )
    with urllib.request.urlopen(req, context=ctx, timeout=5) as resp:
        return resp.read()


class DoHHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # 静音日志

    def _get_dns_query(self):
        if self.command == "GET":
            qs = parse_qs(urlparse(self.path).query)
            dns_b64 = qs.get("dns", [None])[0]
            if not dns_b64:
                return None
            # base64url → bytes
            padding = 4 - len(dns_b64) % 4
            dns_b64 += "=" * (padding % 4)
            return base64.urlsafe_b64decode(dns_b64)
        elif self.command == "POST":
            length = int(self.headers.get("Content-Length", 0))
            return self.rfile.read(length) if length else None
        return None

    def handle_request(self):
        if not self.path.startswith("/dns-query"):
            self.send_error(404)
            return

        query = self._get_dns_query()
        if not query or len(query) < 17:
            self.send_error(400)
            return

        # 解析 QNAME
        try:
            qname, qend = parse_qname(query, 12)
            qname_lower = qname.rstrip(".").lower()
        except Exception:
            qname_lower = ""

        # 本地记录直答
        if qname_lower in LOCAL_RECORDS:
            # 只处理 A 记录查询 (qtype == 1)
            qtype = struct.unpack("!H", query[qend:qend+2])[0]
            if qtype == 1:
                response = build_a_response(query, LOCAL_RECORDS[qname_lower])
            else:
                # AAAA 等 -> 返回 NOERROR 无记录
                txid = query[:2]
                response = txid + b'\x81\x80\x00\x01\x00\x00\x00\x00\x00\x00' + query[12:]
        else:
            try:
                response = forward_doh(query)
            except Exception as e:
                self.send_error(502, str(e))
                return

        self.send_response(200)
        self.send_header("Content-Type", "application/dns-message")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)

    do_GET = handle_request
    do_POST = handle_request


if __name__ == "__main__":
    server = HTTPServer(("127.0.0.1", 8053), DoHHandler)
    print("DoH local server listening on 127.0.0.1:8053")
    server.serve_forever()
