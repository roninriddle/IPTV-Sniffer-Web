"""Bounded untrusted downloads, decompression and classic PCAP records."""
import gzip
import io
import struct
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler

MAX_PCAP_BYTES = 128 * 1024 * 1024
MAX_PACKET_BYTES = 1024 * 1024
MAX_HTTP_BYTES = 16 * 1024 * 1024
MAX_XML_BYTES = 64 * 1024 * 1024


def validate_http_url(url):
    parts = urlsplit(url)
    if parts.scheme.lower() not in {'http', 'https'} or not parts.hostname or parts.username or parts.password:
        raise ValueError('仅允许不含用户名密码的 HTTP(S) 地址')
    if any(c in url for c in '\r\n\x00'):
        raise ValueError('URL 含非法控制字符')
    try:
        port = parts.port
    except ValueError:
        raise ValueError('URL 端口无效') from None
    if port is not None and not 1 <= port <= 65535:
        raise ValueError('URL 端口无效')
    return url


class HttpOnlyRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        validate_http_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def read_bounded(stream, limit):
    data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError('内容超过允许的字节上限')
    return data


def gunzip_bounded(data, limit=MAX_XML_BYTES):
    with gzip.GzipFile(fileobj=io.BytesIO(data)) as stream:
        return read_bounded(stream, limit)


def iter_pcap_packets(path):
    if Path(path).stat().st_size > MAX_PCAP_BYTES:
        raise ValueError('PCAP 超过 128 MiB 解析上限，请拆分后重试')
    with open(path, 'rb') as stream:
        magic = stream.read(4)
        stream.seek(0)
        if magic == b'\x0a\x0d\x0d\x0a':
            yield from _iter_pcapng_packets(stream)
            return
        header = stream.read(24)
        if len(header) < 24:
            return  # A live capture may not have flushed its global header yet.
        orders = {b'\xd4\xc3\xb2\xa1':'<', b'\xa1\xb2\xc3\xd4':'>',
                  b'\x4d\x3c\xb2\xa1':'<', b'\xa1\xb2\x3c\x4d':'>'}
        endian = orders.get(header[:4])
        if not endian:
            raise ValueError('仅支持 PCAP 或 PCAPNG 抓包文件')
        snaplen, linktype = struct.unpack(endian+'II',header[16:24])
        if linktype not in (1,113,276):
            raise ValueError('不支持的 PCAP 链路类型')
        consumed = 24
        while True:
            record = stream.read(16)
            if len(record) < 16:
                return  # A live capture may not yet have flushed the final record.
            size = struct.unpack(endian+'I',record[8:12])[0]
            if size > MAX_PACKET_BYTES or (snaplen and size > snaplen):
                raise ValueError('PCAP 包长度超过上限或 snaplen')
            consumed += 16 + size
            if consumed > MAX_PCAP_BYTES:
                raise ValueError('PCAP 超过解析字节上限')
            packet = stream.read(size)
            if len(packet) < size:
                return
            yield linktype, packet


def _iter_pcapng_packets(stream):
    """Yield common packet blocks from a bounded PCAPNG stream.

    PCAPNG can contain multiple sections and interfaces.  We intentionally
    accept only the link types understood by the IPTV parser, while safely
    skipping unrelated interfaces in a mixed capture.
    """
    interfaces = []
    endian = None
    consumed = 0
    yielded = 0
    supported = {1, 113, 276}
    while True:
        prefix = stream.read(12)
        if not prefix:
            break
        if len(prefix) < 12:
            raise ValueError('PCAPNG 数据块头不完整')
        is_section = prefix[:4] == b'\x0a\x0d\x0d\x0a'
        if is_section:
            bom = prefix[8:12]
            if bom == b'\x4d\x3c\x2b\x1a':
                endian = '<'
            elif bom == b'\x1a\x2b\x3c\x4d':
                endian = '>'
            else:
                raise ValueError('PCAPNG 字节序标记无效')
            block_type = 0x0A0D0D0A
            interfaces = []
        elif endian is None:
            raise ValueError('PCAPNG 缺少 Section Header Block')
        else:
            block_type = struct.unpack(endian + 'I', prefix[:4])[0]
        block_len = struct.unpack(endian + 'I', prefix[4:8])[0]
        if block_len < 12 or block_len % 4 or block_len > MAX_PACKET_BYTES + 65536:
            raise ValueError('PCAPNG 数据块长度无效或超过上限')
        rest = stream.read(block_len - 12)
        if len(rest) != block_len - 12:
            raise ValueError('PCAPNG 数据块不完整')
        block = prefix + rest
        if struct.unpack(endian + 'I', block[-4:])[0] != block_len:
            raise ValueError('PCAPNG 数据块长度校验失败')
        consumed += block_len
        if consumed > MAX_PCAP_BYTES:
            raise ValueError('PCAPNG 超过解析字节上限')
        body = block[8:-4]
        if block_type == 1:  # Interface Description Block
            if len(body) < 8:
                raise ValueError('PCAPNG 接口描述不完整')
            linktype = struct.unpack(endian + 'H', body[:2])[0]
            snaplen = struct.unpack(endian + 'I', body[4:8])[0]
            interfaces.append((linktype, snaplen))
            continue
        interface_id = None
        captured_len = None
        packet_start = None
        if block_type == 6:  # Enhanced Packet Block
            if len(body) < 20:
                raise ValueError('PCAPNG 增强包数据块不完整')
            interface_id, captured_len = struct.unpack(endian + 'II', body[:8])[0], struct.unpack(endian + 'I', body[12:16])[0]
            packet_start = 20
        elif block_type == 3:  # Simple Packet Block, always interface zero
            if len(body) < 4:
                raise ValueError('PCAPNG 简单包数据块不完整')
            interface_id = 0
            original_len = struct.unpack(endian + 'I', body[:4])[0]
            snaplen = interfaces[0][1] if interfaces else 0
            captured_len = min(original_len, snaplen or original_len, len(body) - 4)
            packet_start = 4
        elif block_type == 2:  # Obsolete Packet Block
            if len(body) < 20:
                raise ValueError('PCAPNG 包数据块不完整')
            interface_id = struct.unpack(endian + 'H', body[:2])[0]
            captured_len = struct.unpack(endian + 'I', body[12:16])[0]
            packet_start = 20
        else:
            continue
        if interface_id is None or interface_id >= len(interfaces):
            raise ValueError('PCAPNG 数据包引用了不存在的接口')
        if captured_len is None or captured_len > MAX_PACKET_BYTES:
            raise ValueError('PCAPNG 数据包长度超过上限')
        packet = body[packet_start:packet_start + captured_len]
        if len(packet) != captured_len:
            raise ValueError('PCAPNG 数据包内容不完整')
        linktype = interfaces[interface_id][0]
        if linktype not in supported:
            continue
        yielded += 1
        yield linktype, packet
    if not interfaces:
        raise ValueError('PCAPNG 中没有接口描述')
    if not yielded and not any(linktype in supported for linktype, _ in interfaces):
        raise ValueError('PCAPNG 中没有受支持的 Ethernet、Linux SLL 或 SLL2 接口')
