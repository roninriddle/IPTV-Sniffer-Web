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
        header = stream.read(24)
        if len(header) < 24:
            return
        orders = {b'\xd4\xc3\xb2\xa1':'<', b'\xa1\xb2\xc3\xd4':'>',
                  b'\x4d\x3c\xb2\xa1':'<', b'\xa1\xb2\x3c\x4d':'>'}
        endian = orders.get(header[:4])
        if not endian:
            raise ValueError('仅支持经典 PCAP（大小端／微秒／纳秒），请先将 pcapng 转换为 PCAP')
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
