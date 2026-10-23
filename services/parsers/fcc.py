"""Identify FCC client requests by their RTCP wire format, not UDP port guesses.

Protocol field reference: stackia/rtp2httpd src/fcc_{telecom,huawei}.c.
Only destination and multicast metadata are returned; STB identifiers are ignored.
"""
import ipaddress


def parse_fcc_request(payload, channel_ports):
    if len(payload) < 12 or payload[0] >> 6 != 2 or payload[1] != 205:
        return None
    size = (int.from_bytes(payload[2:4], "big") + 1) * 4
    if size > len(payload) or size < 12 or payload[0] & 0x20:
        return None
    fmt = payload[0] & 31
    if fmt == 2 and size >= 40:
        group = str(ipaddress.IPv4Address(payload[20:24]))
        port = int.from_bytes(payload[18:20], "big")
        protocol = "telecom"
    elif fmt == 5 and size == 32:
        group = str(ipaddress.IPv4Address(payload[8:12]))
        ports = channel_ports.get(group, set())
        # Huawei RSR does not carry the multicast port. An ambiguous channel
        # table must not associate one FCC request with multiple sources.
        if len(ports) != 1:
            return None
        port = next(iter(ports))
        protocol = "huawei"
    else:
        return None
    if not ipaddress.IPv4Address(group).is_multicast or not 1 <= port <= 65535:
        return None
    return {"ip": group, "port": port, "fcc_protocol": protocol}
