import struct
import socket


def pack_domain(domain):
    parts = domain.split('.')
    res = b''

    for part in parts:
        res += struct.pack('B', len(part)) + part.encode('ascii')

    return res + b'\x00'


def create_request(request_id, domain, qtype=1):
    header = struct.pack('!HHHHHH', request_id, 0x0000, 1, 0, 0, 0)
    question = pack_domain(domain) + struct.pack('!HH', qtype, 1)

    return header + question


def create_response(request_id, domain, ip, qtype=1):
    header = struct.pack('!HHHHHH', request_id, 0x8180, 1, 1, 0, 0)
    question = pack_domain(domain) + struct.pack('!HH', qtype, 1)

    if qtype == 1:
        ip_bytes = socket.inet_aton(ip)
    elif qtype == 28:
        ip_bytes = socket.inet_pton(socket.AF_INET6, ip)
    else:
        ip_bytes = b''

    answer = struct.pack('!HHHLH', 0xC00C, qtype, 1, 300, len(ip_bytes)) + ip_bytes

    return header + question + answer


def create_noerror_response(request_id, domain, qtype=1):
    header = struct.pack('!HHHHHH', request_id, 0x8180, 1, 0, 0, 0)
    question = pack_domain(domain) + struct.pack('!HH', qtype, 1)

    return header + question


def create_nxdomain_response(request_id, domain, qtype=1):
    header = struct.pack('!HHHHHH', request_id, 0x8183, 1, 0, 0, 0)
    question = pack_domain(domain) + struct.pack('!HH', qtype, 1)

    return header + question