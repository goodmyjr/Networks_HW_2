import struct
import socket


def pack_domain(domain):
    parts = domain.split('.')
    res = b''

    for part in parts:
        res += struct.pack('B', len(part)) + part.encode('ascii')

    return res + b'\x00'


def create_request(request_id, domain):
    header = struct.pack('!HHHHHH', request_id, 0x0000, 1, 0, 0, 0)
    question = pack_domain(domain) + struct.pack('!HH', 1, 1)

    return header + question


def create_response(request_id, domain, ip):
    header = struct.pack('!HHHHHH', request_id, 0x8180, 1, 1, 0, 0)
    question = pack_domain(domain) + struct.pack('!HH', 1, 1)
    answer = struct.pack('!HHHLH', 0xC00C, 1, 1, 300, 4) + socket.inet_aton(ip)

    return header + question + answer