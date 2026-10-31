import socket
import struct

from dns_parser import process_client_request, extract_ip_from_response
from dns_creator import create_request, create_response, create_noerror_response, create_nxdomain_response

ROOT_SERVER = "192.36.148.17"


def resolve_iterative(domain, request_id, qtype):
    target_ip = ROOT_SERVER
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)

    try:
        for i in range(10):
            request = create_request(request_id, domain, qtype)
            try:
                sock.sendto(request, (target_ip, 53))
                response, _ = sock.recvfrom(4096)
            except socket.timeout:
                return None

            final_ip, next_ip = extract_ip_from_response(response, qtype)

            if final_ip:
                return final_ip
            if next_ip:
                target_ip = next_ip
            else:
                return None

        return None
    finally:
        sock.close()


def start_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 53))
    try:
        while True:
            data, addr = sock.recvfrom(1024)

            if len(data) < 12:
                continue

            try:
                request_id, domain, qtype = process_client_request(data)
            except (struct.error, IndexError, UnicodeDecodeError):
                continue

            if qtype not in (1, 28):
                response = create_noerror_response(request_id, domain, qtype)
                sock.sendto(response, addr)
                continue

            if qtype == 1 and ".multiply." in f".{domain}.":
                multiply_ip = calculate_multiply_ip(domain)

                if multiply_ip:
                    response = create_response(request_id, domain, multiply_ip, qtype=1)
                    sock.sendto(response, addr)
                    continue

            resolved_ip = resolve_iterative(domain, request_id, qtype)

            if resolved_ip:
                response = create_response(request_id, domain, resolved_ip, qtype)
                sock.sendto(response, addr)
            else:
                response = create_nxdomain_response(request_id, domain, qtype)
                sock.sendto(response, addr)
    except KeyboardInterrupt:
        pass
    finally:
        sock.close()


def calculate_multiply_ip(domain):
    parts = domain.strip('.').split('.')

    if "multiply" not in parts:
        return None

    multiply_index = parts.index("multiply")
    prefix = parts[:multiply_index]

    if not prefix:
        return None

    product = 1

    for item in prefix:
        if not item.isdigit():
            return None

        product = (product * int(item)) % 256

    return f"127.0.0.{product}"


if __name__ == "__main__":
    start_server()