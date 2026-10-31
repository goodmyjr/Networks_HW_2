import socket
import struct

from dns_parser import process_client_request, extract_ip_from_response
from dns_creator import create_request, create_response

ROOT_SERVER = "192.36.148.17"


def resolve_iterative(domain, request_id):
    target_ip = ROOT_SERVER
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2)

    try:
        for i in range(10):
            request = create_request(request_id, domain)
            try:
                sock.sendto(request, (target_ip, 53))
                response, _ = sock.recvfrom(4096)
            except socket.timeout:
                return None

            final_ip, next_ip = extract_ip_from_response(response)

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

            if qtype != 1:
                continue

            resolved_ip = resolve_iterative(domain, request_id)

            if resolved_ip:
                response = create_response(request_id, domain, resolved_ip)
                sock.sendto(response, addr)
    except KeyboardInterrupt:
        pass
    finally:
        sock.close()


if __name__ == "__main__":
    start_server()