import struct
import socket


def parse_header(data):
    return struct.unpack('!HHHHHH', data[:12])


def parse_domain(data, offset):
    domain = []
    pointer_position = offset
    jumped = False

    while True:
        length = data[offset]

        if length == 0:
            offset += 1
            break
        elif length >= 192:
            if not jumped:
                pointer_position = offset + 2
            offset = struct.unpack('!H', data[offset:offset + 2])[0] & 0x3FFF
            jumped = True
        else:
            offset += 1
            domain.append(data[offset:offset + length].decode('ascii'))
            offset += length

    if not jumped:
        pointer_position = offset

    return ('.'.join(domain), pointer_position)


def process_client_request(data):
    request_id, _, _, _, _, _ = parse_header(data)
    domain, offset = parse_domain(data, 12)
    qtype, _ = struct.unpack('!HH', data[offset:offset + 4])

    return request_id, domain, qtype


def extract_ip_from_response(data):
    _, _, _, an, ns, ar = parse_header(data)
    _, offset = parse_domain(data, 12)
    offset += 4

    final_ip = None
    next_server_ip = None

    def parse_section(count, is_answer_section):
        nonlocal offset, final_ip, next_server_ip

        for i in range(count):
            _, offset = parse_domain(data, offset)
            rtype, rclass, _, rdlength = struct.unpack('!HHIH', data[offset:offset + 10])
            offset += 10

            if rtype == 1 and rclass == 1 and rdlength == 4:
                ip = socket.inet_ntoa(data[offset:offset + 4])

                if is_answer_section and not final_ip:
                    final_ip = ip
                elif not is_answer_section and not next_server_ip:
                    next_server_ip = ip

            offset += rdlength

    parse_section(an, True)
    parse_section(ns, False)
    parse_section(ar, False)

    return (final_ip, next_server_ip)