import argparse
from socket import gethostbyname, AF_INET, SOCK_STREAM, SOCK_DGRAM
import socket
from multiprocessing.dummy import Pool as ThreadPool


def tcp_ports_scan(hostname: str, port_start: int, port_end: int, timeout:int = 2):
    ports = {
        'tcp': {
            'opened': [],
            'closed': []
        },
        'udp': {
            'opened': [],
            'closed': []
        }
    }

    def scan_udp_port(port: int):
        message = "This is a message, hello!"

        sock = socket.socket(AF_INET, SOCK_DGRAM)

        targetIP = gethostbyname(hostname)


        try:
            sock.sendto(message.encode('utf-8'),(targetIP, port))
            sock.settimeout(2)
            sock.recvfrom(4096)
            ports['udp']['opened'].append(port)

        except socket.timeout as err:
            ports['udp']['closed'].append(port)


        sock.close()

    def scan_tcp_port(port: int):
        s = socket.socket(AF_INET, SOCK_STREAM)
        s.settimeout(5)

        targetIP = gethostbyname(hostname)
        result = s.connect_ex((targetIP, port))

        if (result == 0):
            ports['tcp']['opened'].append(port)
        else:
            ports['tcp']['closed'].append(port)
        s.close()


    port_start = port_start if port_start > 0 else 0
    port_end = port_end if port_end < 65534 else 65534

    pool = ThreadPool(400)
    pool.map(scan_tcp_port, range(port_start, port_end + 1))
    pool.map(scan_udp_port, range(port_start, port_end + 1))
    pool.close()
    pool.join()

    return ports


def parse_args():
    parser = argparse.ArgumentParser(description="Scan TCP and UDP ports.")

    parser.add_argument("HOSTNAME", help="name of host to scan")
    parser.add_argument("MIN_PORT", help="min port of host to scan")
    parser.add_argument("MAX_PORT", help="max port of host to scan")
    parser.add_argument("-t", "--timeout", type=int, help="timeout in seconds", default=2)
    return vars(parser.parse_args())


if __name__ == '__main__':
    args = parse_args()
    ports = tcp_ports_scan(
        args['HOSTNAME'],
        int(args['MIN_PORT']),
        int(args['MAX_PORT']),
        int(args['timeout']))

    print('UDP opened ports')
    for udp_opened_port in ports['udp']['opened']:
        print(udp_opened_port)
    if len(ports['udp']['opened']) == 0:
        print('Not found.')
    print()

    print('TCP opened ports')
    for tcp_opened_port in ports['tcp']['opened']:
        print(tcp_opened_port)
    if len(ports['tcp']['opened']) == 0:
        print('Not found.')
