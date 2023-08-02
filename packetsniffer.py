import socket
import struct
import sys

def parse_ip_header(data):
    ip_header = struct.unpack('!BBHHHBBH4s4s', data[:20])
    version_ihl = ip_header[0]
    version = version_ihl >> 4
    ihl = version_ihl & 0xF
    ttl = ip_header[5]
    protocol = ip_header[6]
    src_ip = socket.inet_ntoa(ip_header[8])
    dest_ip = socket.inet_ntoa(ip_header[9])
    return version, ihl, ttl, protocol, src_ip, dest_ip, data[ihl*4:]

def main():
    # Disable output buffering
    sys.stdout.flush()

    # Create a raw socket to capture packets (For Windows, use AF_INET and SOCK_RAW)
    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    interface_ip = find_interface_ip()

    if interface_ip:
        print(f"Sniffing packets on interface IP: {interface_ip}")
        sniffer.bind((interface_ip, 0))
    else:
        print("Could not find a valid non-loopback interface IP.")
        return

    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    try:
        while True:
            packet = sniffer.recvfrom(65535)
            data = packet[0]
            version, ihl, ttl, protocol, src_ip, dest_ip, data = parse_ip_header(data)
            print(f"Version: {version}, IHL: {ihl}, TTL: {ttl}, Protocol: {protocol}, Source IP: {src_ip}, Destination IP: {dest_ip}")

    except KeyboardInterrupt:
        print("Packet sniffing stopped.")
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

def find_interface_ip():
    interfaces = socket.gethostbyname_ex(socket.gethostname())[2]
    for ip in interfaces:
        if not ip.startswith("127."):
            return ip
    return None

if __name__ == "__main__":
    main()

