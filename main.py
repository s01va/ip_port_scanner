import os
from dotenv import load_dotenv
from scapy.all import sr1, send
from scapy.layers.inet import IP, ICMP, TCP
import ipaddress
import argparse
import concurrent.futures
import time


def ping_host(ip):
    try:
        packet = IP(dst=str(ip))/ICMP()
        reply = sr1(packet, timeout=5, verbose=0)
        if reply:
            return str(ip)
    except Exception as e:
        print(f"Error pinging {ip}: {e}")
    return None


def os_fingerprint(ip, tcp_ports):
    ttl_values = {
        64: ["Linux", "Unix", "macOS"],
        128: ["Windows"],
        255: ["Cisco IOS"]
    }

    try:
        # SYN scan to an open port
        for tcp_port in tcp_ports:
            ans = sr1(IP(dst=ip) / TCP(dport=tcp_port, flags="S"), timeout=2, verbose=0)
            if ans is None:
                # return "Unknown (No response)"
                continue

            if ans.haslayer(TCP):
                if ans[TCP].flags == 0x12:  # SYN-ACK
                    # Send RST to close the connection
                    send(IP(dst=ip) / TCP(dport=tcp_port, flags="R"), verbose=0)

                    ttl = ans.ttl
                    os_guess = "Unknown"
                    for known_ttl, os_list in ttl_values.items():
                        if ttl <= known_ttl:
                            os_guess = "/".join(os_list)
                            break

                    window_size = ans[TCP].window
                    if window_size == 65535:
                        os_guess += " (possibly FreeBSD)"
                    elif window_size == 65535:
                        os_guess += " (possibly Linux)"
                    elif window_size == 8192:
                        os_guess += " (possibly Windows)"

                    return f"Possible OS: {os_guess} (TTL: {ttl}, Window Size: {window_size})"
                else:
                    return "Unknown (Unexpected TCP flags)"
            else:
                # return "Unknown (No TCP layer)"
                continue
        return "Unknown (No Response/No TCP layer)"
    except Exception as e:
        return f"Error: {str(e)}"


def scan_port(ip, port):
    try:
        packet = IP(dst=ip)/TCP(dport=port, flags="S")
        response = sr1(packet, timeout=1, verbose=0)
        if response and response.haslayer(TCP):
            if response[TCP].flags == 0x12:  # SYN-ACK
                return port
    except Exception as e:
        print(f"Error scanning port {port} on {ip}: {e}")
    return None


def port_scan(ip, port_option: str):
    open_ports = []
    print(f"\nPerforming {port_option} port scan on {ip}")
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        if port_option == "wellknown":
            future_to_port = {executor.submit(scan_port, ip, port): port for port in range(1, 1024)}
        elif port_option == "full":
            future_to_port = {executor.submit(scan_port, ip, port): port for port in range(1, 65536)}
        for future in concurrent.futures.as_completed(future_to_port):
            port = future_to_port[future]
            try:
                result = future.result()
                if result:
                    open_ports.append(result)
                    print(f"Port {result} is open on {ip}")
            except Exception as exc:
                print(f'Port {port} on {ip} generated an exception: {exc}')
    print(f"Open ports on {ip}: {open_ports}")
    return open_ports


def check_hops(ip, max_hops=30):
    for ttl in range(1, max_hops + 1):
        pkt = IP(dst=ip, ttl=ttl) / ICMP()
        # Send the packet and get a reply
        reply = sr1(pkt, verbose=0, timeout=2)

        if reply is None:
            # No reply
            print(f"{ttl}: *")
        elif reply.type == 0:
            # We've reached our destination
            print(f"{ttl}: {reply.src} (destination reached)")
            return ttl
        elif reply.type == 11:
            # Time exceeded
            print(f"{ttl}: {reply.src}")
        else:
            print(f"{ttl}: {reply.src} (unexpected reply)")

    print("Destination not reached within maximum hops")
    return max_hops


def scan_ip_range(arg_ip_range, max_workers=100): #(start_ip, end_ip, max_workers=100)
    # start = ipaddress.IPv4Address(start_ip)
    # end = ipaddress.IPv4Address(end_ip)
    # ip_range = [ipaddress.IPv4Address(ip) for ip in range(int(start), int(end) + 1)]
    ip_range = list(ipaddress.ip_network(arg_ip_range))
    alive_hosts = []

    start_time = time.time()

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_ip = {executor.submit(ping_host, ip): ip for ip in ip_range}
        for future in concurrent.futures.as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                result = future.result()
                if result:
                    alive_hosts.append(result)
                    print(f"Host {result} is up")
                # else:
                #     print(f"Host {ip} is down")
            except Exception as exc:
                print(f'{ip} generated an exception: {exc}')

    end_time = time.time()
    duration = end_time - start_time

    print(f"\nTotal alive hosts: {len(alive_hosts)}")
    print("Alive hosts:", alive_hosts)
    print(f"Scan duration: {duration:.2f} seconds")

    return alive_hosts


def main(port_mode):
    ip_network_list = os.getenv("IPLIST").split(",")
    for ip_network in ip_network_list:
        alive_hosts = scan_ip_range(ip_network)

        for alive_host in alive_hosts:
            hops = check_hops(alive_host)
            print(f"{alive_host} hops: {hops}")
            if port_mode:
                open_ports = port_scan(alive_host, port_mode)
                os_info = os_fingerprint(alive_host, open_ports)
                print(os_info)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="-p | --port")
    parser.add_argument('--port', default=None, help="wellknown | full")
    args = parser.parse_args()
    load_dotenv(".env")
    main(port_mode=args.port)
