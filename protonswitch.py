import os
import logging
import argparse
import signal
from scapy.all import IFACES, sniff, get_if_addr,bind_layers
from scapy.packet import Packet
from scapy.layers.isakmp import ISAKMP
from scapy.layers.inet import IP,UDP
from scapy.layers.inet6 import IPv6
from scapy.contrib.wireguard import Wireguard
import subprocess
import platform
import sys
import time
import ipaddress
import threading


send_to_vpn_time = 0.0
is_waiting_for_response = False
TIMEOUT_THRESHOLD = 3
system = platform.system()
protocol = ""
vpn_ip = None
my_ip = None
state_lock = threading.Lock()
def alert_user(message="ProtonSwitch Crashed or interrupted. Restart again."):
    global stop_sniffing
    stop_sniffing = True
    try:
        if system == "Linux":
            subprocess.run(["speaker-test", "-t", "sine", "-f", "1000", "-l", "1", "-s", "1"], timeout=1, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
        elif system == "Darwin":
            subprocess.run(["afplay", "/System/Library/Sounds/Ping.aiff"])
    except Exception as e:
        logging.warning(f"Failed to play alert sound: {e}")

    try:
        if system == "Linux":
            subprocess.run([
                "notify-send",
                "ProtonSwitch Alert",
                message,
                "-u", "critical",
                "-t", "5000"
            ])
        elif system == "Darwin":
            applescript = f'''
            display notification "{message}" with title "ProtonSwitch" sound name "Ping"
            '''
            subprocess.run(["osascript", "-e", applescript])
    except Exception as e:
        logging.warning(f"Failed to show desktop alert: {e}")
def alert_crash(exc_type, exc_value, exc_traceback):
    alert_user("ProtonSwitch Crashed!")

sys.excepthook = alert_crash
    

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("kill.log"),
        logging.StreamHandler(sys.stdout)
    ]
)

os_name = sys.platform.upper()
logging.info(f"[OS DETECTED]: {os_name}")

stop_sniffing = False

def is_same_subnet(ip1: str, ip2: str, prefix_len=24) -> bool:
    try:
        net1 = ipaddress.ip_network(f"{ip1}/{prefix_len}", strict=False)
        net2 = ipaddress.ip_network(f"{ip2}/{prefix_len}", strict=False)
        return net1.network_address == net2.network_address
    except Exception:
        return False
def bring_interfaces_up():
    logging.info("Executing network_up (bringing interfaces up)...")
    for ifc in IFACES.data:
        if ifc == "lo" or "loopback" in IFACES[ifc].description.lower():
            continue
        cmd = f"sudo ifconfig {ifc} up"
        if os.system(cmd) == 0:
            logging.info(f"[SUCCESS] {cmd}")
        else:
            logging.fatal(f"[FAIL] {cmd}")
    logging.info("All interfaces restored.")

def bring_interfaces_down():
    logging.info("Bringing all interfaces down...")
    for ifc in IFACES.data:
        if ifc == "lo":
            continue
        cmd = f"sudo ifconfig {ifc} down"
        if os.system(cmd) == 0:
            logging.info(f"[SUCCESS] {cmd}")
        else:
            logging.fatal(f"[FAIL] {cmd}")
    logging.info("All interfaces disabled. Run 'protonswitch up' to restore.")

def packet_callback(packet):
    global stop_sniffing

    try:

        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
        elif IPv6 in packet:
            src_ip = packet[IPv6].src
            dst_ip = packet[IPv6].dst
        else:
            return

        if not (is_same_subnet(src_ip, vpn_ip) or is_same_subnet(dst_ip, vpn_ip)):
            return

        if not packet.haslayer(UDP):
            return

        udp = packet[UDP]

        is_wireguard = False
        if hasattr(udp.payload, 'load') and isinstance(udp.payload.load, (bytes, bytearray)) and len(udp.payload.load) > 0:
            first_byte = udp.payload.load[0]
            is_wireguard = first_byte in (1, 2, 3, 4)

        is_isakmp = (udp.sport == 500 or udp.dport == 500) and packet.haslayer(ISAKMP)

        if not (is_wireguard or is_isakmp):
            return

        threading.Thread(
            target=heavy_packet_handler,
            args=(packet, src_ip, dst_ip, is_wireguard, is_isakmp),
            daemon=True
        ).start()

    except Exception as e:
        pass


def heavy_packet_handler(packet, src_ip, dst_ip, is_wireguard, is_isakmp):
    try:
        summary = packet.summary()
        logging.info(f"[PACKET DETECTED]: {summary}")

        if is_isakmp:
            isakmp_layer = packet[ISAKMP]
            if isakmp_layer.next_payload != 0:
                logging.info(f"[SKIPPED] Next Payload is {isakmp_layer.next_payload}")
                return
            bring_interfaces_down()
            global stop_sniffing
            stop_sniffing = True

        elif is_wireguard:
            global protocol, is_waiting_for_response, send_to_vpn_time
            protocol = "WIREGUARD"

            with state_lock:
                if src_ip == my_ip and is_same_subnet(dst_ip, vpn_ip):
                    if not is_waiting_for_response:
                        send_to_vpn_time = time.time()
                        is_waiting_for_response = True
                        logging.info("[TIMER STARTED] First request sent...")
                    else:
                        logging.info("[IGNORED] Additional request...")

                elif is_same_subnet(src_ip, vpn_ip) and dst_ip == my_ip:
                    if is_waiting_for_response:
                        is_waiting_for_response = False
                        send_to_vpn_time = 0.0
                        logging.info("[TIMER RESET] Response received.")
                    else:
                        logging.info("Unsolicited response...")

    except Exception as e:
        logging.error(f"Heavy handler error: {e}")

def is_process_running(pid):
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False

def start_sniffing_daemon(iface):
    logging.info("[FUNCTION EXECUTING] Start_sniffing_daemon...")
    global my_ip, stop_sniffing, is_waiting_for_response
    my_ip = get_if_addr(iface)
    if not my_ip:
        logging.error(f"Could not get IP for interface {iface}")
        print(f"Could not get IP for interface {iface}")
        sys.exit(1)
    network = str(ipaddress.IPv4Network(f"{vpn_ip}/24", strict=False).network_address)
    bpf_filter = f"net {network} mask 255.255.255.0"
    logging.info(f"Applied filter: {bpf_filter}")
    print(f"Starting daemon mode on {iface} for VPN IP {vpn_ip}")
    print("Logs written to kill.log")
    print("To stop: protonswitch off")


    def stop_handler(signum, frame):
        alert_user("ProtonSwitch Crashed!")

    signal.signal(signal.SIGTERM, stop_handler)
    signal.signal(signal.SIGINT, stop_handler)
    timer_thread = threading.Thread(target=timeout_checker, daemon=True)
    timer_thread.start()
    try:
        sniff(
            filter=bpf_filter,
            prn=packet_callback,
            store=False,
            iface=iface,
            stop_filter=lambda x: stop_sniffing
        )
    except KeyboardInterrupt:
        stop_sniffing = True
    finally:
        print("\nDaemon stopped gracefully.")

def timeout_checker():
    global is_waiting_for_response, send_to_vpn_time, stop_sniffing
    CHECK_INTERVAL = 0.5

    while not stop_sniffing:
        if is_waiting_for_response and protocol == 'WIREGUARD':
            elapsed = time.time() - send_to_vpn_time
            logging.info(f"[TIMER CHECK] Elapsed: {elapsed:.2f}s")
            if elapsed > TIMEOUT_THRESHOLD:
                logging.warning(f"[TIMEOUT TRIGGERED] No response for {elapsed:.2f}s!")
                bring_interfaces_down()
                stop_sniffing = True
                break 
        time.sleep(CHECK_INTERVAL)

def main():
    parser = argparse.ArgumentParser(
        description="ProtonSwitch Daemon: Monitor ISAKMP packets in background.",
        usage="protonswitch [on|up] [VPN_IP] [INTERFACE]"
    )
    parser.add_argument('mode', choices=['on', 'off', 'up'], help="Mode: on=start daemon, off=stop daemon, up=restore interfaces")
    parser.add_argument('vpn_ip', nargs='?', default=None, help="VPN server IP (required for 'on')")
    parser.add_argument('iface', nargs='?', default=None, help="Interface to capture on (required for 'on')")

    args = parser.parse_args()

    if args.mode == 'up':
        bring_interfaces_up()
    elif args.mode == 'on':
        if not args.vpn_ip or not args.iface:
            print("Error: VPN_IP and Protocol and INTERFACE are required for 'on' mode.")
            parser.print_help()
            sys.exit(1)
        global vpn_ip
        vpn_ip = args.vpn_ip.strip()
        start_sniffing_daemon(args.iface)

if __name__ == "__main__":
    main()