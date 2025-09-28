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

bind_layers(UDP, Wireguard)
send_to_vpn_time = 0.0
is_waiting_for_response = False
TIMEOUT_THRESHOLD = 0.1
system = platform.system()
def alert_crash(exc_type, exc_value, exc_traceback):
    logging.fatal("CRASH DETECTED", exc_info=(exc_type, exc_value, exc_traceback))

    msg = f"ProtonSwitch has crashed!\n{exc_type.__name__}: {exc_value}"
    print(f"\n\n{msg}\n", file=sys.stderr)


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
                "ProtonSwitch Crashed!",
                "ProtonSwitch Crashed or interrupted restart again",
                "-u", "critical",
                "-t", "5000"
            ])
        elif system == "Darwin":
            applescript = f'''
            display notification "{"ProtonSwitch Crashed or interrupted restart again"}" with title "ProtonSwitch Crashed!" sound name "Ping"
            '''
            subprocess.run(["osascript", "-e", applescript])
    except Exception as e:
        logging.warning(f"Failed to show desktop alert: {e}")

sys.excepthook = alert_crash


logging.basicConfig(
    filename="kill.log",
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

os_name = sys.platform.upper()
logging.info(f"[OS DETECTED]: {os_name}")

stop_sniffing = False

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

def packet_callback(packet:Packet):
    global stop_sniffing, send_to_vpn_time, is_waiting_for_response
    current_time = time.time()
    logging.info(f"[PACKET DETECTED]: {packet.summary()}")
    print(f"\nPacket Detected: {packet.summary()}")
    if not (packet.haslayer(ISAKMP) or packet.haslayer(Wireguard)):
        return
    if packet.haslayer(ISAKMP) and protocol == 'ISAKMP':
        isakmp_layer = packet[ISAKMP]
        print(isakmp_layer.default_fields)
        if isakmp_layer.default_fields['next_payload'] != 0:
            logging.info(f"[SKIPPED] Next Payload is {isakmp_layer.next_payload}, not 0. Ignoring packet.")
            return  # Skip if not 0
        bring_interfaces_down()
        stop_sniffing = True


    if packet.haslayer(Wireguard) and protocol == 'WIREGUARD':
        ip_layer:IP|IPv6|None = None
        if packet.haslayer(IP):
            ip_layer = packet[IP]
        elif packet.haslayer(IPv6):
            ip_layer = packet[IPv6]
        else:
            return
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        logging.info(f"[WIREGUARD] src={src_ip} dst={dst_ip}")
        if src_ip == my_ip and dst_ip == vpn_ip:
            if not is_waiting_for_response:
                current_time = time.time()
                send_to_vpn_time = current_time
                is_waiting_for_response = True
                logging.info("[TIMER STARTED] First request sent to VPN server. Waiting for response...")
            else:
                logging.info("[IGNORED] Additional request while waiting for response.")
        elif src_ip == vpn_ip and dst_ip == my_ip:
            if is_waiting_for_response:
                is_waiting_for_response = False
                send_to_vpn_time = 0.0
                logging.info("[TIMER RESET] Response received from VPN server.")
            else:
                logging.info("Unsolicited response from VPN server (no pending request).")




def is_process_running(pid):
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False

def start_sniffing_daemon(iface):
    logging.info("[FUNCTION EXECUTING] Start_sniffing_daemon...")
    global my_ip, protocol, stop_sniffing, is_waiting_for_response
    my_ip = get_if_addr(iface)
    if not my_ip:
        logging.error(f"Could not get IP for interface {iface}")
        print(f"Could not get IP for interface {iface}")
        sys.exit(1)
    if protocol.upper() == 'ISAKMP':
        bpf_filter = f"src host {vpn_ip} and dst host {my_ip} and udp and (port 500 or port 4500)"
    elif protocol.upper() == 'WIREGUARD':
        bpf_filter = f"udp"
    logging.info(f"Applied filter: {bpf_filter}")
    print(f"Starting daemon mode on {iface} for VPN IP {vpn_ip} and protocol {protocol}")
    print("Logs written to kill.log")
    print("To stop: protonswitch off")


    def stop_handler(signum):
        global stop_sniffing
        stop_sniffing = True
        logging.info("[SNIFF STOPPED] by signal")
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
                    "ProtonSwitch Crashed!",
                    "ProtonSwitch Crashed or interrupted restart again",
                    "-u", "critical",
                    "-t", "5000"
                ])
            elif system == "Darwin":
                applescript = f'''
                display notification "protonswitch crashed or interrupted restart again" with title "Protonswitch" subtitle "Important Info" sound name "Ping"
                '''
                subprocess.run(["osascript", "-e", applescript])
        except Exception as e:
            logging.warning(f"Failed to show desktop alert: {e}")

    signal.signal(signal.SIGTERM, stop_handler)
    signal.signal(signal.SIGINT, stop_handler)
    print("bpf filter:", bpf_filter)
    SNIFF_TIMEOUT = 0.5
    try:
        while not stop_sniffing:
            sniff(
                filter=bpf_filter,
                prn=packet_callback,
                store=False,
                iface=iface,
                timeout=SNIFF_TIMEOUT,
                stop_filter=lambda x: stop_sniffing
            )

            if is_waiting_for_response and protocol.upper() == 'WIREGUARD':
                elapsed = time.time() - send_to_vpn_time
                if int(elapsed * 2) % 1 == 0:
                    logging.info(f"[TIMER CHECK] Elapsed: {elapsed:.2f}s")
                if elapsed > TIMEOUT_THRESHOLD:
                    logging.warning(f"[TIMEOUT TRIGGERED] No response for {elapsed:.2f}s!")
                    bring_interfaces_down()
                    stop_sniffing = True
    except KeyboardInterrupt:
        pass
    finally:
        print("\nDaemon stopped gracefully.")

def monitor_timeout():
    ""
def main():
    parser = argparse.ArgumentParser(
        description="ProtonSwitch Daemon: Monitor ISAKMP packets in background.",
        usage="protonswitch [on|up] [VPN_IP] [INTERFACE]"
    )
    parser.add_argument('mode', choices=['on', 'off', 'up'], help="Mode: on=start daemon, off=stop daemon, up=restore interfaces")
    parser.add_argument('vpn_ip', nargs='?', default=None, help="VPN server IP (required for 'on')")
    parser.add_argument('protocol', nargs='?', default=None, help="wireguard or isakmp (required for 'on')")
    parser.add_argument('iface', nargs='?', default=None, help="Interface to capture on (required for 'on')")

    args = parser.parse_args()

    if args.mode == 'up':
        bring_interfaces_up()
    elif args.mode == 'on':
        if not args.vpn_ip or not args.iface or not args.protocol:
            print("Error: VPN_IP and Protocol and INTERFACE are required for 'on' mode.")
            parser.print_help()
            sys.exit(1)
        global vpn_ip, protocol
        vpn_ip = args.vpn_ip.strip()
        protocol = args.protocol.strip()
        start_sniffing_daemon(args.iface)

if __name__ == "__main__":
    main()