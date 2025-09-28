import os
import logging
import argparse
import signal
from scapy.all import IFACES, sniff, get_if_addr
from scapy.layers.isakmp import ISAKMP
import subprocess
import platform
import sys

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

def packet_callback(packet):
    global stop_sniffing
    if not packet.haslayer(ISAKMP):
        return
    isakmp_layer = packet[ISAKMP]
    print(isakmp_layer.default_fields)
    if isakmp_layer.default_fields['next_payload'] != 0:
        logging.info(f"[SKIPPED] Next Payload is {isakmp_layer.next_payload}, not 0. Ignoring packet.")
        return  # Skip if not 0
    logging.info(f"[PACKET DETECTED]: {packet.summary()}")
    print(f"\nISAKMP Packet Detected: {packet.summary()}")
    bring_interfaces_down()
    stop_sniffing = True




def is_process_running(pid):
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False

def start_sniffing_daemon(vpn_ip, iface):

    my_ip = get_if_addr(iface)
    if not my_ip:
        logging.error(f"Could not get IP for interface {iface}")
        print(f"Could not get IP for interface {iface}")
        sys.exit(1)

    bpf_filter = f"src host {vpn_ip} and dst host {my_ip} and udp and (port 500 or port 4500)"
    logging.info(f"Applied filter: {bpf_filter}")
    print(f"Starting daemon mode on {iface} for VPN IP {vpn_ip}")
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

    try:
        while not stop_sniffing:
            sniff(
                filter=bpf_filter,
                prn=packet_callback,
                store=False,
                iface=iface,
                timeout=1,
                stop_filter=lambda x: stop_sniffing
            )
    except KeyboardInterrupt:
        pass
    finally:
        print("\nDaemon stopped gracefully.")



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
            print("Error: VPN_IP and INTERFACE are required for 'on' mode.")
            parser.print_help()
            sys.exit(1)
        start_sniffing_daemon(args.vpn_ip, args.iface)

if __name__ == "__main__":
    main()