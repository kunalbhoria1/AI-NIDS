
import json
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from scapy.all import PcapReader, IP, IPv6, TCP, UDP


PCAP_FILE = Path("capture.pcap")
OUTPUT_FILE = Path("flows.jsonl")


def new_flow():
    return {
        "packets": 0,
        "bytes": 0,
        "first_seen": None,
        "last_seen": None,
        "a_to_b_packets": 0,
        "b_to_a_packets": 0,
        "a_to_b_bytes": 0,
        "b_to_a_bytes": 0,
        "tcp_syn": 0,
        "tcp_fin": 0,
        "tcp_rst": 0,
        "tcp_ack": 0,
    }


def get_flow_key(packet):
    """Return canonical bidirectional key and packet direction."""

    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
    elif IPv6 in packet:
        src = packet[IPv6].src
        dst = packet[IPv6].dst
    else:
        return None

    if TCP in packet:
        protocol = "TCP"
        sport = int(packet[TCP].sport)
        dport = int(packet[TCP].dport)
    elif UDP in packet:
        protocol = "UDP"
        sport = int(packet[UDP].sport)
        dport = int(packet[UDP].dport)
    else:
        return None

    source = (src, sport)
    destination = (dst, dport)

    endpoint_a, endpoint_b = sorted([source, destination])
    key = (protocol, endpoint_a, endpoint_b)

    direction = (
        "a_to_b" if source == endpoint_a else "b_to_a"
    )

    return key, direction


if not PCAP_FILE.exists():
    raise SystemExit(
        f"{PCAP_FILE} not found. "
        "Place capture.pcap in the project folder."
    )


flows = defaultdict(new_flow)
packets_read = 0
packets_processed = 0


with PcapReader(str(PCAP_FILE)) as reader:
    for packet in reader:
        packets_read += 1

        result = get_flow_key(packet)
        if result is None:
            continue

        key, direction = result
        flow = flows[key]

        timestamp = float(packet.time)
        packet_bytes = len(packet)

        flow["packets"] += 1
        flow["bytes"] += packet_bytes

        if direction == "a_to_b":
            flow["a_to_b_packets"] += 1
            flow["a_to_b_bytes"] += packet_bytes
        else:
            flow["b_to_a_packets"] += 1
            flow["b_to_a_bytes"] += packet_bytes

        if flow["first_seen"] is None:
            flow["first_seen"] = timestamp
            flow["last_seen"] = timestamp
        else:
            flow["first_seen"] = min(
                flow["first_seen"], timestamp
            )
            flow["last_seen"] = max(
                flow["last_seen"], timestamp
            )

        if TCP in packet:
            flags = int(packet[TCP].flags)

            # SYN without ACK: usually a connection initiation.
            if (flags & 0x02) and not (flags & 0x10):
                flow["tcp_syn"] += 1

            if flags & 0x01:
                flow["tcp_fin"] += 1

            if flags & 0x04:
                flow["tcp_rst"] += 1

            if flags & 0x10:
                flow["tcp_ack"] += 1

        packets_processed += 1


with OUTPUT_FILE.open("w", encoding="utf-8") as output:
    for (protocol, endpoint_a, endpoint_b), stats in flows.items():
        first = stats["first_seen"]
        last = stats["last_seen"]

        record = {
            "protocol": protocol,
            "endpoint_a": {
                "ip": endpoint_a[0],
                "port": endpoint_a[1],
            },
            "endpoint_b": {
                "ip": endpoint_b[0],
                "port": endpoint_b[1],
            },
            "packets": stats["packets"],
            "bytes": stats["bytes"],
            "a_to_b_packets": stats["a_to_b_packets"],
            "b_to_a_packets": stats["b_to_a_packets"],
            "a_to_b_bytes": stats["a_to_b_bytes"],
            "b_to_a_bytes": stats["b_to_a_bytes"],
            "duration_seconds": round(last - first, 6),
            "first_seen_utc": datetime.fromtimestamp(
                first, tz=timezone.utc
            ).isoformat(),
            "last_seen_utc": datetime.fromtimestamp(
                last, tz=timezone.utc
            ).isoformat(),
            "tcp_syn_count": stats["tcp_syn"],
            "tcp_fin_count": stats["tcp_fin"],
            "tcp_rst_count": stats["tcp_rst"],
            "tcp_ack_count": stats["tcp_ack"],
            "failed_connections": None,
            "limitations": [
                "Endpoint A and B are sorted, not client/server roles.",
                "Directional counters indicate packet direction between endpoints.",
                "Failed connections are not inferred.",
                "This is bidirectional 5-tuple aggregation, not full TCP session tracking.",
                "The capture may contain only part of a connection.",
                "TCP flags are counted per packet, not per unique connection.",
            ],
        }

        output.write(json.dumps(record) + "\n")


print(f"Packets read: {packets_read}")
print(f"TCP/UDP packets processed: {packets_processed}")
print(f"Bidirectional flows: {len(flows)}")
print(f"Saved flow records to: {OUTPUT_FILE}")
