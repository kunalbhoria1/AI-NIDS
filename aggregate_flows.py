
import json
from collections import defaultdict
from pathlib import Path

INPUT_FILE = Path("flows.jsonl")
OUTPUT_FILE = Path("aggregated_flows.jsonl")
LOCAL_IP = "192.168.1.58"


def new_summary():
    return {
        "remote_ip": None,
        "flow_count": 0,
        "total_packets": 0,
        "total_bytes": 0,
        "remote_ports": set(),
        "local_ports": set(),
        "tcp_syn_count": 0,
        "tcp_rst_count": 0,
        "tcp_fin_count": 0,
        "protocols": set(),
        "first_seen_utc": None,
        "last_seen_utc": None,
    }


def main():
    if not INPUT_FILE.exists():
        raise SystemExit("flows.jsonl not found. Run extract_flows.py first.")

    summaries = defaultdict(new_summary)

    with INPUT_FILE.open(encoding="utf-8") as source:
        for line_number, line in enumerate(source, start=1):
            if not line.strip():
                continue

            try:
                flow = json.loads(line)
            except json.JSONDecodeError as error:
                raise SystemExit(f"Invalid JSON on line {line_number}: {error}")

            endpoint_a = flow["endpoint_a"]
            endpoint_b = flow["endpoint_b"]

            if endpoint_a["ip"] == LOCAL_IP:
                local_endpoint = endpoint_a
                remote_endpoint = endpoint_b
            elif endpoint_b["ip"] == LOCAL_IP:
                local_endpoint = endpoint_b
                remote_endpoint = endpoint_a
            else:
                print(
                    f"Skipping flow {line_number}: "
                    "neither endpoint matches LOCAL_IP"
                )
                continue

            remote_ip = remote_endpoint["ip"]
            summary = summaries[remote_ip]

            summary["remote_ip"] = remote_ip
            summary["flow_count"] += 1
            summary["total_packets"] += flow["packets"]
            summary["total_bytes"] += flow["bytes"]
            summary["remote_ports"].add(remote_endpoint["port"])
            summary["local_ports"].add(local_endpoint["port"])
            summary["protocols"].add(flow["protocol"])
            summary["tcp_syn_count"] += flow.get("tcp_syn_count", 0)
            summary["tcp_rst_count"] += flow.get("tcp_rst_count", 0)
            summary["tcp_fin_count"] += flow.get("tcp_fin_count", 0)

            first_seen = flow.get("first_seen_utc")
            last_seen = flow.get("last_seen_utc")

            if first_seen:
                if (
                    summary["first_seen_utc"] is None
                    or first_seen < summary["first_seen_utc"]
                ):
                    summary["first_seen_utc"] = first_seen

            if last_seen:
                if (
                    summary["last_seen_utc"] is None
                    or last_seen > summary["last_seen_utc"]
                ):
                    summary["last_seen_utc"] = last_seen

    with OUTPUT_FILE.open("w", encoding="utf-8") as output:
        for remote_ip, summary in sorted(
            summaries.items(),
            key=lambda item: item[1]["flow_count"],
            reverse=True,
        ):
            record = {
                **summary,
                "remote_ports": sorted(summary["remote_ports"]),
                "local_ports": sorted(summary["local_ports"]),
                "protocols": sorted(summary["protocols"]),
                "limitations": [
                    "This is aggregation of captured flows, not a confirmed attack verdict.",
                    "Flow counts alone do not establish malicious behavior.",
                    "TCP SYN, FIN, and RST counts are packet counts, not completed session counts.",
                    "LOCAL_IP must match the host whose traffic was captured.",
                ],
            }

            output.write(json.dumps(record) + "\n")

    print(f"Remote IPs aggregated: {len(summaries)}")
    print(f"Saved summary to: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
