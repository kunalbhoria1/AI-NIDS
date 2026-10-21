
import json
from datetime import datetime
from pathlib import Path

INPUT_FILE = Path("aggregated_flows.jsonl")
OUTPUT_FILE = Path("rule_alerts.jsonl")

# Initial triage threshold, not a validated attack threshold.
REPEATED_FLOW_THRESHOLD = 5
SHORT_WINDOW_SECONDS = 10.0


def parse_timestamp(value):
    return datetime.fromisoformat(value)


def evaluate_summary(summary):
    flow_count = summary["flow_count"]
    first = parse_timestamp(summary["first_seen_utc"])
    last = parse_timestamp(summary["last_seen_utc"])

    span_seconds = max(0.0, (last - first).total_seconds())

    observations = []

    if (
        flow_count >= REPEATED_FLOW_THRESHOLD
        and span_seconds <= SHORT_WINDOW_SECONDS
    ):
        observations.append({
            "rule_id": "OBS-REPEATED-FLOWS",
            "severity": "informational",
            "description": (
                f"{flow_count} flows to the same remote IP were observed "
                f"within {span_seconds:.3f} seconds."
            ),
            "reason": (
                "Repeated connections can occur during normal application "
                "activity; this observation alone does not establish an attack."
            ),
        })

    if (
        len(summary.get("remote_ports", [])) >= 5
        and flow_count >= REPEATED_FLOW_THRESHOLD
    ):
        observations.append({
            "rule_id": "OBS-MULTIPLE-REMOTE-PORTS",
            "severity": "informational",
            "description": (
                "Multiple remote ports were observed for this remote IP."
            ),
            "reason": (
                "Port diversity alone does not prove scanning or malicious activity."
            ),
        })

    if not observations:
        observations.append({
            "rule_id": "OBS-NO-THRESHOLD-MET",
            "severity": "informational",
            "description": "No configured observation threshold was met.",
            "reason": (
                "This does not prove the traffic is benign; these rules cover "
                "only a small set of behaviors."
            ),
        })

    return {
        "remote_ip": summary["remote_ip"],
        "flow_count": flow_count,
        "observed_span_seconds": round(span_seconds, 6),
        "observations": observations,
        "verified_attack": None,
        "limitations": [
            "Rules are preliminary and have not been validated against labeled traffic.",
            "Repeated connections may be normal application behavior.",
            "A missing observation does not mean the traffic is safe.",
            "The aggregation is based only on the captured PCAP.",
        ],
    }


def main():
    if not INPUT_FILE.exists():
        raise SystemExit(
            "aggregated_flows.jsonl not found. Run aggregate_flows.py first."
        )

    with INPUT_FILE.open(encoding="utf-8") as source:
        summaries = [
            json.loads(line)
            for line in source
            if line.strip()
        ]

    results = [evaluate_summary(summary) for summary in summaries]

    with OUTPUT_FILE.open("w", encoding="utf-8") as output:
        for result in results:
            output.write(json.dumps(result) + "\n")

    print(f"Remote-IP summaries evaluated: {len(results)}")
    print(f"Saved rule observations to: {OUTPUT_FILE}")

    for result in results:
        print(
            f"{result['remote_ip']} | "
            f"flows={result['flow_count']} | "
            f"span={result['observed_span_seconds']}s | "
            f"rules={','.join(o['rule_id'] for o in result['observations'])}"
        )


if __name__ == "__main__":
    main()
