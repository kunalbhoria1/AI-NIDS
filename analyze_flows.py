
import json
import urllib.request
import urllib.error
from pathlib import Path
from datetime import datetime, timezone

INPUT_FILE = Path("flows.jsonl")
OUTPUT_FILE = Path("alerts.jsonl")
OLLAMA_URL = "http://localhost:11434/api/chat"
MODEL = "qwen3:1.7b"

SCHEMA = {
    "type": "object",
    "properties": {
        "prediction": {
            "type": "string",
            "enum": ["normal", "suspicious", "likely_attack", "uncertain"],
        },
        "evidence": {
            "type": "array",
            "items": {"type": "string"},
        },
        "uncertainty": {
            "type": "string",
            "enum": ["low", "moderate", "high"],
        },
        "limitations": {
            "type": "array",
            "items": {"type": "string"},
        },
    },
    "required": [
        "prediction",
        "evidence",
        "uncertainty",
        "limitations",
    ],
}


def validate_flow(flow):
    """Check required fields and directional counter consistency."""
    required = [
        "protocol",
        "endpoint_a",
        "endpoint_b",
        "packets",
        "bytes",
        "duration_seconds",
        "a_to_b_packets",
        "b_to_a_packets",
        "a_to_b_bytes",
        "b_to_a_bytes",
    ]

    missing = [key for key in required if key not in flow]
    if missing:
        raise ValueError(f"Missing flow fields: {missing}")

    if flow["a_to_b_packets"] + flow["b_to_a_packets"] != flow["packets"]:
        raise ValueError("Directional packet counts do not match total.")

    if flow["a_to_b_bytes"] + flow["b_to_a_bytes"] != flow["bytes"]:
        raise ValueError("Directional byte counts do not match total.")


def analyze_flow(flow):
    validate_flow(flow)

    prompt = {
        "task": "Triage this captured network flow using only supplied metadata.",
        "flow": flow,
        "interpretation_rules": [
            "Endpoint A and B are sorted endpoints, not guaranteed client/server roles.",
            "a_to_b means packets from endpoint A to endpoint B.",
            "b_to_a means packets from endpoint B to endpoint A.",
            "Compare directional packet and byte counts cautiously.",
            "Port numbers, short duration, packet counts, and byte imbalance alone do not prove an attack.",
            "A zero SYN count may mean the capture began after connection setup.",
            "Do not infer failed connections, failed logins, malware, or scanning unless supported by supplied evidence.",
            "Do not treat AI-generated explanations as verified facts.",
            "Choose uncertain when the available metadata is insufficient to distinguish normal from malicious activity.",
        ],
    }

    payload = {
        "model": MODEL,
        "stream": False,
        "format": SCHEMA,
        "think": False,
        "options": {
            "temperature": 0,
            "num_predict": 220,
        },
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are a cautious network-flow triage assistant. "
                    "Use only the supplied flow metadata. "
                    "Do not invent observations or claim an attack is confirmed. "
                    "Return only the JSON object required by the schema. "
                    "AI triage is not a ground-truth security verdict."
                ),
            },
            {
                "role": "user",
                "content": json.dumps(prompt),
            },
        ],
    }

    request = urllib.request.Request(
        OLLAMA_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    with urllib.request.urlopen(request, timeout=180) as response:
        response_data = json.loads(response.read().decode("utf-8"))

    content = response_data["message"]["content"]
    result = json.loads(content)

    # Validate model output before accepting it.
    if result.get("prediction") not in {
        "normal", "suspicious", "likely_attack", "uncertain"
    }:
        raise ValueError("Invalid prediction in model response.")

    if result.get("uncertainty") not in {"low", "moderate", "high"}:
        raise ValueError("Invalid uncertainty in model response.")

    if not isinstance(result.get("evidence"), list):
        raise ValueError("Evidence must be a list.")

    if not isinstance(result.get("limitations"), list):
        raise ValueError("Limitations must be a list.")

    return result


def main():
    if not INPUT_FILE.exists():
        raise SystemExit("flows.jsonl not found. Run extract_flows.py first.")

    flows = []
    with INPUT_FILE.open(encoding="utf-8") as source:
        for line_number, line in enumerate(source, start=1):
            if not line.strip():
                continue
            try:
                flows.append(json.loads(line))
            except json.JSONDecodeError as error:
                raise SystemExit(
                    f"Invalid JSON in {INPUT_FILE}, line {line_number}: {error}"
                )

    print(f"Loaded {len(flows)} flow records.")
    print(f"Model: {MODEL}")
    print("Starting local AI triage...")

    counts = {
        "normal": 0,
        "suspicious": 0,
        "likely_attack": 0,
        "uncertain": 0,
        "failed": 0,
    }

    # Write a fresh output file for this run.
    with OUTPUT_FILE.open("w", encoding="utf-8") as output:
        for index, flow in enumerate(flows, start=1):
            base_record = {
                "analyzed_at_utc": datetime.now(timezone.utc).isoformat(),
                "source": str(INPUT_FILE),
                "flow": flow,
                "verified_attack": None,
            }

            try:
                prediction = analyze_flow(flow)
                base_record["status"] = "success"
                base_record["ai_analysis"] = prediction
                counts[prediction["prediction"]] += 1

                label = prediction["prediction"]

            except (
                urllib.error.URLError,
                TimeoutError,
                json.JSONDecodeError,
                KeyError,
                ValueError,
                OSError,
            ) as error:
                base_record["status"] = "failed"
                base_record["error"] = str(error)
                base_record["ai_analysis"] = None
                counts["failed"] += 1
                label = "FAILED"

            output.write(json.dumps(base_record) + "\n")
            output.flush()

            print(
                f"[{index}/{len(flows)}] "
                f"{flow.get('protocol', 'UNKNOWN')} "
                f"{flow.get('packets', '?')} packets -> {label}"
            )

    print("\nAnalysis summary:")
    for label, count in counts.items():
        print(f"  {label}: {count}")

    print(f"\nInput flows: {len(flows)}")
    print(f"Output records: {sum(counts.values())}")
    print(f"Saved results to: {OUTPUT_FILE}")
    print("Reminder: AI predictions are not verified attack labels.")


if __name__ == "__main__":
    main()
