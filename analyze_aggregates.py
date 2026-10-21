
import json
import urllib.request
import urllib.error
from pathlib import Path
from datetime import datetime, timezone

INPUT_FILE = Path("aggregated_flows.jsonl")
OUTPUT_FILE = Path("aggregate_alerts.jsonl")
OLLAMA_URL = "http://localhost:11434/api/chat"
MODEL = "qwen3:1.7b"

SCHEMA = {
    "type": "object",
    "properties": {
        "prediction": {
            "type": "string",
            "enum": ["normal", "suspicious", "likely_attack", "uncertain"]
        },
        "evidence": {
            "type": "array",
            "items": {"type": "string"}
        },
        "uncertainty": {
            "type": "string",
            "enum": ["low", "moderate", "high"]
        },
        "limitations": {
            "type": "array",
            "items": {"type": "string"}
        }
    },
    "required": ["prediction", "evidence", "uncertainty", "limitations"]
}


def analyze_summary(summary):
    prompt = {
        "task": "Triage an aggregated network traffic summary.",
        "summary": summary,
        "rules": [
            "This summary groups captured flows by remote IP, not by confirmed user or organization.",
            "A high flow count or repeated SYN packets alone does not prove malicious behavior.",
            "Multiple connections to port 443 can be normal HTTPS traffic.",
            "Do not claim a port scan when the observed remote ports do not support that claim.",
            "Do not infer failed connections, successful handshakes, malware, or unauthorized access.",
            "Use only the supplied metadata.",
            "Choose uncertain if evidence is insufficient.",
            "This is AI triage, not a verified intrusion verdict."
        ]
    }

    payload = {
        "model": MODEL,
        "stream": False,
        "format": SCHEMA,
        "think": False,
        "options": {"temperature": 0, "num_predict": 400},
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are a cautious network security triage assistant. "
                    "Return only the required JSON object. "
                    "Distinguish observed metadata from interpretation. "
                    "Never claim an attack is confirmed from this summary alone."
                )
            },
            {
                "role": "user",
                "content": json.dumps(prompt)
            }
        ]
    }

    request = urllib.request.Request(
        OLLAMA_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST"
    )

    with urllib.request.urlopen(request, timeout=180) as response:
        body = json.loads(response.read().decode("utf-8"))

    message = body.get("message", {})
    content = message.get("content", "")

    print(
        f"Debug: remote_ip={summary.get('remote_ip')}, "
        f"done={body.get('done')}, "
        f"done_reason={body.get('done_reason')}, "
        f"response_chars={len(content)}"
    )

    try:
        result = json.loads(content)
    except json.JSONDecodeError as error:
        raise ValueError(
            f"Invalid model JSON for {summary.get('remote_ip')}; "
            f"done={body.get('done')}, "
            f"done_reason={body.get('done_reason')}, "
            f"response_chars={len(content)}, "
            f"parse_error={error}"
        ) from error

    if result.get("prediction") not in {
        "normal", "suspicious", "likely_attack", "uncertain"
    }:
        raise ValueError("Invalid prediction in model response.")

    if result.get("uncertainty") not in {"low", "moderate", "high"}:
        raise ValueError("Invalid uncertainty value.")

    if not isinstance(result.get("evidence"), list):
        raise ValueError("Evidence must be a list.")

    if not isinstance(result.get("limitations"), list):
        raise ValueError("Limitations must be a list.")

    return result


def main():
    if not INPUT_FILE.exists():
        raise SystemExit("aggregated_flows.jsonl not found. Run aggregate_flows.py first.")

    with INPUT_FILE.open(encoding="utf-8") as source:
        summaries = [
            json.loads(line)
            for line in source
            if line.strip()
        ]

    print(f"Loaded {len(summaries)} remote-IP summaries.")

    counts = {
        "normal": 0,
        "suspicious": 0,
        "likely_attack": 0,
        "uncertain": 0,
        "failed": 0
    }

    # Keep previous results by making a timestamped backup before replacement.
    if OUTPUT_FILE.exists():
        backup = OUTPUT_FILE.with_name(
            f"aggregate_alerts_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.jsonl"
        )
        OUTPUT_FILE.replace(backup)
        print(f"Previous output backed up to {backup}")

    with OUTPUT_FILE.open("w", encoding="utf-8") as output:
        for index, summary in enumerate(summaries, start=1):
            record = {
                "analyzed_at_utc": datetime.now(timezone.utc).isoformat(),
                "source": str(INPUT_FILE),
                "summary": summary,
                "verified_attack": None
            }

            try:
                result = analyze_summary(summary)
                record["status"] = "success"
                record["ai_analysis"] = result
                counts[result["prediction"]] += 1
                label = result["prediction"]

            except (
                urllib.error.URLError,
                TimeoutError,
                json.JSONDecodeError,
                KeyError,
                ValueError,
                OSError
            ) as error:
                record["status"] = "failed"
                record["error"] = str(error)
                record["ai_analysis"] = None
                counts["failed"] += 1
                label = "FAILED"

            output.write(json.dumps(record) + "\n")
            output.flush()

            print(
                f"[{index}/{len(summaries)}] "
                f"{summary['remote_ip']} -> {label}"
            )

    print("\nSummary:")
    for label, count in counts.items():
        print(f"  {label}: {count}")

    print(f"Output records: {sum(counts.values())}")
    print(f"Saved to {OUTPUT_FILE}")
    print("AI predictions are not verified attack labels.")


if __name__ == "__main__":
    main()
