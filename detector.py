
import json
import urllib.request
import urllib.error

OLLAMA_URL = "http://localhost:11434/api/chat"
MODEL = "qwen3:1.7b"

# Synthetic test flow; not captured from a real network.
test_flow = {
    "protocol": "TCP",
    "duration_seconds": 0.2,
    "packets": 180,
    "bytes": 9500,
    "destination_port": 22,
    "failed_connections": 15
}

schema = {
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
    "required": [
        "prediction", "evidence", "uncertainty", "limitations"
    ]
}

payload = {
    "model": MODEL,
    "stream": False,
    "format": schema,
    "think": False,
    "options": {"temperature": 0},
    "messages": [
        {
            "role": "system",
            "content": (
                "You are a network intrusion triage assistant. "
                "Analyze only the supplied flow features. "
                "Do not invent missing observations. "
                "A destination port or short duration alone does not "
                "prove an attack. Missing context must be listed as a "
                "limitation. Return only the requested structured result."
            )
        },
        {
            "role": "user",
            "content": (
                "Analyze this network flow record:\n"
                + json.dumps(test_flow)
                + "\nClassify the flow and explain the available evidence."
            )
        }
    ]
}

request = urllib.request.Request(
    OLLAMA_URL,
    data=json.dumps(payload).encode("utf-8"),
    headers={"Content-Type": "application/json"},
    method="POST"
)

try:
    with urllib.request.urlopen(request, timeout=180) as response:
        result = json.loads(response.read().decode("utf-8"))

    prediction = json.loads(result["message"]["content"])

    print("\n=== AI-NIDS TEST RESULT ===")
    print(json.dumps(prediction, indent=2))
    print("\nNote: This is a model prediction, not a confirmed attack.")

except urllib.error.URLError as exc:
    print("Could not connect to Ollama.")
    print("Check that Ollama is running.", exc)

except (json.JSONDecodeError, KeyError) as exc:
    print("Could not parse the model response:", exc)
