# AI-NIDS — AI-Assisted Network Intrusion Detection

An offline network traffic analysis prototype that combines PCAP processing, flow aggregation, local LLM-assisted triage, rule-based observations, and a Streamlit dashboard.

## Overview

AI-NIDS processes a captured network trace and generates structured information about observed network flows. It uses Scapy for packet processing, Ollama with the Qwen model for AI-assisted analysis, and simple heuristic rules to flag traffic patterns for further investigation.

**Project status:** Functional prototype. Detection accuracy has not yet been validated against a labeled dataset.

## Architecture

```text
PCAP capture
    |
    v
extract_flows.py
    |
    +----> flows.jsonl
    |          |
    |          +----> analyze_flows.py
    |                     |
    |                     v
    |                 alerts.jsonl
    |
    v
aggregate_flows.py
    |
    +----> aggregated_flows.jsonl
               |
               +----> analyze_aggregates.py
               |              |
               |              v
               |       aggregate_alerts.jsonl
               |
               +----> rule_engine.py
                              |
                              v
                       rule_alerts.jsonl

dashboard.py reads the AI and rule outputs and provides
traffic charts, IP-level details, filtering, and CSV export.
```

## Technologies

- Python
- Scapy
- Ollama
- Qwen 3 1.7B
- Streamlit
- Pandas
- JSONL for intermediate analysis records

## Project Components

| File | Purpose |
|---|---|
| `extract_flows.py` | Extracts bidirectional TCP/UDP flow records from `capture.pcap`. |
| `aggregate_flows.py` | Aggregates flow records by remote IP. |
| `analyze_flows.py` | Performs local LLM-assisted analysis of individual flows. |
| `analyze_aggregates.py` | Performs LLM-assisted analysis of aggregated traffic summaries. |
| `rule_engine.py` | Generates preliminary rule-based observations. |
| `dashboard.py` | Displays traffic statistics, AI analysis, rule observations, and CSV export. |
| `detector.py` | Standalone synthetic-flow test for the Ollama model. |
| `requirements.txt` | Python dependency list. |

## Requirements

- Python and `pip`
- Ollama installed and running
- The `qwen3:1.7b` model available in Ollama
- The Python dependencies listed in `requirements.txt`
- A PCAP file named `capture.pcap` in the project directory

## Setup

Clone or download this repository, then enter its directory.

Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install Python dependencies:

```bash
python -m pip install -r requirements.txt
```

Install and start Ollama separately, then obtain the model if it is not already installed:

```bash
ollama pull qwen3:1.7b
```

Ensure Ollama is running before executing the AI analysis scripts.

Place your authorized PCAP capture in the project directory as `capture.pcap`.

## Run the Pipeline

Run the scripts from the project directory, in this order:

```bash
python extract_flows.py
python aggregate_flows.py
python analyze_flows.py
python analyze_aggregates.py
python rule_engine.py
```

The scripts write intermediate and final JSONL files to the project directory. Running them again may overwrite existing outputs; back up important results first.

## Launch the Dashboard

After generating the analysis outputs:

```bash
python -m streamlit run dashboard.py
```

Open the local URL printed by Streamlit.

The dashboard includes:

- Remote-IP traffic summaries
- Packet, byte, and flow charts
- AI predictions and model-reported evidence
- Rule-based observations and their explanations
- Filtering by IP and AI prediction
- CSV export of filtered results

The dashboard reads existing output files. It does not currently perform live packet capture or automatically rerun the analysis pipeline.

## Current Rule Observations

The rule engine includes preliminary observations for:

- Repeated flows to a remote IP within a configured time window
- Multiple remote ports associated with repeated flows
- No configured observation threshold being met

These rules are simple heuristics and have not been validated as reliable attack detectors.

## Validation Performed

During development, the current sample capture was processed through the pipeline:

- 100 packets read from the PCAP
- 99 TCP/UDP packets processed
- 18 bidirectional flow records extracted
- 7 remote-IP summaries generated
- 18 per-flow AI records generated
- 7 aggregate AI records generated
- 7 rule observation records generated

Packet and byte totals matched between the extracted flows and aggregated summaries for this capture. Python syntax checks, JSON parsing checks, rule behavior tests using synthetic summaries, and dashboard functionality were also checked.

These checks establish that the prototype's components run on the tested sample. They do **not** establish detection accuracy.

## Limitations

- The prototype currently analyzes a saved PCAP rather than monitoring traffic continuously.
- AI predictions may be uncertain or incorrect and must not be treated as confirmed attack labels.
- Model-reported uncertainty is not a calibrated probability of correctness.
- The rule thresholds are preliminary and may flag normal application behavior.
- The current sample capture does not provide ground-truth attack labels.
- Precision, recall, false-positive rate, and other detection metrics have not yet been established using labeled data.
- Flow features depend on the completeness and quality of the captured traffic.

## Responsible Use

Use packet captures only when you are authorized to inspect the traffic. Treat the generated observations as investigation aids, not as a substitute for validated security monitoring or analyst review.

## Future Improvements

- Evaluate detection against labeled normal and malicious traffic
- Measure precision, recall, and false-positive rates
- Add automated pipeline orchestration and error handling
- Improve test coverage and input validation
- Explore live capture and real-time alerting after offline validation

## License

Choose and add an appropriate license before distributing this project publicly.
