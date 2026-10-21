
import json
from pathlib import Path

import pandas as pd
import streamlit as st

BASE_DIR = Path(__file__).resolve().parent
AI_FILE = BASE_DIR / "aggregate_alerts.jsonl"
RULE_FILE = BASE_DIR / "rule_alerts.jsonl"

st.set_page_config(
    page_title="AI-NIDS | Network Security Dashboard",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ AI-NIDS")
st.caption("Local AI-assisted Network Intrusion Detection and Triage")
st.warning(
    "Research prototype: observations and AI predictions are not "
    "confirmed attacks. No traffic is being captured live by this dashboard."
)


def load_jsonl(path):
    if not path.exists():
        return [], f"File not found: {path.name}"

    records = []
    errors = []

    with path.open("r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            if not line.strip():
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                errors.append(line_number)

    if errors:
        return records, (
            f"{path.name}: invalid JSON on line(s) "
            + ", ".join(map(str, errors))
        )

    return records, None


ai_records, ai_error = load_jsonl(AI_FILE)
rule_records, rule_error = load_jsonl(RULE_FILE)

for error in (ai_error, rule_error):
    if error:
        st.error(error)

if not ai_records and not rule_records:
    st.info("No analysis records found. Run the analysis pipeline first.")
    st.stop()

ai_by_ip = {
    record.get("summary", {}).get("remote_ip"): record
    for record in ai_records
    if record.get("summary", {}).get("remote_ip")
}

rules_by_ip = {
    record.get("remote_ip"): record
    for record in rule_records
    if record.get("remote_ip")
}

all_ips = sorted(set(ai_by_ip) | set(rules_by_ip))

if not all_ips:
    st.error("No remote IP addresses found in the available records.")
    st.stop()

# Build a combined view while preserving AI and rule results separately.
rows = []

for ip in all_ips:
    ai_record = ai_by_ip.get(ip, {})
    summary = ai_record.get("summary", {})
    analysis = ai_record.get("ai_analysis", {})
    rule_record = rules_by_ip.get(ip, {})
    observations = rule_record.get("observations", [])

    rows.append({
        "Remote IP": ip,
        "Flows": summary.get(
            "flow_count", rule_record.get("flow_count")
        ),
        "Packets": summary.get("total_packets"),
        "Bytes": summary.get("total_bytes"),
        "Protocols": ", ".join(summary.get("protocols", [])),
        "Remote ports": ", ".join(
            map(str, summary.get("remote_ports", []))
        ),
        "AI prediction": analysis.get("prediction", "unavailable"),
        "AI uncertainty": analysis.get("uncertainty", "unavailable"),
        "AI status": ai_record.get("status", "unavailable"),
        "Rule observations": ", ".join(
            item.get("rule_id", "unknown") for item in observations
        ) or "unavailable",
        "Verified attack": (
            ai_record.get("verified_attack")
            if ai_record else rule_record.get("verified_attack")
        ),
    })

df = pd.DataFrame(rows)

st.subheader("Overview")

col1, col2, col3, col4 = st.columns(4)
col1.metric("Remote IPs", len(all_ips))
col2.metric("AI records successful", sum(
    record.get("status") == "success" for record in ai_records
))
col3.metric("Rule observations", sum(
    len(record.get("observations", [])) for record in rule_records
))
col4.metric("Verified attacks", sum(
    row["Verified attack"] is True for row in rows
))

st.caption(
    "A verified-attack count of zero means no records are explicitly "
    "labeled True; it does not mean the traffic is benign."
)

st.subheader("Remote-IP analysis")

search = st.text_input("Filter by remote IP", placeholder="Enter an IP address")
predictions = sorted(df["AI prediction"].dropna().unique().tolist())
selected_predictions = st.multiselect(
    "Filter by AI prediction",
    options=predictions,
    default=predictions,
)

filtered = df.copy()

if search:
    filtered = filtered[
        filtered["Remote IP"].str.contains(search, case=False, na=False)
    ]

if selected_predictions:
    filtered = filtered[
        filtered["AI prediction"].isin(selected_predictions)
    ]
elif predictions:
    filtered = filtered.iloc[0:0]

st.dataframe(filtered, use_container_width=True, hide_index=True)


csv_data = filtered.to_csv(index=False).encode("utf-8")

st.download_button(
    label="📥 Download filtered analysis as CSV",
    data=csv_data,
    file_name="ai_nids_analysis.csv",
    mime="text/csv",
)



st.subheader("Traffic charts")

chart_df = df.copy()

for column in ("Packets", "Bytes", "Flows"):
    chart_df[column] = pd.to_numeric(
        chart_df[column], errors="coerce"
    ).fillna(0)

chart_df = chart_df.sort_values("Bytes", ascending=False)

left_chart, right_chart = st.columns(2)

with left_chart:
    st.markdown("#### Packets by remote IP")
    packet_chart = chart_df.set_index("Remote IP")[["Packets"]]
    st.bar_chart(packet_chart)

with right_chart:
    st.markdown("#### Bytes by remote IP")
    byte_chart = chart_df.set_index("Remote IP")[["Bytes"]]
    st.bar_chart(byte_chart)

st.markdown("#### Flows by remote IP")
flow_chart = chart_df.set_index("Remote IP")[["Flows"]]
st.bar_chart(flow_chart)


st.subheader("Selected IP details")

available_ips = filtered["Remote IP"].tolist()

if not available_ips:
    st.info("No IPs match the current filters.")
else:
    selected_ip = st.selectbox("Choose a remote IP", available_ips)

    ai_record = ai_by_ip.get(selected_ip, {})
    summary = ai_record.get("summary", {})
    analysis = ai_record.get("ai_analysis", {})
    rule_record = rules_by_ip.get(selected_ip, {})

    left, right = st.columns(2)

    with left:
        st.markdown("#### Traffic evidence")
        st.json({
            "remote_ip": selected_ip,
            "flow_count": summary.get(
                "flow_count", rule_record.get("flow_count")
            ),
            "total_packets": summary.get("total_packets"),
            "total_bytes": summary.get("total_bytes"),
            "protocols": summary.get("protocols", []),
            "remote_ports": summary.get("remote_ports", []),
            "local_ports": summary.get("local_ports", []),
            "tcp_syn_count": summary.get("tcp_syn_count"),
            "tcp_rst_count": summary.get("tcp_rst_count"),
            "tcp_fin_count": summary.get("tcp_fin_count"),
            "first_seen_utc": summary.get("first_seen_utc"),
            "last_seen_utc": summary.get("last_seen_utc"),
        })

    with right:
        st.markdown("#### AI triage")
        st.write("**Prediction:**", analysis.get("prediction", "unavailable"))
        st.write("**Uncertainty:**", analysis.get("uncertainty", "unavailable"))
        st.write("**Processing status:**", ai_record.get("status", "unavailable"))

        st.write("**Evidence reported by model**")
        st.write(analysis.get("evidence", []))

        st.write("**AI limitations**")
        st.write(analysis.get("limitations", []))

    st.markdown("#### Rule observations")
    observations = rule_record.get("observations", [])

    if observations:
        for observation in observations:
            st.markdown(
                f"**{observation.get('rule_id', 'Unknown rule')}** "
                f"— {observation.get('severity', 'unspecified')}"
            )
            st.write(observation.get("description", "No description"))
            st.caption(observation.get("reason", "No reason provided"))
    else:
        st.info("No rule observations are available for this IP.")

    st.markdown("#### Data limitations")
    st.write(summary.get("limitations", []))
    st.write(rule_record.get("limitations", []))

st.divider()
st.caption(
    "AI-NIDS prototype | Offline PCAP-derived analysis | "
    "Heuristic rules are preliminary and not validated against labeled traffic."
)
