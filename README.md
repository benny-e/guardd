## guardd

Lightweight behavioral anomaly detection for Linux using eBPF and Isolation Forest.  

This is not signature-based and does not try to classify malware. It learns what is normal and reports outliers.  

All data is outputted as NDJSON.  

### Features

- eBPF-based telemetry (exec + network events)  
- Streaming ingestion pipeline  
- Windowed feature aggregation  
- Isolation Forest anomaly detection  
- NDJSON output for easy integration  
- Periodic retraining with systemd timer  
- Automatic data retention cleanup  


### How it works

1. eBPF programs collect exec and network events  
2. Python pipeline aggregates events into time windows  
3. Features are written to a SQLite store  
4. Model is trained on historical data  
5. New windows are scored against the model  
6. Low-score events are flagged as anomalies  


### Installation

```bash
git clone https://github.com/benny-e/guardd.git
cd guardd

python3 -m venv .venv
.venv/bin/pip install -e .
```

### Usage

### Detect

```bash
sudo .venv/bin/guard detect --model-path data/model.bundle
```

### Train

```bash
sudo .venv/bin/guard train \
  --db-path data/features.db \
  --model-out data/model.bundle
```

---

### Systemd setup

```bash
sudo cp systemd/guardd.service /etc/systemd/system/
sudo cp systemd/guardd-train.service /etc/systemd/system/
sudo cp systemd/guardd-train.timer /etc/systemd/system/

sudo systemctl daemon-reload
sudo systemctl enable --now guardd.service
sudo systemctl enable --now guardd-train.timer
```

---

### Output

All output is newline-delimited JSON (NDJSON).

Example anomaly:

```json
{
  "type": "anomaly",
  "score": -0.61,
  "threshold_score": -0.57,
  "severity": "low",
  "summary": {
    "exec_count": 372,
    "unique_comm_count": 21
  }
}
```


### Notes

- First runs may not detect much until enough data is collected  
- Model quality improves over time as more normal behavior is observed  
- Retraining is designed to run periodically (weekly)  

