## guardd

AI-driven behavioral anomaly detection for Linux using eBPF and Isolation Forest.

guardd collects low-level system events (process execution, network activity), aggregates them into time-windowed feature vectors, and detects anomalous behavior using a machine learning model.

Output is emitted as structured NDJSON for easy integration with SIEM pipelines.


### Features

eBPF-based kernel telemetry  
Time-windowed behavioral feature aggregation  
Isolation Forest anomaly detection  
Automatic model training and retraining  
NDJSON output  
Designed to run as a systemd service  


### Installation

#### 1. Clone the repository

```
git clone https://github.com/benny-e/guardd.git
cd guardd
``````

#### 2. Run the install script

```
sudo bash install-systemd.sh
```

This will:

Install system dependencies  
Copy the project to /opt/guardd  
Create a Python virtual environment  
Install the package  
Build eBPF components  
Install the systemd service  


### How it works

guardd runs as a single systemd service that manages the full lifecycle of data collection, training, and detection.

On startup:

If no model exists, guardd begins collecting baseline behavioral data  
It attempts to train a model every 10 minutes until enough data is available  
Once training succeeds, it switches automatically into detection mode  

During operation:

System activity is continuously aggregated into time windows and converted into feature vectors  
Each window is scored by the trained Isolation Forest model  
Anomalies are emitted as NDJSON  

Ongoing:

The model is retrained automatically once per week  
Detection resumes immediately after retraining with the updated model  


### Usage

#### Start service

```
sudo systemctl start guardd.service
```

#### Check status

```
systemctl status guardd.service
```

#### View logs

```
journalctl -u guardd.service -f
```

### Running without systemd

You can run `guardd` directly from the command line without installing the systemd service.

#### Run full daemon 

```bash
sudo /opt/guardd/.venv/bin/python -m guard daemon \
  --mode auto \
  --guardd-path /opt/guardd/ebpf/guardd \
  --db-path /opt/guardd/data/features.db \
  --model-path /opt/guardd/data/model.bundle
```

### Run individual components

Collect data:
```bash
sudo /opt/guardd/.venv/bin/python -m guard collect \
  --guardd-path /opt/guardd/ebpf/guardd \
  --db-path /opt/guardd/data/features.db
```

Train model:
```bash
sudo /opt/guardd/.venv/bin/python -m guard train \
  --db-path /opt/guardd/data/features.db \
  --model-out /opt/guardd/data/model.bundle
```

Run Detection:
```bash
sudo /opt/guardd/.venv/bin/python -m guard detect \
  --guardd-path /opt/guardd/ebpf/guardd \
  --db-path /opt/guardd/data/features.db \
  --model-path /opt/guardd/data/model.bundle
```

### Dependencies

#### System

python3  
python3-venv  
python3-pip  
clang  
llvm  
libbpf-dev  
libelf-dev  
bpftool  
build-essential  
pkg-config  
sqlite3  

