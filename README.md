<h1 align="center">guardd</h1>
<p align="center">Machine learning driven behavioral anomaly detection for Linux using eBPF + Isolation Forest</p>

---

Guardd collects low-level system events (process execution, network activity), aggregates them into time-windowed feature vectors, and detects anomalous behavior using a machine learning model.  


---

<p align="center">
  <img src="assets/guarddgui-overview.png" width="800"/>
</p

<p align="center">
  <img src="assets/guarddtui.png" width="800"/>
</p>
### How it works

guardd runs as a single systemd service that manages the full lifecycle of data collection, training, and detection.

On startup:

If no model exists, guardd begins collecting baseline behavioral data  
It collects enough windows for a reference baseline and a later model-training period.

Once training succeeds, it switches automatically into detection mode  

During operation:

System activity is continuously aggregated into time windows and converted into feature vectors  
Each window is scored by the trained Isolation Forest model  
Anomalies are emitted as NDJSON  

Detection keeps the baseline snapshot fixed until a new model is loaded, so repeated unseen behavior remains new to the current model.

Training reserves the earliest 20% of selected windows as the reference baseline.
It recalculates novelty for every later window against that fixed reference,
using the same feature extractor as live detection. Only those later windows
are used to fit the model and calculate its threshold. The reference never
includes identities first observed in the later training period.

Collection stores observed identities with `novelty_scored = false`; its novelty
counts are placeholders. Training recalculates them from metadata, so restarting
collection or mixing windows stored under older models does not change the
novelty definition. Existing version-3 feature rows can be reused. Feature order
and event schemas are unchanged; model bundles are now version 2.

On upgrade, auto mode rebuilds a legacy model from the existing database before
detecting. If more windows are needed, it collects them and retries. Explicit
detect mode requires running `guardd train` first. Alert history is retained;
training continues to use its existing 45-day feature retention policy.
This change fixes feature consistency; it does not by
itself establish improved detection accuracy.

Ongoing:

The model is retrained automatically once per week  
Detection resumes immediately after retraining with the updated model  

---

### Installation

#### 1. Clone the repository

```
git clone https://github.com/benny-e/guardd.git
cd guardd
```

#### 2. Run the install script

```
sudo bash install.sh
```

This will:

Install system dependencies  
Copy the project to /opt/guardd  
Create a Python virtual environment  
Install the package  
Build eBPF components  
Install the systemd service  

---

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
---

#### Terminal TUI

guardd includes a terminal UI for browsing recent alerts and searching anomalies  

To launch: (after starting guardd.service)
```bash
guardd tui
```

#### Desktop GUI (optional)

The PySide6 desktop client has two screens: **Overview** (service state, alerts
today, model availability, Guardd CPU/memory usage, process ID and uptime, host
and kernel, aggregation window size, feature schema, recent alerts, and telemetry
freshness) and **Alerts**
(search, severity/time filters, and a scrollable detail panel with scores,
explanations, activity, and context). It refreshes every five seconds without
blocking the interface. Times use your local timezone; “today” means your local
calendar day.

![Guardd desktop Overview](assets/guarddgui-overview.png)
![Guardd desktop Alerts](assets/guarddgui-alerts.png)

Screenshots show sample alerts and a simulated service state.

For a new system installation with the GUI:

```bash
sudo bash install.sh --gui
guardd gui
```

To add the GUI to an existing `/opt/guardd` installation, update its source first,
then install the optional dependency in its virtual environment:

```bash
sudo /opt/guardd/.venv/bin/python -m pip install -e '/opt/guardd[gui]'
guardd gui
```

For development from a checkout:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[gui]'
.venv/bin/guardd gui --db-path data/features.db --model-path data/model.bundle
```

#### Application launcher and icon

`install.sh --gui` also installs a Guardd launcher and icon into the system's
application menu. The launcher runs `/usr/local/bin/guardd gui` as your desktop
user. For an existing installation, you can add the launcher for your account
from the patched checkout without restarting or reinstalling the daemon:

```bash
install -Dm644 desktop/guardd.desktop ~/.local/share/applications/guardd.desktop
install -Dm644 guard/gui/assets/guardd.png ~/.local/share/icons/hicolor/256x256/apps/guardd.png
rm -f ~/.local/share/icons/hicolor/scalable/apps/guardd.svg
```

Reopen your desktop's application list and search for **Guardd**. If an old icon
is cached, run `gtk-update-icon-cache -f -t ~/.local/share/icons/hicolor` when
that command is available. The desktop entry expects the standard installer
command at `/usr/local/bin/guardd`; adjust `Exec` and `TryExec` if yours is
installed elsewhere.

The GUI uses the same `[paths]` config and config discovery as the daemon.
`--db-path` and `--model-path` override config; `--limit` controls the maximum
matching alerts displayed (default 200, also configurable as `[gui] limit`).
Overview counts cover all alerts today, independent of filters and this limit.

Run it as your regular desktop user. It opens the existing SQLite database in
read-only mode and never starts/stops the daemon, trains a model, or collects
telemetry. Closing it leaves detection running. If the database is missing or
unreadable, it shows a notice and retries on refresh. The database and any SQLite
`-wal`/`-shm` files must be readable by that user; use your existing group or ACL
policy if access is restricted. Do not launch the GUI with `sudo` to work around
permissions.

Service status refers specifically to `guardd.service`; it is **unknown** when
systemd cannot be queried, and manual daemon runs are not detected. Model
availability reports file presence and modification time, not model validity or
confirmation that the service is in detection mode. The GUI does not unpickle
model files.

Resource usage covers the complete systemd service, including its eBPF collector.
CPU is calculated between refreshes (one logical core equals 100%, so a busy
multithreaded service can exceed 100%). Memory is the service’s cgroup memory
usage. The first CPU sample shows “Sampling…”; unavailable accounting shows
“Unavailable”. The supplied service unit enables CPU and memory accounting.
For an existing installation, install the updated service unit and run
`sudo systemctl daemon-reload` followed by `sudo systemctl restart guardd.service`
to apply it. Window size reflects the daemon’s current 60-second aggregation
default; feature schema comes from the latest stored window when available.

On a headless host, install/run the daemon without the GUI. The GUI requires a
graphical desktop session. If Qt reports missing platform libraries on Debian or
Ubuntu, `install.sh --gui` installs the EGL/OpenGL, XKB, and XCB runtime packages.

To run the desktop and data-access checks from a checkout:

```bash
.venv/bin/python -m pip install pytest
QT_QPA_PLATFORM=offscreen .venv/bin/python -m pytest -q
```

Qt interaction tests are skipped when PySide6 is not installed; the read-only
database and CLI tests still run.

---

### Running without systemd

You can run `guardd` directly from the command line without installing the systemd service. This can be configured to run with other init systems  

#### Run full daemon 

```bash
sudo guardd daemon
```

#### Run individual components

Collect data:
```bash
sudo guardd collect
```

Train model:
```bash
sudo guardd train
```

Run Detection:
```bash
sudo guardd detect
```
---
### Configuration

guardd supports configuration via a `config.toml` file.

By default, the daemon looks for:

```
/opt/guardd/config.toml
```

#### Example

```toml
[daemon]
mode = "auto"
bootstrap_retry_seconds = 60
retrain_interval_seconds = 604800

[train]
min_training_rows = 10
baseline_fraction = 0.2
contamination = 0.01
n_estimators = 200
threshold_percentile = 10.0

[paths]
db_path = "/opt/guardd/data/features.db"
model_path = "/opt/guardd/data/model.bundle"
guardd_path = "/opt/guardd/ebpf/guardd"
```

#### [daemon]

Controls the lifecycle of guardd.

 mode  
   -- `"auto"` → full pipeline (collect → train → detect)  
   -- `"collect"` → only collect data  
   -- `"detect"` → only run detection (requires model)  

 bootstrap_retry_seconds  
   -- How often guardd attempts initial training when no model exists  
   -- During this phase, guardd collects data and periodically pauses to try training  

 retrain_interval_seconds  
   -- How often the model is retrained after initial bootstrap  
   -- Default: 7 days (default)  


#### [train]

Controls model behavior and requirements.  

 min_training_rows  
   -- Minimum number of model-fit windows, excluding reference baseline windows

   -- If not met, training fails and will retry later  

 baseline_fraction

   -- Earliest fraction of selected windows reserved for the fixed baseline.

   -- Default: `0.2`; must be greater than 0 and less than 1.

   -- With `min_training_rows = 1380`, at least 1724 total windows are needed: 344 reference windows and 1380 model-fit windows (about 29 hours at one-minute windows).

 contamination  
   -- Expected proportion of anomalies in the data  
   -- Passed directly to Isolation Forest  
   -- Typical values: `0.01`–`0.05`  

 n_estimators  
   -- Number of trees in the Isolation Forest  
   -- Higher = more accurate, slower training  

 threshold_percentile  
   -- Determines anomaly cutoff score  
   -- Lower = more aggressive detection  


#### [paths]

Controls where guardd reads/writes data.  

 db_path  
   -- SQLite database storing feature vectors and anomalies

 model_path  
   -- Serialized model bundle used for detection

 guardd_path  
   -- Path to the eBPF collector binary


#### Notes

 Config values override CLI defaults   
 CLI arguments can still override config if explicitly provided  
 Model accuracy relies heavily on good training data. Longer training times will result in a more accurate detector  

---

### Dependencies

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
