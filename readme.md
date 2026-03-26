# HoneyCloud RedOps
## A Closed-Loop Adversarial Framework for Honeypot Stress-Testing

> **"We don't just test honeypots. We break them — then make them smarter."**

---

## The Problem

Honeypots fail in silence. A well-resourced attacker probes a system, recognizes the telltale fingerprints of a Cowrie or Dionaea instance, and quietly walks away — never triggering an alert, never appearing in a report. The honeypot *thinks* it worked. It didn't.

**HoneyCloud Part 1** built the blue team — deploy, detect, classify.  
**HoneyCloud RedOps** closes the loop: an automated red team that attacks the honeypot, finds its blind spots, and feeds that intelligence back to harden it.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                      REDOPS CONTROL PLANE                        │
│                                                                  │
│  ┌─────────────┐    ┌──────────────┐    ┌─────────────────────┐ │
│  │  Campaign   │───▶│  Attack      │───▶│  Evasion Scorer     │ │
│  │  Planner    │    │  Orchestrator│    │  (ML Feedback Loop) │ │
│  └─────────────┘    └──────────────┘    └─────────────────────┘ │
│         │                  │                      │              │
│         ▼                  ▼                      ▼              │
│  ┌─────────────┐    ┌──────────────┐    ┌─────────────────────┐ │
│  │  APT Stage  │    │  Attack      │    │  Adversarial Report │ │
│  │  Sequencer  │    │  Modules     │    │  + Patch Recommender│ │
│  └─────────────┘    └──────────────┘    └─────────────────────┘ │
└──────────────────────────────────┬───────────────────────────────┘
                                   │ attacks
                                   ▼
┌──────────────────────────────────────────────────────────────────┐
│                      HONEYCLOUD (BLUE TEAM)                      │
│                                                                  │
│   SSH Honeypot   HTTP Decoy   DB Trap   SMB Lure                │
│         │              │          │          │                   │
│         └──────────────┴──────────┴──────────┘                  │
│                           │                                      │
│                    ┌──────▼──────┐                              │
│                    │  ML Pipeline │ ◀── RedOps measures          │
│                    │  (Detect →  │     detection latency,        │
│                    │   Classify → │     evasion success rate,    │
│                    │   Predict)  │     fingerprint exposure      │
│                    └─────────────┘                              │
└──────────────────────────────────────────────────────────────────┘
```

---

## How It Works — Three Phases

### Phase 1 · Fingerprint & Identify
Before attacking, RedOps determines whether the target is a honeypot.

**Fingerprinting Techniques:**
- **Banner analysis** — SSH version strings, HTTP headers, and service banners compared against known Cowrie/Dionaea signatures
- **Timing oracles** — real services respond to malformed packets differently than emulated ones; we measure response delta distributions
- **Filesystem probing** — real Linux systems have `/proc`, `/dev`, and `/sys` inconsistencies that honeypots can't perfectly replicate
- **Protocol depth testing** — escalate protocol complexity until emulation breaks (e.g., SSH subsystems, SMB dialect negotiation)

Each signal is scored by a **Random Forest classifier** trained on packet captures from both real systems and known honeypot deployments.

```
Fingerprint Score  →  [0.0 — 1.0]
                       ↑ honeypot confidence
```

---

### Phase 2 · APT Simulation — Multi-Stage Kill Chain

RedOps doesn't just fire exploits — it simulates a deliberate, patient attacker.

```
Reconnaissance → Initial Access → Credential Brute → Lateral Move → Execution → Exfil
      │                │                 │                │              │          │
   Port scan      SSH connect       Dictionary       Pivot attempt   cmd run    Data pull
   + banner       + KEX probe       attack (slow)    (internal IPs)  sequence   attempt
```

**Key design decisions that make this realistic:**

| Technique | Why it Matters |
|---|---|
| **Slow-drip brute force** (1 attempt / 45–90s jitter) | Evades rate-limit detection thresholds |
| **Human-timing emulation** | Keypress inter-arrival times drawn from real session recordings |
| **Credential stuffing from real breach lists** | Tests if honeypot correctly logs common passwords |
| **Lateral movement probing** | Validates whether honeypot isolates or exposes internal network |
| **Benign command injection** | `id`, `uname`, `whoami` — same commands real attackers run first |

Campaigns are defined as YAML playbooks. Each stage has a configurable dwell time, abort conditions, and escalation logic — mirroring how real APT groups operate.

---

### Phase 3 · Adversarial Feedback Loop

This is the core of the system. After each campaign, RedOps scores its own performance and feeds results back.

```
Campaign Result
      │
      ├── Evasion Rate        ← % of attacks that were NOT detected
      ├── Detection Latency   ← seconds until first alert fired
      ├── Fingerprint Score   ← confidence that target was identified as honeypot
      └── Kill Chain Depth    ← how far the attacker progressed before detection
```

These four metrics feed a **Reinforcement Learning agent** (PPO — Proximal Policy Optimization) that iterates attack parameters: timing, protocol choice, credential ordering, command sequence.

**The honeypot gets better too.** Detection gaps found by RedOps are exported as structured patches — new detection rules, updated Isolation Forest thresholds, MITRE technique additions — directly into HoneyCloud's pipeline.

---

## ML Stack

| Model | Role | Why This Choice |
|---|---|---|
| **Random Forest** | Honeypot fingerprint classifier | Interpretable; features are tabular timing/packet metrics |
| **PPO (RL agent)** | Attack strategy optimizer | Policy gradient handles the sequential decision problem of campaign planning |
| **Isolation Forest** | Anomaly detection baseline | Reused from HoneyCloud Part 1; RedOps measures its blind spots |
| **LSTM** | Human-timing emulation | Generates realistic inter-arrival time sequences from real session data |
| **XGBoost** | Evasion success predictor | Predicts per-attack evasion probability before execution |

---

## System Design

### Rate Limiting & Safety Rails
RedOps operates against **isolated lab environments only** — network-namespaced containers with no egress to the real internet. A hard-coded IP allowlist enforces this at the kernel level via `iptables` rules set before any campaign starts.

Internal rate limiting prevents campaign loops from generating so much noise that the honeypot's detection becomes trivially easy — we want realistic load, not a flood.

### Campaign Isolation
Each red team campaign runs in its own Docker network namespace. Campaigns are stateful — Redis tracks stage progression, dwell time, and abort signals. If a campaign is interrupted mid-run, it can resume from the last completed stage.

### Observability
Every attack action is logged with a nanosecond timestamp. Post-campaign reports are generated automatically as structured JSON + a human-readable PDF, covering: detection coverage %, evasion vectors that succeeded, and recommended countermeasures ranked by risk.

### API Surface
RedOps exposes a REST API consumed by the HoneyCloud dashboard — judges can launch a campaign from the UI, watch the live feed, and see the post-campaign hardening report in one flow.

---

## What Makes This Different

Most red team tools fire attacks and measure whether an alert fires. **RedOps measures something harder:** whether the honeypot *knew it was being tested*.

A honeypot that detects an attack is useful. A honeypot that detects an attack without revealing that it's a honeypot — that's deception done right. We score both.

```
Deception Score = (1 - Fingerprint Confidence) × Detection Coverage
                   ↑ attacker didn't know      ↑ honeypot still caught it
```

A score of 1.0 means the honeypot was invisible to the attacker and still detected everything. That's the target.

---

## Evaluation Metrics

| Metric | Description | Target |
|---|---|---|
| **Evasion Rate** | % of attack stages not detected | < 10% (blue team goal) |
| **Fingerprint Confidence** | Attacker certainty that target is a honeypot | < 0.3 |
| **Detection Latency (p95)** | Time from first malicious action to first alert | < 30s |
| **Kill Chain Depth** | Stages completed before detection | ≤ 2 (Recon + Initial Access) |
| **Deception Score** | Composite metric above | > 0.85 |

---

## Datasets

- **MITRE ATT&CK Enterprise Matrix** — campaign playbook templates
- **SecLists / RockYou** — credential brute force corpus
- **Hornet-40 + CIC-Honeynet** (from Part 1) — baseline traffic for RL agent training
- **Real SSH session recordings** — LSTM timing emulation training data

---

## Connection to HoneyCloud (Part 1)

RedOps is not a standalone tool — it's a **stress tester for the system we already built**.

| HoneyCloud (Part 1) | RedOps (Part 2) |
|---|---|
| Deploys honeypots | Attacks them |
| Detects anomalies | Finds what anomaly detection misses |
| Tags with MITRE IDs | Validates MITRE coverage is complete |
| Scores IPs with Isolation Forest | Finds Isolation Forest's false-negative rate |
| Predicts next move with Bi-LSTM | Generates move sequences the Bi-LSTM hasn't seen |

Every gap RedOps finds becomes a training signal. The system is designed to get harder to fool over time.

---

## Implementation Roadmap

```
Week 1   Fingerprinting module + Random Forest classifier
Week 2   APT campaign playbook engine + stage sequencer
Week 3   RL agent (PPO) for attack optimization
Week 4   Feedback loop → HoneyCloud patch export + dashboard integration
```

---

*Built on top of HoneyCloud — Cowrie · Isolation Forest · XGBoost · Bi-LSTM · MITRE ATT&CK*