---
title: Cyber Triage Environment Server
colorFrom: purple
colorTo: green
sdk: docker
pinned: false
app_port: 8000
base_path: /web
tags:
  - openenv
---

# CyberTriage: Enterprise Network Defense Environment
![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-2496ED?style=for-the-badge&logo=docker&logoColor=white)
![OpenAI](https://img.shields.io/badge/OpenAI-412991?style=for-the-badge&logo=openai&logoColor=white)

## Real-World Utility
Modern enterprise servers are bombarded with thousands of requests per second. Human analysts cannot triage network logs fast enough to block zero-day threats. **CyberTriage** is a highly realistic OpenEnv simulation designed to test Agentic LLMs on their ability to act as an automated Level 1 Security Operations Center (SOC) Analyst. The agent must read raw network logs, classify threats, and issue precise IP quarantines without disrupting legitimate business traffic.

## State and Action Spaces

**Observation Space (Network Log):**
* `log_id`: Unique event identifier.
* `source_ip`: Origin IP of the request.
* `protocol`: Network protocol (e.g., HTTP, HTTPS, SSH).
* `payload_snippet`: Truncated request payload or URL string.
* `failed_login_attempts`: Rolling integer of recent auth failures.

**Action Space (Decision):**
* `classification`: Strictly typed literal ("Safe", "Suspicious", "Critical Attack").
* `quarantine_ip`: The IPv4 address to block (or null to allow traffic).

## The 3-Tier Task Architecture
1. **Easy (Brute Force Blocker):** Tests basic threshold recognition (e.g., massive failed login spikes from a single IP).
2. **Medium (Payload Inspector):** Tests pattern recognition for obfuscated SQL injections hidden in standard HTTP traffic.
3. **Hard (Multi-Vector Anomaly):** Tests advanced reasoning. The agent must flag low-frequency, highly suspicious lateral movement (e.g., SSH protocol with `wget` execution commands) that evades standard threshold alerts.

## Reward Shaping & Grader Logic
We utilize intermediate reward shaping to guide the LLM, punishing False Negatives (allowing an attack) severely. The final episodic Grader normalizes the agent's performance to a float between 0.0 and 1.0.

The reward function $R(s, a)$ is defined as:

$$
R(s, a) = \begin{cases} 
1.0, & \text{if Critical Attack AND exact IP Quarantined} \\ 
0.5, & \text{if Suspicious AND exact IP Quarantined (Safe partial credit)} \\ 
-1.0, & \text{if Safe AND Threat is active (Severe False Negative penalty)} \\ 
0.0, & \text{otherwise} 
\end{cases}
$$

## Deploying to Hugging Face Spaces

You can easily deploy this environment to Hugging Face Spaces using the `openenv push` command:

```bash
# From the environment directory (where openenv.yaml is located)
openenv push
The `openenv push` command will:
1. Validate that the directory is an OpenEnv environment.
2. Prepare a custom build for Hugging Face Docker space (enables the web interface).
3. Upload to Hugging Face.

After deployment, your space will be available at:
`https://huggingface.co/spaces/<repo-id>`

The deployed space includes:
- **Web Interface** at `/web` - Interactive UI for exploring the environment manually.
- **API Documentation** at `/docs` - Full OpenAPI/Swagger interface.

## Local Development & Testing

### Running the Inference Baseline
To run an LLM agent against the environment locally, ensure you have your Hugging Face token set:

```bash
export HF_TOKEN="your_hf_token"
uv run inference.py
### Running the Server Locally
Run the server locally for testing the Fast API wrapper:

```bash
uvicorn server.app:app --reload
### Project Structure
cyber_triage/
├── .dockerignore         # Docker build exclusions
├── .cursorrules          # OpenEnv Strict Architecture Guidelines
├── inference.py          # Baseline agent evaluation script
├── validate-submission.sh # Hackathon compliance checker
├── README.md             # This file
├── openenv.yaml          # OpenEnv manifest
├── pyproject.toml        # Project metadata and dependencies
├── uv.lock               # Locked dependencies
├── client.py             # CyberTriageEnv client
├── models.py             # Action and Observation Pydantic models
└── server/
    ├── __init__.py       # Server module exports
    ├── cyber_triage_environment.py  # Core triage environment and reward logic
    ├── app.py            # FastAPI application
└── Dockerfile            # Container image definition
