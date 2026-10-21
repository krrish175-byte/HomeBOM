# HomeBOM

> **"Alexa, how safe is my home?"**  
> An Alexa+ MCP server and vulnerability intelligence engine for smart-home devices. Matches device firmware against real-world vulnerability feeds (CISA KEV, FIRST EPSS, NVD), delivers short spoken responses tailored for voice assistants, and exports CycloneDX 1.6 Hardware BOMs with embedded VEX.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/downloads/)
[![MCP Spec: 2025-11-25+](https://img.shields.io/badge/MCP%20Spec-2025--11--25+-brightgreen.svg)](https://modelcontextprotocol.io/)
[![CycloneDX 1.6](https://img.shields.io/badge/CycloneDX-1.6%20HBOM%20%2B%20VEX-orange.svg)](https://cyclonedx.org/)

---

## 🏆 Hackathon Challenges

1. **Alexa+ Track**: Production-ready Model Context Protocol (MCP) server running over Streamable HTTP at `/mcp`, powering voice-first interactions with plain-language, short spoken summaries. Includes a full simulated Alexa+ web interface with speech-to-text, LLM routing, and text-to-speech.
2. **AWS Builder Challenge**: Direct integration with **Amazon Bedrock** via the Converse API (`boto3`) for candidate CPE disambiguation and conversational voice phrasing, complete with 100% deterministic local template fallbacks. Ready for deployment on AWS App Runner or AWS Lambda.
3. **Open Source Challenge**: Clean separation of domain logic into `packages/homebom-core/` — a standalone, zero-MCP, zero-AWS MIT-licensed Python library for consumer firmware CVE matching, risk ranking, and CycloneDX 1.6 HBOM/VEX generation.

---

## 🏗️ Architecture

```text
               +--------------------------------------------------+
               |             Simulated Alexa+ Web UI              |
               | (Speech Recognition -> LLM MCP Client -> TTS)   |
               +--------------------------------------------------+
                                        |  Streamable HTTP (/mcp)
                                        v
               +--------------------------------------------------+
               |               HomeBOM MCP Server                 |
               |      (FastMCP, Token Auth, 6 Core Tools)         |
               +--------------------------------------------------+
                        |                                |
                        v                                v
         +-----------------------------+   +-----------------------------+
         |    Amazon Bedrock Converse  |   |        homebom-core         |
         | (Conversational Phrasing,   |   |   (CPE Matching, Range      |
         |  CPE Disambiguation,        |   |    Comparison, Risk Ranker, |
         |  Deterministic Fallbacks)   |   |    CycloneDX 1.6 HBOM+VEX)  |
         +-----------------------------+   +-----------------------------+
                                                         |
                                                         v
                                           +-----------------------------+
                                           |      Cached Local Feeds     |
                                           | (CISA KEV, FIRST EPSS, NVD) |
                                           +-----------------------------+
```

---

## 🚀 Quickstart

### Prerequisites
- Python 3.12+
- [`uv`](https://github.com/astral-sh/uv) (recommended package manager)

### Installation
```bash
# Clone the repository
git clone https://github.com/krrish175-byte/HomeBOM.git
cd HomeBOM

# Sync virtualenv and dependencies
uv sync --extra dev
```

### Run Tests & Verification
```bash
# Run full test suite
uv run pytest -v

# Run linter
uv run ruff check .
```

### Check AWS Bedrock Connectivity
```bash
uv run python scripts/bedrock_hello.py
```

---

## 📦 Project Layout
```text
homebom/
├── packages/
│   └── homebom-core/       # Pure Python core library (Zero MCP, Zero AWS imports)
│       ├── homebom_core/   # cpe, versions, match, rank, hbom
│       ├── tests/          # Core unit tests
│       ├── pyproject.toml
│       └── LICENSE
├── server/                 # MCP server application
│   ├── main.py             # FastMCP server & Streamable HTTP app
│   ├── phrasing.py         # Voice response generator
│   ├── bedrock.py          # Bedrock Converse API client with template fallback
│   ├── auth.py             # API key protection
│   └── data/               # Seed devices & cached vulnerability feeds
├── scripts/
│   ├── refresh_cache.py    # Offline feed caching script
│   └── bedrock_hello.py    # Bedrock connectivity check
├── web/                    # Simulated Alexa+ Web Client
│   ├── index.html          # Web audio & voice interface
│   └── app.js              # Speech recognition, MCP client calls, TTS
├── tests/
│   └── fixtures/           # Offline test fixtures & golden snapshots
├── AGENTS.md               # AI & developer operational guide
├── FRICTION_LOG.md         # Hackathon developer friction log
└── README.md
```

---

## 📄 License
This project is licensed under the [MIT License](LICENSE).
The `homebom-core` library is independently licensed under the [MIT License](packages/homebom-core/LICENSE).