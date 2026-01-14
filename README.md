# 🛡️ MITRE ATT&CK / ATLAS MCP Server

## Table of Contents

- [❓ What is this MCP Server?](#-what-is-this-mcp-server)
- [⭐ Features](#-features)
- [🚀 Use Cases](#-use-cases)
- [⚙️ How It Works](#-how-it-works)
- [📦 Data Sources](#-data-sources)
- [🛠️ API Endpoints / Tools](#-api-endpoints--tools)
- [▶️ Getting Started](#-getting-started)
- [📜 License](#-license)
- [🙏 Acknowledgments](#-acknowledgments)

## ❓ What is this MCP Server?

This project is a Model Context Protocol (MCP) server that exposes the MITRE ATT&CK and MITRE ATLAS knowledge bases through a unified, programmatic API. It enables automated reasoning, enrichment, and integration of adversarial techniques, tactics, mitigations, and detections for both cybersecurity (ATT&CK) and AI/ML security (ATLAS) frameworks.

## ⭐ Features

- Query by technique ID (e.g., T1059.001) or name (substring search)
- Retrieve full context for a technique: mitigations, detections, subtechniques
- List all tactics in ATT&CK or ATLAS
- List all techniques for a given tactic
- Explore relationships between techniques, mitigations, and detections
- Supports both MITRE ATT&CK (enterprise) and MITRE ATLAS frameworks
- Fast, in-memory STIX data loading with caching
- Simple HTTP API (MCP protocol)

## 🚀 Use Cases

- Automated enrichment of threat intelligence platforms
- Security automation and orchestration (SOAR) integrations
- AI/ML security research and mapping
- Building custom security dashboards or visualizations
- Educational tools for adversarial tactics and techniques

You have some examples in the [`examples/`](examples/) directory.

## ⚙️ How It Works

- Loads official STIX bundles for ATT&CK and ATLAS
- Exposes a set of MCP tools (API endpoints) for querying and searching
- Returns structured JSON responses for easy integration
- Can be run locally or deployed as a microservice

## 📦 Data Sources

- **MITRE ATT&CK (Enterprise):**
  - [enterprise-attack.json](https://github.com/mitre-attack/attack-stix-data)
- **MITRE ATLAS:**
  - [stix-atlas-attack-enterprise.json](https://github.com/mitre-atlas/atlas-navigator-data)

STIX files are stored in the [`data/`](data/) directory.

## 🛠️ API Endpoints / Tools

The following MCP tools are available:

- `query_technique(framework, query)` — Search by technique ID or name
- `search_technique_full(framework, query)` — Get full context (mitigations, detections, subtechniques)
- `query_mitigations(framework, technique_id)` — List mitigations for a technique
- `query_detections(framework, technique_id)` — List detections for a technique
- `list_tactics(framework)` — List all tactics
- `query_subtechniques(framework, technique_id)` — List subtechniques for a technique
- `query_tactic_techniques(framework, tactic_id_or_name)` — List techniques for a tactic

See `main.py` for detailed docstrings and usage.

## ▶️ Getting Started

1. **Install dependencies:**
   ```sh
   pip install fastmcp
   # or
   uv sync
   ```
2. **Download STIX data (if needed):**
   - Place the required STIX JSON files in the [`data/`](data/) directory (see above).
3. **Run the server:**
   ```sh
   python main.py
   # or
   uv run main.py
   ```
4. **Access the MCP API:**
   - The server runs at `http://localhost:8000/mcp` by default.
   - Use an MCP client or the [MCP Inspector](https://modelcontextprotocol.io/docs/tools/inspector) to interact with the API.

## 📜 License

This project is licensed under the MIT License. See the `LICENSE` file for more information.

## 🙏 Acknowledgments

This project is based on the work related to MITRE ATT&CK from Jorge Calbo: [attack-mcp-server](https://github.com/jcalbo/attack-mcp-server)

---

<div align="center">
  <small>
    Made with ❤️ by <a target="_blank" href="https://www.linkedin.com/in/jalvarezz13/">jalvarezz13</a>
  </small>
</div>
