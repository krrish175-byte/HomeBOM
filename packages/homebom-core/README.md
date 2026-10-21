# homebom-core

`homebom-core` is an open-source, standalone Python library for consumer smart-home device inventory management, firmware version matching, real-world vulnerability risk ranking (KEV + EPSS prioritized), and CycloneDX 1.6 Hardware Bill of Materials (HBOM) generation with embedded VEX (Vulnerability Exploitability eXchange).

## Key Principles
- **Zero MCP and Zero AWS Imports**: Pure Python domain logic and schemas.
- **Real-World Severity**: Risk ranking prioritized by active exploitation (CISA KEV) and exploit prediction (FIRST EPSS), not misleading CVSS base scores alone.
- **Defensive Version Handling**: Robust extraction and range comparison for real-world messy firmware strings.
- **Hardware BOM + VEX**: Native export to CycloneDX 1.6 JSON.
