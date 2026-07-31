# dns-whois-mcp

FastMCP server for DNS lookups and WHOIS domain research. Part of the
[Palimpsest](https://github.com/palimpsest-labs) intelligence toolkit.

## Tools

- **dns_lookup** — DNS record lookup (A, AAAA, MX, NS, TXT, SOA, CNAME,
  PTR, SRV, CAA, DS, DNSKEY). Returns JSON with resolved records.
- **whois_lookup** — WHOIS domain or IP query. Returns structured data
  (registrar, creation/expiry dates, name servers, registrant, DNSSEC)
  plus raw WHOIS text. Includes computed `age_days`.
- **reverse_lookup** — Reverse DNS (PTR) lookup for an IPv4 or IPv6 address.
- **dns_research** — Comprehensive domain investigation. Runs all DNS
  record types and WHOIS in parallel, then reverse-lookups every resolved
  IP. Consolidated JSON report.

## Usage

### Via stdio (MCP)

```bash
python -m dns_whois_mcp
```

### Example

```python
dns_research("magnalending.co.uk")
```

### As a library

```python
from dns_whois_mcp.server import _dns_lookup_sync, _whois_lookup_sync

print(_dns_lookup_sync("iana.org", "A"))
print(_whois_lookup_sync("iana.org"))
```

## Storage

Every lookup is archived as a JSONL entry in
`~/.local/share/dns-whois/YYYY-MM-DD-dns-whois.jsonl`.
Duplicates (same domain + same tool within the same hour) are skipped.

Each entry includes a human-readable `content` field for full-text search
via [fst-indexer](https://github.com/palimpsest-labs/fst-indexer) and
[unified-history-mcp](https://github.com/palimpsest-labs/unified-history-mcp).

## Dependencies

- Python ≥ 3.11
- mcp ≥ 1.0
- dnspython ≥ 2.7
- asyncwhois ≥ 1.0

## Install

```bash
pip install -e .
```
