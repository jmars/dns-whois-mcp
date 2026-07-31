"""Archive storage — JSONL writer with hourly dedup.

Saves every DNS and WHOIS lookup as timestamped JSONL entries in
~/.local/share/dns-whois/YYYY-MM-DD-dns-whois.jsonl.

Dedup: if the same domain + same tool was queried within the same hour,
the duplicate is skipped to avoid bloat. Unlike web content (which we
SHA-256 dedup), DNS/WHOIS responses change over time, so we only collapse
within the same hour, not by content hash.
"""

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


ARCHIVE_DIR = Path.home() / ".local" / "share" / "dns-whois"


def _build_content(domain: str, tool_name: str, result: dict) -> str:
    """Build a human-readable text blob for full-text search indexing."""
    parts = [f"{tool_name} {domain}"]

    if tool_name == "dns_lookup":
        rtype = result.get("record_type", "")
        records = result.get("records", [])
        if records:
            parts.append(f"{rtype}: {', '.join(records[:20])}")
        elif result.get("error"):
            parts.append(f"error: {result['error']}")

    elif tool_name == "whois_lookup":
        if result.get("registrar"):
            parts.append(f"registrar={result['registrar']}")
        if result.get("created"):
            parts.append(f"created={result['created']}")
        if result.get("expires"):
            parts.append(f"expires={result['expires']}")
        if result.get("name_servers"):
            parts.append(f"nameservers={', '.join(result['name_servers'][:10])}")
        if result.get("age_days") is not None:
            parts.append(f"age={result['age_days']}d")
        if result.get("error"):
            parts.append(f"error: {result['error']}")

    elif tool_name == "reverse_lookup":
        hostnames = result.get("hostnames", [])
        if hostnames:
            parts.append(" -> ".join(hostnames[:10]))
        elif result.get("error"):
            parts.append(f"error: {result['error']}")

    elif tool_name == "dns_research":
        for rtype in ("A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"):
            data = result.get(rtype)
            if isinstance(data, dict):
                records = data.get("records", [])
                if records:
                    parts.append(f"{rtype}={', '.join(records[:10])}")
        whois = result.get("whois", {})
        if isinstance(whois, dict):
            if whois.get("registrar"):
                parts.append(f"registrar={whois['registrar']}")
            if whois.get("created"):
                parts.append(f"created={whois['created']}")
        rdns = result.get("reverse_dns", [])
        if rdns:
            for entry in rdns[:5]:
                if isinstance(entry, dict):
                    parts.append(f"PTR({entry.get('ip','')})={entry.get('hostname','')}")
        if result.get("domain_age_days") is not None:
            parts.append(f"age={result['domain_age_days']}d")

    return "; ".join(parts)


def save_lookup(
    domain: str,
    tool_name: str,
    result_json: str,
    base_dir: Optional[Path] = None,
) -> str:
    """Save a lookup result to JSONL archive. Returns the filepath string.

    Args:
        domain:     The domain or IP queried
        tool_name:  "dns_lookup", "whois_lookup", "reverse_lookup", or "dns_research"
        result_json: JSON string of the result payload
        base_dir:   Archive directory (default: ~/.local/share/dns-whois)

    Returns:
        Filepath string of the archive file.
    """
    base = base_dir or ARCHIVE_DIR
    base.mkdir(parents=True, exist_ok=True)
    os.chmod(base, 0o700)

    ts = datetime.now(timezone.utc)
    date_str = ts.strftime("%Y-%m-%d")
    filepath = base / f"{date_str}-dns-whois.jsonl"

    # Parse result for storage
    try:
        result_obj = json.loads(result_json) if isinstance(result_json, str) else result_json
    except json.JSONDecodeError:
        result_obj = {"raw": result_json}

    # Dedup: skip if same domain + same tool within same hour
    if filepath.exists():
        hour_prefix = ts.strftime("%Y-%m-%dT%H:")
        try:
            for line in filepath.read_text(encoding="utf-8", errors="replace").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if entry.get("domain") == domain and entry.get("tool") == tool_name:
                    entry_ts = entry.get("timestamp", "")
                    if entry_ts.startswith(hour_prefix):
                        return str(filepath)  # already logged this hour
        except OSError:
            pass

    # Build a human-readable content blob for full-text search indexing.
    # The fst-indexer jsonl extractor reads the "content" field.
    content = _build_content(domain, tool_name, result_obj)

    entry = {
        "domain": domain,
        "tool": tool_name,
        "timestamp": ts.isoformat(),
        "result": result_obj,
        "content": content,
    }

    with open(filepath, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    os.chmod(filepath, 0o600)

    return str(filepath)
