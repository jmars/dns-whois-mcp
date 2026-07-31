"""dns-whois-mcp MCP server.

Tools:
  dns_lookup     — DNS record lookup (A, AAAA, MX, NS, TXT, SOA, CNAME, etc.)
  whois_lookup   — WHOIS domain or IP query
  reverse_lookup — Reverse DNS (PTR) lookup for an IP address
  dns_research   — Comprehensive domain investigation (all DNS records + WHOIS + reverse)
"""

import asyncio
import ipaddress
import json
import logging
import re
from datetime import datetime, timezone
from typing import Optional

import dns.asyncresolver
import dns.exception
import dns.reversename
import dns.resolver
import asyncwhois

from mcp.server.fastmcp import FastMCP

from .storage import save_lookup

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

WHOIS_TIMEOUT = 10  # seconds

logger = logging.getLogger("dns-whois-mcp")

# ---------------------------------------------------------------------------
# MCP server
# ---------------------------------------------------------------------------

mcp = FastMCP(
    "dns-whois",
    instructions="DNS and WHOIS domain research — every lookup is archived for later analysis",
)

# ---------------------------------------------------------------------------
# Async resolver (shared instance)
# ---------------------------------------------------------------------------

_resolver = dns.asyncresolver.Resolver()


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _validate_domain(domain: str) -> Optional[str]:
    """Validate a domain name per RFC 1035. Returns error string or None."""
    domain = domain.strip().lower()
    if not domain:
        return "Domain name is empty."
    if len(domain) > 253:
        return "Domain name exceeds maximum length of 253 characters."
    for label in domain.split("."):
        if not label:
            return f"Invalid domain '{domain}': empty label."
        if len(label) > 63:
            return f"Label '{label}' exceeds maximum length of 63 characters."
        if not re.match(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$", label) and label != "*":
            return f"Invalid label '{label}' in domain '{domain}'."
    return None


def _validate_record_type(record_type: str) -> Optional[str]:
    """Validate a DNS record type. Returns error string or None."""
    allowed = {"A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "PTR", "SRV", "CAA", "DS", "DNSKEY"}
    rt = record_type.upper().strip()
    if rt not in allowed:
        return f"Unsupported record type: {record_type}. Supported: {', '.join(sorted(allowed))}"
    return None


# ---------------------------------------------------------------------------
# DNS helper
# ---------------------------------------------------------------------------


async def _resolve(domain: str, record_type: str) -> dict:
    """Resolve a DNS record type. Returns a dict with 'records' or 'error'."""
    try:
        answers = await _resolver.resolve(domain, record_type)
        if record_type in ("MX",):
            records = [f"{r.preference} {r.exchange}" for r in answers]
        elif record_type in ("SOA",):
            soa = answers[0]
            records = [f"{soa.mname} {soa.rname} (serial {soa.serial})"]
        elif record_type in ("TXT",):
            records = ["".join(r.strings) if hasattr(r, "strings") else str(r) for r in answers]
        else:
            records = [str(r) for r in answers]
        return {"records": records}
    except dns.resolver.NXDOMAIN:
        return {"error": "NXDOMAIN", "message": f"Domain '{domain}' does not exist."}
    except dns.resolver.NoAnswer:
        return {"error": "NoAnswer", "message": f"No {record_type} records found for '{domain}'."}
    except dns.resolver.NoNameservers:
        return {"error": "NoNameservers", "message": f"No nameservers could be reached for '{domain}'."}
    except dns.exception.Timeout:
        return {"error": "Timeout", "message": f"DNS query timed out for '{domain}' ({record_type})."}
    except dns.exception.DNSException as e:
        return {"error": "DNSException", "message": str(e)}
    except Exception as e:
        return {"error": "UnexpectedError", "message": str(e)}


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------


@mcp.tool()
async def dns_lookup(
    domain: str,
    record_type: str = "A",
) -> str:
    """DNS record lookup.

    Resolves a DNS record for the given domain. Supports A, AAAA, MX, NS,
    TXT, SOA, CNAME, PTR, SRV, CAA, DS, and DNSKEY record types.

    Args:
        domain:      The domain name to look up (e.g., "example.com")
        record_type: DNS record type (default: "A")
    """
    err = _validate_domain(domain)
    if err:
        return json.dumps({"error": err}, ensure_ascii=False)

    err = _validate_record_type(record_type)
    if err:
        return json.dumps({"error": err}, ensure_ascii=False)

    rt = record_type.upper().strip()
    result = await _resolve(domain, rt)

    payload = {
        "domain": domain,
        "record_type": rt,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        **result,
    }

    save_lookup(domain, "dns_lookup", json.dumps(payload, ensure_ascii=False))

    return json.dumps(payload, ensure_ascii=False, indent=2)


@mcp.tool()
async def whois_lookup(
    query: str,
) -> str:
    """WHOIS domain or IP query.

    Looks up WHOIS registration data for a domain name or IP address.
    Returns structured information: registrar, creation/expiry dates,
    name servers, registrant details, DNSSEC status, and raw WHOIS text.

    Args:
        query: Domain name (e.g., "example.com") or IP address to query
    """
    query = query.strip().lower()

    # Validate — must be a domain or IP
    if not query:
        return json.dumps({"error": "Query is empty."}, ensure_ascii=False)

    # Check if it looks like an IP
    is_ip = False
    try:
        ipaddress.ip_address(query)
        is_ip = True
    except ValueError:
        pass

    # If not IP, validate as domain
    if not is_ip:
        err = _validate_domain(query)
        if err:
            return json.dumps({"error": f"Invalid query: {err}"}, ensure_ascii=False)

    # Set socket-level timeout for whois queries
    old_timeout = None
    try:
        import socket as _socket
        old_timeout = _socket.getdefaulttimeout()
        _socket.setdefaulttimeout(WHOIS_TIMEOUT)
    except Exception:
        pass

    try:
        raw_text, parser_output = await asyncwhois.aio_whois(query)
        if parser_output is None:
            parser_output = {}

        parsed = {
            "domain_name": parser_output.get("domain_name"),
            "registrar": parser_output.get("registrar"),
            "registrar_url": parser_output.get("registrar_url"),
            "creation_date": _fmt_date(parser_output.get("created")),
            "expiration_date": _fmt_date(parser_output.get("expires")),
            "updated_date": _fmt_date(parser_output.get("updated")),
            "name_servers": parser_output.get("name_servers"),
            "registrant_name": parser_output.get("registrant_name"),
            "registrant_organization": parser_output.get("registrant_organization"),
            "dnssec": parser_output.get("dnssec"),
            "status": parser_output.get("status"),
        }

        # Compute age in days if creation date is available
        age_days = None
        creation_raw = parser_output.get("created")
        if creation_raw:
            try:
                if isinstance(creation_raw, datetime):
                    cdate = creation_raw
                elif isinstance(creation_raw, str):
                    cdate = datetime.fromisoformat(creation_raw.replace("Z", "+00:00"))
                else:
                    cdate = None
                if cdate:
                    age_days = (datetime.now(timezone.utc) - cdate.replace(tzinfo=timezone.utc)).days
            except (ValueError, TypeError):
                pass

        if age_days is not None:
            parsed["age_days"] = age_days

        payload = {
            "query": query,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "parsed": parsed,
            "raw_whois": str(raw_text) if raw_text else "",
        }

        save_lookup(query, "whois_lookup", json.dumps(payload, ensure_ascii=False))

        return json.dumps(payload, ensure_ascii=False, indent=2)

    except asyncio.TimeoutError:
        return json.dumps({
            "query": query,
            "error": "Timeout",
            "message": f"WHOIS query timed out after {WHOIS_TIMEOUT}s.",
        }, ensure_ascii=False, indent=2)
    except Exception as e:
        payload = {
            "query": query,
            "error": "WhoisError",
            "message": str(e),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        save_lookup(query, "whois_lookup", json.dumps(payload, ensure_ascii=False))
        return json.dumps(payload, ensure_ascii=False, indent=2)
    finally:
        # Restore socket timeout
        if old_timeout is not None:
            try:
                import socket as _socket
                _socket.setdefaulttimeout(old_timeout)
            except Exception:
                pass


@mcp.tool()
async def reverse_lookup(
    ip: str,
) -> str:
    """Reverse DNS (PTR) lookup for an IP address.

    Resolves hostname(s) associated with the given IP address via PTR records.

    Args:
        ip: IP address to look up (IPv4 or IPv6)
    """
    ip = ip.strip()

    try:
        addr = ipaddress.ip_address(ip)
    except ValueError as e:
        return json.dumps({"error": f"Invalid IP address: {e}"}, ensure_ascii=False)

    ptr_name = dns.reversename.from_address(str(addr))

    result = await _resolve(str(ptr_name), "PTR")

    payload = {
        "ip": str(addr),
        "version": addr.version,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        **result,
    }

    save_lookup(str(addr), "reverse_lookup", json.dumps(payload, ensure_ascii=False))

    return json.dumps(payload, ensure_ascii=False, indent=2)


@mcp.tool()
async def dns_research(
    domain: str,
) -> str:
    """Comprehensive domain investigation.

    Runs ALL DNS record types (A, AAAA, MX, NS, TXT, SOA, CNAME) and WHOIS
    lookup in parallel. For every resolved IP in A and AAAA records, performs
    reverse DNS lookups. Returns a consolidated JSON report.

    Args:
        domain: The domain name to investigate
    """
    err = _validate_domain(domain)
    if err:
        return json.dumps({"error": err}, ensure_ascii=False)

    domain = domain.strip().lower()
    ts = datetime.now(timezone.utc).isoformat()

    # Run DNS and WHOIS lookups in parallel
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]
    tasks = {rt: _resolve(domain, rt) for rt in record_types}
    tasks["whois"] = _whois_inner(domain)

    results = await asyncio.gather(*tasks.values(), return_exceptions=True)

    # Build output
    payload: dict = {
        "domain": domain,
        "timestamp": ts,
    }

    task_names = list(tasks.keys())
    for name, res in zip(task_names, results):
        if isinstance(res, Exception):
            payload[name] = {"error": "Exception", "message": str(res)}
        elif isinstance(res, dict):
            payload[name] = res
        else:
            payload[name] = {"error": "UnexpectedResult", "message": str(res)}

    # Reverse DNS for each resolved IP in A and AAAA records
    reverse_dns_results = []
    for rt in ("A", "AAAA"):
        rt_data = payload.get(rt, {})
        if isinstance(rt_data, dict) and "records" in rt_data:
            for record in rt_data["records"]:
                try:
                    r_addr = ipaddress.ip_address(record)
                except ValueError:
                    continue
                ptr_name = dns.reversename.from_address(str(r_addr))
                rev_res = await _resolve(str(ptr_name), "PTR")
                if "records" in rev_res:
                    for hostname in rev_res["records"]:
                        reverse_dns_results.append({
                            "ip": str(r_addr),
                            "hostname": hostname,
                        })

    if reverse_dns_results:
        payload["reverse_dns"] = reverse_dns_results

    # Calculate domain age from WHOIS if available
    whois_data = payload.get("whois", {})
    if isinstance(whois_data, dict):
        parsed = whois_data.get("parsed", {})
        if isinstance(parsed, dict):
            creation_raw = parsed.get("creation_date") or parsed.get("created")
            if creation_raw:
                try:
                    if isinstance(creation_raw, datetime):
                        cdate = creation_raw
                    elif isinstance(creation_raw, str):
                        cdate = datetime.fromisoformat(creation_raw.replace("Z", "+00:00"))
                    else:
                        cdate = None
                    if cdate:
                        age = (datetime.now(timezone.utc) - cdate.replace(tzinfo=timezone.utc)).days
                        if "parsed" not in payload:
                            payload["parsed"] = {}
                        payload["domain_age_days"] = age
                except (ValueError, TypeError):
                    pass

    save_lookup(domain, "dns_research", json.dumps(payload, ensure_ascii=False))

    return json.dumps(payload, ensure_ascii=False, indent=2)


# ---------------------------------------------------------------------------
# Internal helpers (shared between tools)
# ---------------------------------------------------------------------------


async def _whois_inner(query: str) -> dict:
    """WHOIS lookup used internally by dns_research. Returns a dict, never raises."""
    try:
        raw_text, parser_output = await asyncio.wait_for(
            asyncwhois.aio_whois(query),
            timeout=WHOIS_TIMEOUT,
        )
        if parser_output is None:
            parser_output = {}

        parsed = {
            "domain_name": parser_output.get("domain_name"),
            "registrar": parser_output.get("registrar"),
            "registrar_url": parser_output.get("registrar_url"),
            "creation_date": _fmt_date(parser_output.get("created")),
            "expiration_date": _fmt_date(parser_output.get("expires")),
            "updated_date": _fmt_date(parser_output.get("updated")),
            "name_servers": parser_output.get("name_servers"),
            "registrant_name": parser_output.get("registrant_name"),
            "registrant_organization": parser_output.get("registrant_organization"),
            "dnssec": parser_output.get("dnssec"),
            "status": parser_output.get("status"),
        }

        age_days = None
        creation_raw = parser_output.get("created")
        if creation_raw:
            try:
                if isinstance(creation_raw, datetime):
                    cdate = creation_raw
                elif isinstance(creation_raw, str):
                    cdate = datetime.fromisoformat(creation_raw.replace("Z", "+00:00"))
                else:
                    cdate = None
                if cdate:
                    age_days = (datetime.now(timezone.utc) - cdate.replace(tzinfo=timezone.utc)).days
            except (ValueError, TypeError):
                pass

        if age_days is not None:
            parsed["age_days"] = age_days

        return {
            "query": query,
            "parsed": parsed,
            "raw_whois": str(raw_text) if raw_text else "",
        }
    except asyncio.TimeoutError:
        return {"error": "Timeout", "message": f"WHOIS query timed out after {WHOIS_TIMEOUT}s."}
    except Exception as e:
        return {"error": "WhoisError", "message": str(e)}


def _fmt_date(val) -> Optional[str]:
    """Format a date value as ISO string, or return as-is if already string."""
    if val is None:
        return None
    if isinstance(val, datetime):
        return val.isoformat()
    if isinstance(val, str):
        return val
    if isinstance(val, list):
        return _fmt_date(val[0]) if val else None
    return str(val)


# ---------------------------------------------------------------------------
# Sync helpers for testing (mirror tool logic)
# ---------------------------------------------------------------------------


def _dns_lookup_sync(domain: str, record_type: str = "A") -> str:
    """Sync DNS lookup for testing. Uses dns.resolver directly."""
    err = _validate_domain(domain)
    if err:
        return json.dumps({"error": err}, ensure_ascii=False)

    err = _validate_record_type(record_type)
    if err:
        return json.dumps({"error": err}, ensure_ascii=False)

    rt = record_type.upper().strip()

    try:
        answers = dns.resolver.resolve(domain, rt)
        if rt == "MX":
            records = [f"{r.preference} {r.exchange}" for r in answers]
        elif rt == "SOA":
            soa = answers[0]
            records = [f"{soa.mname} {soa.rname} (serial {soa.serial})"]
        elif rt == "TXT":
            records = ["".join(r.strings) if hasattr(r, "strings") else str(r) for r in answers]
        else:
            records = [str(r) for r in answers]

        payload = {
            "domain": domain,
            "record_type": rt,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "records": records,
        }
    except dns.resolver.NXDOMAIN:
        payload = {
            "domain": domain,
            "record_type": rt,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "error": "NXDOMAIN",
            "message": f"Domain '{domain}' does not exist.",
        }
    except dns.resolver.NoAnswer:
        payload = {
            "domain": domain,
            "record_type": rt,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "error": "NoAnswer",
            "message": f"No {rt} records found for '{domain}'.",
        }
    except dns.exception.Timeout:
        payload = {
            "domain": domain,
            "record_type": rt,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "error": "Timeout",
            "message": f"DNS query timed out for '{domain}' ({rt}).",
        }
    except dns.exception.DNSException as e:
        payload = {
            "domain": domain,
            "record_type": rt,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "error": "DNSException",
            "message": str(e),
        }

    save_lookup(domain, "dns_lookup", json.dumps(payload, ensure_ascii=False))
    return json.dumps(payload, ensure_ascii=False, indent=2)


def _whois_lookup_sync(query: str) -> str:
    """Sync WHOIS lookup for testing."""
    query = query.strip().lower()

    if not query:
        return json.dumps({"error": "Query is empty."}, ensure_ascii=False)

    is_ip = False
    try:
        ipaddress.ip_address(query)
        is_ip = True
    except ValueError:
        pass

    if not is_ip:
        err = _validate_domain(query)
        if err:
            return json.dumps({"error": f"Invalid query: {err}"}, ensure_ascii=False)

    try:
        raw_text, parser_output = asyncwhois.whois(query)
        if parser_output is None:
            parser_output = {}

        parsed = {
            "domain_name": parser_output.get("domain_name"),
            "registrar": parser_output.get("registrar"),
            "registrar_url": parser_output.get("registrar_url"),
            "creation_date": _fmt_date(parser_output.get("created")),
            "expiration_date": _fmt_date(parser_output.get("expires")),
            "updated_date": _fmt_date(parser_output.get("updated")),
            "name_servers": parser_output.get("name_servers"),
            "registrant_name": parser_output.get("registrant_name"),
            "registrant_organization": parser_output.get("registrant_organization"),
            "dnssec": parser_output.get("dnssec"),
            "status": parser_output.get("status"),
        }

        age_days = None
        creation_raw = parser_output.get("created")
        if creation_raw:
            try:
                if isinstance(creation_raw, datetime):
                    cdate = creation_raw
                elif isinstance(creation_raw, str):
                    cdate = datetime.fromisoformat(creation_raw.replace("Z", "+00:00"))
                else:
                    cdate = None
                if cdate:
                    age_days = (datetime.now(timezone.utc) - cdate.replace(tzinfo=timezone.utc)).days
            except (ValueError, TypeError):
                pass

        if age_days is not None:
            parsed["age_days"] = age_days

        payload = {
            "query": query,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "parsed": parsed,
            "raw_whois": str(raw_text) if raw_text else "",
        }
    except Exception as e:
        payload = {
            "query": query,
            "error": "WhoisError",
            "message": str(e),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    save_lookup(query, "whois_lookup", json.dumps(payload, ensure_ascii=False))
    return json.dumps(payload, ensure_ascii=False, indent=2)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Start the MCP server with stdio transport."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
