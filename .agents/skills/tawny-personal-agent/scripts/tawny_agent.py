#!/usr/bin/env python3
"""Deterministic local tools for Tawny TI, UniFi events, and Kelpie cases."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import ssl
import sys
from typing import Any, Iterable
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


DOMAIN_RE = re.compile(
    r"(?<![@\w-])(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}(?![\w-])"
)
TOKEN_RE = re.compile(r"[0-9A-Fa-f:.]{3,}")
MAX_LOOKUP_VALUES = 500


class AgentError(RuntimeError):
    pass


def load_config(path: str) -> dict[str, Any]:
    config_path = Path(path).expanduser()
    try:
        data = json.loads(config_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise AgentError(f"Config not found: {config_path}") from exc
    except json.JSONDecodeError as exc:
        raise AgentError(f"Config is invalid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise AgentError("Config root must be a JSON object.")
    data["_config_path"] = str(config_path.resolve())
    return data


def required(config: dict[str, Any], section: str, key: str) -> str:
    value = config.get(section, {}).get(key) if isinstance(config.get(section), dict) else None
    if not isinstance(value, str) or not value.strip():
        raise AgentError(f"Missing config value: {section}.{key}")
    return value.strip()


def api_json(
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    payload: Any = None,
    verify_tls: bool = True,
) -> Any:
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    request_headers = {"Accept": "application/json", **(headers or {})}
    if body is not None:
        request_headers["Content-Type"] = "application/json"
    request = Request(url, data=body, headers=request_headers, method=method)
    context = None if verify_tls else ssl._create_unverified_context()
    try:
        with urlopen(request, timeout=30, context=context) as response:
            raw = response.read().decode("utf-8")
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:500]
        raise AgentError(f"{method} {url} returned HTTP {exc.code}: {detail}") from exc
    except URLError as exc:
        raise AgentError(f"{method} {url} failed: {exc.reason}") from exc
    try:
        return json.loads(raw) if raw else {}
    except json.JSONDecodeError as exc:
        raise AgentError(f"{method} {url} returned invalid JSON.") from exc


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def join_url(base_url: str, path: str) -> str:
    return f"{base_url.rstrip('/')}/{path.lstrip('/')}"


def normalise_indicator(value: str) -> str:
    return value.strip().rstrip(".").lower()


def extract_indicators(value: Any) -> set[str]:
    indicators: set[str] = set()
    for text in string_values(value):
        for token in TOKEN_RE.findall(text):
            candidate = token.strip("[](),;")
            try:
                indicators.add(str(ipaddress.ip_address(candidate)).lower())
            except ValueError:
                pass
        indicators.update(normalise_indicator(match.group(0)) for match in DOMAIN_RE.finditer(text))
    return indicators


def string_values(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for child in value.values():
            yield from string_values(child)
    elif isinstance(value, list):
        for child in value:
            yield from string_values(child)


def ti_lookup(config: dict[str, Any], values: list[str]) -> list[dict[str, Any]]:
    unique = list(dict.fromkeys(normalise_indicator(value) for value in values if value.strip()))
    matches: list[dict[str, Any]] = []
    for start in range(0, len(unique), MAX_LOOKUP_VALUES):
        response = api_json(
            "POST",
            join_url(required(config, "tawny", "base_url"), "/api/threat-intel/lookup"),
            headers=bearer(required(config, "tawny", "api_token")),
            payload={"values": unique[start : start + MAX_LOOKUP_VALUES]},
        )
        batch = response.get("matches") if isinstance(response, dict) else None
        if not isinstance(batch, list):
            raise AgentError("Tawny TI lookup response has no matches array.")
        matches.extend(match for match in batch if isinstance(match, dict))
    return matches


def records_at_path(payload: Any, path: str) -> list[dict[str, Any]]:
    current = payload
    if path:
        for part in path.split("."):
            if not isinstance(current, dict) or part not in current:
                raise AgentError(f"UniFi response has no records_path '{path}'.")
            current = current[part]
    if not isinstance(current, list):
        raise AgentError("UniFi event records must be a JSON array.")
    return [record for record in current if isinstance(record, dict)]


def fetch_unifi_records(config: dict[str, Any]) -> list[dict[str, Any]]:
    unifi = config.get("unifi")
    if not isinstance(unifi, dict):
        raise AgentError("Missing config section: unifi")
    header_name = str(unifi.get("api_key_header") or "X-API-Key")
    headers = {header_name: required(config, "unifi", "api_key")}
    response = api_json(
        "GET",
        required(config, "unifi", "events_url"),
        headers=headers,
        verify_tls=bool(unifi.get("verify_tls", True)),
    )
    if isinstance(response, list):
        return records_at_path(response, "")
    return records_at_path(response, str(unifi.get("records_path") or "data"))


def fetch_unifi_info(config: dict[str, Any]) -> dict[str, Any]:
    unifi = config.get("unifi")
    if not isinstance(unifi, dict):
        raise AgentError("Missing config section: unifi")
    header_name = str(unifi.get("api_key_header") or "X-API-Key")
    response = api_json(
        "GET",
        join_url(
            required(config, "unifi", "base_url"),
            "/proxy/network/integration/v1/info",
        ),
        headers={header_name: required(config, "unifi", "api_key")},
        verify_tls=bool(unifi.get("verify_tls", True)),
    )
    if not isinstance(response, dict) or not response.get("applicationVersion"):
        raise AgentError("UniFi info response has no applicationVersion.")
    return response


def event_reference(record: dict[str, Any]) -> str:
    for key in ("id", "_id", "event_id", "flow_id"):
        value = record.get(key)
        if isinstance(value, (str, int)) and str(value):
            return str(value)
    canonical = json.dumps(record, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:24]


def state_file(config: dict[str, Any]) -> Path:
    raw = config.get("state_path") or "~/.local/state/tawny-agent/state.json"
    return Path(str(raw)).expanduser()


def load_state(config: dict[str, Any]) -> set[str]:
    path = state_file(config)
    if not path.exists():
        return set()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AgentError(f"State file is unreadable: {path}") from exc
    return set(data.get("delivered", [])) if isinstance(data, dict) else set()


def save_state(config: dict[str, Any], delivered: set[str]) -> None:
    path = state_file(config)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps({"delivered": sorted(delivered)[-10_000:]}, indent=2) + "\n",
        encoding="utf-8",
    )
    os.chmod(temporary, 0o600)
    temporary.replace(path)


def create_kelpie_case(
    config: dict[str, Any],
    record: dict[str, Any],
    reference: str,
    matches: list[dict[str, Any]],
) -> dict[str, Any]:
    values = sorted({str(match.get("value", "")) for match in matches if match.get("value")})
    title_values = ", ".join(values[:3])
    details = "\n".join(
        f"- `{match.get('value')}`: {match.get('feed_name', match.get('feedName', 'TI feed'))} "
        f"({match.get('kind', 'indicator')}, {match.get('severity', 'unknown')})"
        for match in matches
    )
    evidence = json.dumps(record, indent=2, sort_keys=True)
    safe_evidence = evidence.replace("```", "``\u200b`")
    summary = (
        "UniFi network event matched Tawny threat intelligence.\n\n"
        f"## Matches\n{details}\n\n"
        f"## UniFi event\n```json\n{safe_evidence}\n```"
    )
    payload = {
        "title": f"UniFi TI match: {title_values}"[:255],
        "summary": summary[:24_000],
        "severity": highest_severity(matches),
        "classification": "other",
        "tags": ["tawny", "unifi", "threat-intel", f"unifi-event-{reference}"],
        "sourceSystem": "tawny-unifi",
        "sourceReference": reference,
    }
    response = api_json(
        "POST",
        join_url(required(config, "kelpie", "base_url"), "/api/v1/cases"),
        headers=bearer(required(config, "kelpie", "api_token")),
        payload=payload,
    )
    if not isinstance(response, dict) or not response.get("id"):
        raise AgentError("Kelpie create-case response has no id.")
    return response


def highest_severity(matches: list[dict[str, Any]]) -> str:
    order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    severities = [str(match.get("severity", "medium")).lower() for match in matches]
    return max(severities, key=lambda value: order.get(value, 1), default="medium")


def run_unifi_hunt(config: dict[str, Any], dry_run: bool) -> dict[str, Any]:
    records = fetch_unifi_records(config)
    record_indicators = [(record, extract_indicators(record)) for record in records]
    all_values = sorted(set().union(*(values for _, values in record_indicators)))
    matches = ti_lookup(config, all_values) if all_values else []
    matches_by_value: dict[str, list[dict[str, Any]]] = {}
    for match in matches:
        value = normalise_indicator(str(match.get("value", "")))
        matches_by_value.setdefault(value, []).append(match)

    delivered = load_state(config)
    created: list[dict[str, Any]] = []
    proposed: list[dict[str, Any]] = []
    for record, values in record_indicators:
        record_matches = [
            match
            for value in values
            for match in matches_by_value.get(normalise_indicator(value), [])
        ]
        if not record_matches:
            continue
        reference = event_reference(record)
        matched_values = sorted(
            {
                normalise_indicator(str(match.get("value", "")))
                for match in record_matches
                if match.get("value")
            }
        )
        dedupe_key = hashlib.sha256(
            f"{reference}:{','.join(matched_values)}".encode("utf-8")
        ).hexdigest()
        if dedupe_key in delivered:
            continue
        proposed.append({"reference": reference, "matches": record_matches})
        if dry_run:
            continue
        case = create_kelpie_case(config, record, reference, record_matches)
        delivered.add(dedupe_key)
        save_state(config, delivered)
        created.append({"reference": reference, "case": case})

    return {
        "records_checked": len(records),
        "indicators_checked": len(all_values),
        "matching_events": len(proposed),
        "cases_created": len(created),
        "proposed": proposed if dry_run else [],
        "created": created,
    }


def cron_command(config: dict[str, Any], schedule: str) -> str:
    if "\n" in schedule or len(schedule.split()) != 5:
        raise AgentError("Cron schedule must contain exactly five fields.")
    script = Path(__file__).resolve()
    config_path = config["_config_path"]
    command = " ".join(
        shlex.quote(value)
        for value in (sys.executable, str(script), "--config", config_path, "unifi-hunt")
    )
    return f"{schedule} {command}"


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    root.add_argument(
        "--config",
        default=os.environ.get(
            "TAWNY_AGENT_CONFIG",
            "~/.config/tawny-agent/config.json",
        ),
        help="Path to JSON config.",
    )
    commands = root.add_subparsers(dest="command", required=True)
    lookup = commands.add_parser("ti-lookup", help="Look up indicators in Tawny TI.")
    lookup.add_argument("values", nargs="+")
    commands.add_parser("unifi-info", help="Read installed UniFi Network version.")
    hunt = commands.add_parser("unifi-hunt", help="Match UniFi event records against Tawny TI.")
    hunt.add_argument("--dry-run", action="store_true")
    cron = commands.add_parser("cron-command", help="Print, but do not install, a cron entry.")
    cron.add_argument("--schedule", required=True)
    return root


def main() -> int:
    args = parser().parse_args()
    try:
        config = load_config(args.config)
        if args.command == "ti-lookup":
            result: Any = {"matches": ti_lookup(config, args.values)}
        elif args.command == "unifi-info":
            result = fetch_unifi_info(config)
        elif args.command == "unifi-hunt":
            result = run_unifi_hunt(config, args.dry_run)
        else:
            result = {"cron": cron_command(config, args.schedule)}
        print(json.dumps(result, indent=2))
        return 0
    except AgentError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
