#!/usr/bin/env python3
"""Convert Microsoft Sentinel analytics-rule YAML files to deployable ARM JSON templates."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:
    print("Missing dependency: PyYAML. Install with: pip install PyYAML", file=sys.stderr)
    raise SystemExit(2)


DURATION_RE = re.compile(
    r"^\s*(?P<value>\d+(?:\.\d+)?)\s*(?P<unit>ms|s|m|h|d|w)\s*$",
    re.IGNORECASE,
)

TRIGGER_OPERATORS = {
    "gt": "GreaterThan",
    "greaterthan": "GreaterThan",
    "greater_than": "GreaterThan",
    "lt": "LessThan",
    "lessthan": "LessThan",
    "less_than": "LessThan",
    "eq": "Equal",
    "equal": "Equal",
    "ne": "NotEqual",
    "notequal": "NotEqual",
    "not_equal": "NotEqual",
}

PASSTHROUGH_PROPERTIES = (
    "entityMappings",
    "sentinelEntitiesMappings",
    "suppressionEnabled",
    "suppressionDuration",
    "eventGroupingSettings",
    "incidentConfiguration",
    "customDetails",
    "alertDetailsOverride",
)


def iso_duration(value: Any) -> Any:
    """Convert Sentinel shorthand such as 5m or 2h to ISO-8601."""
    if value is None or not isinstance(value, str):
        return value

    value = value.strip()
    if value.upper().startswith("P"):
        return value.upper()

    match = DURATION_RE.match(value)
    if not match:
        return value

    number = match.group("value")
    unit = match.group("unit").lower()

    if unit == "ms":
        return value  # ARM duration syntax does not use millisecond shorthand here.
    if unit == "s":
        return f"PT{number}S"
    if unit == "m":
        return f"PT{number}M"
    if unit == "h":
        return f"PT{number}H"
    if unit == "d":
        return f"P{number}D"
    if unit == "w":
        return f"P{float(number) * 7:g}D"
    return value


def normalize_operator(value: Any) -> str:
    if value is None:
        return "GreaterThan"
    text = str(value).strip()
    return TRIGGER_OPERATORS.get(text.lower(), text)


def safe_filename(name: str) -> str:
    cleaned = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", name).strip(" .")
    return cleaned or "analytics-rule"


def load_yaml(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8-sig") as stream:
        data = yaml.safe_load(stream)
    if not isinstance(data, dict):
        raise ValueError("YAML root must be an object")
    return data


def build_arm(rule: dict[str, Any], source_file: str) -> dict[str, Any]:
    rule_id = str(rule.get("id", "")).strip()
    display_name = str(rule.get("name", "")).strip()

    missing = [key for key, value in (("id", rule_id), ("name", display_name), ("query", rule.get("query"))) if not value]
    if missing:
        raise ValueError(f"Missing required field(s): {', '.join(missing)}")

    kind = str(rule.get("kind", "Scheduled"))
    if kind.lower() not in {"scheduled", "nrt"}:
        raise ValueError(f"Unsupported analytics-rule kind: {kind}")

    properties: dict[str, Any] = {
        "displayName": display_name,
        "description": rule.get("description", ""),
        "severity": rule.get("severity", "Medium"),
        "enabled": bool(rule.get("enabled", True)),
        "query": rule["query"],
    }

    if kind.lower() == "scheduled":
        properties.update(
            {
                "queryFrequency": iso_duration(rule.get("queryFrequency", "5m")),
                "queryPeriod": iso_duration(rule.get("queryPeriod", "5m")),
                "triggerOperator": normalize_operator(rule.get("triggerOperator", "gt")),
                "triggerThreshold": int(rule.get("triggerThreshold", 0)),
            }
        )

    if rule.get("tactics") is not None:
        properties["tactics"] = rule["tactics"]

    # YAML uses relevantTechniques; ARM uses techniques.
    techniques = rule.get("techniques", rule.get("relevantTechniques"))
    if techniques is not None:
        properties["techniques"] = techniques

    for key in PASSTHROUGH_PROPERTIES:
        if key in rule and rule[key] is not None:
            value = rule[key]
            if key == "suppressionDuration":
                value = iso_duration(value)
            elif key == "incidentConfiguration":
                value = dict(value)
                grouping = value.get("groupingConfiguration")
                if isinstance(grouping, dict) and "lookbackDuration" in grouping:
                    grouping = dict(grouping)
                    grouping["lookbackDuration"] = iso_duration(grouping["lookbackDuration"])
                    value["groupingConfiguration"] = grouping
            properties[key] = value

    return {
        "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
        "contentVersion": "1.0.0.0",
        "metadata": {
            "source": source_file,
            "generator": "convert_sentinel_yaml.py",
        },
        "parameters": {
            "workspace": {
                "type": "string",
                "metadata": {"description": "Microsoft Sentinel Log Analytics workspace name"},
            }
        },
        "variables": {"ruleId": rule_id},
        "resources": [
            {
                "type": "Microsoft.OperationalInsights/workspaces/providers/alertRules",
                "apiVersion": "2023-12-01-preview",
                "name": "[format('{0}/Microsoft.SecurityInsights/{1}', parameters('workspace'), variables('ruleId'))]",
                "kind": "NRT" if kind.lower() == "nrt" else "Scheduled",
                "properties": properties,
            }
        ],
        "outputs": {
            "analyticsRuleId": {
                "type": "string",
                "value": "[variables('ruleId')]",
            }
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", default=".", help="Repository or YAML source directory")
    parser.add_argument("--output", default="AnalyticsRules", help="Destination directory")
    parser.add_argument("--recursive", action="store_true", default=True)
    parser.add_argument("--clean", action="store_true", help="Delete existing generated JSON files first")
    args = parser.parse_args()

    source = Path(args.source).resolve()
    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=True)

    if args.clean:
        for path in output.glob("*.json"):
            path.unlink()

    yaml_files = sorted(
        {
            *source.rglob("*.yaml"),
            *source.rglob("*.yml"),
        }
    )

    # Never interpret GitHub Actions workflows as Sentinel rule definitions.
    yaml_files = [
        path for path in yaml_files
        if ".github" not in path.parts and output not in path.parents
    ]

    converted = 0
    skipped = 0
    errors: list[str] = []

    manifest: list[dict[str, str]] = []

    for path in yaml_files:
        try:
            data = load_yaml(path)
            # Skip unrelated YAML documents.
            if not {"id", "name", "query"}.issubset(data):
                skipped += 1
                continue

            arm = build_arm(data, str(path.relative_to(source)))
            filename = safe_filename(path.stem) + ".json"
            destination = output / filename
            destination.write_text(
                json.dumps(arm, indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
            manifest.append(
                {
                    "source": str(path.relative_to(source)),
                    "output": str(destination.relative_to(output.parent)),
                    "ruleId": str(data["id"]),
                    "displayName": str(data["name"]),
                }
            )
            converted += 1
            print(f"CONVERTED: {path.relative_to(source)} -> {destination.name}")
        except Exception as exc:
            errors.append(f"{path}: {exc}")
            print(f"ERROR: {path}: {exc}", file=sys.stderr)

    (output / "manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    print(f"\nConverted: {converted}; skipped unrelated YAML: {skipped}; errors: {len(errors)}")
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
