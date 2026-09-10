from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

SEVERITY_WEIGHT = {"critical": 10, "high": 8, "moderate": 5, "medium": 5, "low": 2, "unknown": 1}


def load_json(path: Path) -> Any:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"cannot read JSON file {path}: {exc}") from exc
    return value


def dependency_paths(package_json: dict[str, Any], lock_json: dict[str, Any]) -> dict[str, str]:
    direct: set[str] = set()
    for field in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        values = package_json.get(field, {})
        if isinstance(values, dict):
            direct.update(values)
    paths: dict[str, str] = {}
    packages = lock_json.get("packages", {})
    if isinstance(packages, dict):
        for key, item in packages.items():
            if not key or not isinstance(item, dict):
                continue
            name = key.rsplit("node_modules/", 1)[-1]
            if name and name not in paths:
                paths[name] = "direct" if name in direct and key.count("node_modules/") == 1 else "transitive"
    return paths


def prioritize(package_json: dict[str, Any], lock_json: dict[str, Any], advisories: list[dict[str, Any]]) -> list[dict[str, Any]]:
    paths = dependency_paths(package_json, lock_json)
    findings: list[dict[str, Any]] = []
    for advisory in advisories:
        if not isinstance(advisory, dict) or not advisory.get("package"):
            continue
        severity = str(advisory.get("severity", "unknown")).lower()
        scope = paths.get(str(advisory["package"]), "unknown")
        score = SEVERITY_WEIGHT.get(severity, 1) + (2 if scope == "direct" else 0)
        findings.append({
            "package": str(advisory["package"]),
            "severity": severity,
            "scope": scope,
            "score": score,
            "summary": str(advisory.get("summary", "No advisory summary supplied.")),
            "fixed_version": advisory.get("fixed_version"),
            "source": advisory.get("source"),
        })
    return sorted(findings, key=lambda item: (-item["score"], item["package"]))


def render_markdown(project: Path, findings: list[dict[str, Any]], advisory_source: str) -> str:
    lines = [f"# Dependency risk report: `{project.name}`", "", f"Advisory input: `{advisory_source}`", "", "## Scope and limitations", "", "This is a point-in-time prioritization report. It does not prove exploitability, reachability, or that a clean result is safe. Verify each finding against the linked advisory and run your package manager's audit tools.", "", "## Findings", "", "| Priority | Package | Severity | Scope | Fixed version | Explanation |", "|---:|---|---|---|---|---|"]
    if not findings:
        lines.append("| — | — | — | — | — | No advisory records were supplied. This is not a clean security bill of health. |")
    for index, item in enumerate(findings, 1):
        fixed = str(item["fixed_version"] or "review advisory")
        summary = item["summary"].replace("|", "\\|").replace("\n", " ")
        lines.append(f"| {index} | `{item['package']}` | {item['severity']} | {item['scope']} | `{fixed}` | {summary} |")
    lines += ["", "## Recommended next steps", "", "1. Confirm the affected package and version in the lockfile.", "2. Apply the fixed version in a reviewed change when one is available.", "3. Run tests and your package manager's frozen, audit-enabled CI install.", "4. Enable Dependabot alerts and security updates, then review future dependency changes.", ""]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Explain and prioritize Node.js dependency advisories without executing repository code.")
    parser.add_argument("project", type=Path, help="project directory containing package.json and package-lock.json")
    parser.add_argument("--advisories", type=Path, help="local JSON array of advisory records")
    parser.add_argument("--format", choices=("markdown", "json"), default="markdown")
    args = parser.parse_args()
    project = args.project.resolve()
    package_json = load_json(project / "package.json")
    lock_json = load_json(project / "package-lock.json")
    advisories = load_json(args.advisories) if args.advisories else {}
    records = advisories if isinstance(advisories, list) else advisories.get("advisories", [])
    findings = prioritize(package_json, lock_json, records)
    if args.format == "json":
        print(json.dumps({"project": str(project), "findings": findings}, indent=2))
    else:
        print(render_markdown(project, findings, str(args.advisories or "none supplied")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
