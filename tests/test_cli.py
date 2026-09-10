import json
from pathlib import Path

from dependency_risk.cli import dependency_paths, prioritize, render_markdown


def test_direct_and_transitive_paths():
    package = {"dependencies": {"alpha": "^1.0.0"}}
    lock = {"packages": {"": {}, "node_modules/alpha": {}, "node_modules/alpha/node_modules/beta": {}}}
    assert dependency_paths(package, lock) == {"alpha": "direct", "beta": "transitive"}


def test_prioritizes_direct_critical_first():
    package = {"dependencies": {"alpha": "1.0.0"}, "devDependencies": {"beta": "1.0.0"}}
    lock = {"packages": {"": {}, "node_modules/alpha": {}, "node_modules/beta": {}}}
    findings = prioritize(package, lock, [{"package": "beta", "severity": "high"}, {"package": "alpha", "severity": "critical", "fixed_version": "2.0.0"}])
    assert [item["package"] for item in findings] == ["alpha", "beta"]
    assert findings[0]["scope"] == "direct"


def test_markdown_discloses_empty_input(tmp_path: Path):
    report = render_markdown(tmp_path, [], "none supplied")
    assert "not a clean security bill of health" in report
