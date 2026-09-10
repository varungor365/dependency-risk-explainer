# Dependency Risk Explainer

[![CI](https://github.com/varungor365/dependency-risk-explainer/actions/workflows/ci.yml/badge.svg)](https://github.com/varungor365/dependency-risk-explainer/actions/workflows/ci.yml)

**Turn Node.js dependency alerts into a short, prioritized explanation for small projects.**

Dependency Risk Explainer is a local-first CLI that distinguishes direct from transitive dependencies, ranks advisory records, and explains the next safe steps. It does not replace Dependabot, OSV-Scanner, npm audit, OpenSSF Scorecard, or human review.

## Why star this repository

Star this repository if you want a transparent, no-login starting point for understanding dependency risk without uploading a private repository or accepting an opaque security score.

## Three-minute quick start

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[test]'
dep-risk examples/node-project --advisories examples/advisories.json
```

The command reads only `package.json`, `package-lock.json`, and the advisory JSON you provide. It does not install packages, execute repository scripts, contact registries, or print secret values.

## Advisory input

The MVP accepts a local JSON array. Each record uses `package`, `severity`, `summary`, and optional `fixed_version` and `source` fields:

```json
[{"package":"example-package","severity":"high","summary":"Example advisory","fixed_version":"2.0.0","source":"https://example.com/advisory"}]
```

Use `--format json` for machine-readable output. The first release intentionally keeps advisory retrieval separate so users can review provenance and avoid sending private manifests to an external service.

## Safe defaults and honest limitations

The report is point-in-time and advisory. A vulnerability record does not prove exploitability or reachability, and no findings does not prove safety. Package-manager resolution, optional dependencies, runtime-provided libraries, vendored code, and advisory database differences can produce false positives or negatives. Review every upgrade, run tests, keep lockfiles committed, use frozen CI installs, and enable Dependabot alerts and security updates.

The tool never executes project code and never auto-fixes files. It is currently Node.js/npm-focused and does not yet parse every lockfile format or generate a software bill of materials.

## Development

```bash
python -m pip install -e '.[test]'
pytest -q
python -m compileall -q src tests
```

## References

- [GitHub supply-chain security](https://docs.github.com/code-security/supply-chain-security/understanding-your-software-supply-chain/about-supply-chain-security)
- [OpenSSF Scorecard](https://scorecard.dev/)
- [CISA SBOM guidance](https://www.cisa.gov/topics/information-communications-technology-supply-chain-security/sbom)

## License

MIT. See [LICENSE](LICENSE).
