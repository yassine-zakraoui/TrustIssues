# Security policy

## Scope

SENTINEL is a local simulator with synthetic data. Security reports we want:

- sandbox or container escapes, and ways to reach the host, the network, or the Docker socket;
- ways for a solution to reach the host, the network, or the Docker socket;
- ways to alter simulator state outside declared scenario surfaces;
- validator bypasses that let a scenario mutation touch undeclared state;
- accidental exposure of real credentials or personal data.

Attacks against the simulated agent inside declared scenario surfaces are the challenge itself, not
vulnerabilities.

## Reporting

Report privately to `skander.yacoubi@supcom.tn`. Include the affected version, steps to reproduce
against a local checkout, and the impact. Do not open public issues for unfixed vulnerabilities.

## Rules

- Reproduce only on your own local checkout. Never test against shared challenge, sponsor, or third-party
  infrastructure.
- Do not access, modify, or retain data beyond what is needed to demonstrate the issue.
- Do not use real credentials or personal data.

Good-faith reports that follow these rules will not be penalized in the challenge. The maintainers will
acknowledge reports, fix confirmed issues, and credit reporters who want credit.

## Hardening summary

See [docs/security-model.md](docs/security-model.md).
