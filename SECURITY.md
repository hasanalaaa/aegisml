# Security policy

## Supported versions

AegisML is alpha software. Until the first `2.x` release is published, security
fixes land on the `main` branch. After publication, only the latest `2.x`
release and `main` are expected to receive security fixes; older and unrelated
`aegisml` distributions are not supported by this project.

## Report a vulnerability privately

Do not publish an exploitable report, malicious model, credential, or user data
in a public GitHub issue.

Use the repository's
[Security → Report a vulnerability](https://github.com/hasanalaaa/aegisml/security/advisories/new)
flow.

If GitHub does not show private reporting, open a public issue containing only
a request for a private contact channel. Do not include technical exploit
details in that issue.

Include, when available:

- the affected commit, version, component, and operating system;
- impact and realistic attack prerequisites;
- minimal reproduction steps using synthetic data;
- logs or reports with secrets and personal data removed; and
- a suggested mitigation or patch.

There is no guaranteed response or remediation SLA. Maintainers will prioritize
reports according to demonstrated impact, exploitability, and available
resources, and will coordinate disclosure when a fix is ready.

## Scope

Security reports may cover:

- the `aegisml-scanner` distribution, `aegisml_scanner` import package, and
  `aegisml` command;
- the repository's GitHub Action and release/install path;
- the FastAPI scan engine and background worker;
- the web application and authentication flows; and
- repository-owned deployment configuration.

Reports about the unrelated PyPI distribution named `aegisml`, third-party
services, or vulnerabilities that exist only in unsupported modified forks are
outside this project's control. Dependency vulnerabilities are still useful
when you can show that AegisML reaches the affected code path.

## Safe handling

Use the smallest synthetic artifact that demonstrates the issue. Do not test
against systems or accounts you do not own, cause service disruption, upload
third-party confidential models, or retain data obtained during testing.

Scanner output is evidence, not a safety warranty. A clean result cannot prove
that an arbitrary model is free of unknown exploits, poisoned weights, or
task-specific behavioral backdoors.
