# Security Policy

## Scope

Security reports are welcome for vulnerabilities in iOS-RE Agent itself, including unsafe archive handling, path traversal, denial-of-service inputs, unsafe report generation, and accidental disclosure by the report generator.

## Supported versions

Until the project has a stable release, the latest `main` branch is the only supported version.

## Reporting

Please do not publish details of an exploitable issue before maintainers have had a chance to assess it. Use GitHub's private vulnerability reporting feature if it is enabled for the repository, or contact the repository maintainers privately through a verified contact method. Do not include real credentials, personal information, or proprietary app packages in a public issue.

## Safe use

The tool is designed to inspect untrusted app artifacts as data. It should not execute the target app, extract archive members to arbitrary paths, or attempt to bypass platform protections. Reports can still contain proprietary metadata; review them before sharing.
