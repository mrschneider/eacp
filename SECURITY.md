# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |

## Reporting a Vulnerability

Do **not** open a public issue for security vulnerabilities.

Report privately via GitHub Security Advisories
(**Security → Report a vulnerability**) or email `guilherme.barcha@gmail.com`.

You will receive an acknowledgment within 48 hours. Please include:

- Affected component (relay, client, frame, security, ...)
- Steps to reproduce or a proof-of-concept
- Expected vs. actual behavior

## Security Model Notes

- PlatSec capability checks run **before** any handler/LLM invocation (L2 enforcement).
- Token budgets are escrowed **before** any handler runs; over-budget work is refused without spending compute (`EACP_ERR_TOKEN_OVERFLOW`).
- Frame signatures cover the full header + slots 0–2; tampering invalidates the frame.
- The relay performs transit signature verification and drops spoofed frames at the boundary.
- Payload decompression happens **after** the 16 MB DoS guard is applied to the declared length.
