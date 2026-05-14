# Product

## Register

product

## Users

Tawny is for technical operators, security-minded engineers, homelab builders, and portfolio reviewers who need to understand endpoint activity without operating a full enterprise SIEM. They use it in a focused dashboard context: checking enrollment, agent health, recent telemetry, and raw event detail during local development or a small self-hosted deployment.

## Product Purpose

Tawny is a self-hosted, lightweight EDR system. A compact Windows and macOS agent enrolls with a .NET API, ships telemetry, and presents endpoint state in a Next.js dashboard. The product succeeds when a user can bootstrap the stack, enroll an endpoint or synthetic test agent, confirm telemetry is flowing, and inspect event details without friction.

## Brand Personality

Quiet, precise, watchful. The interface should feel competent and calm, with enough density for repeated operational use. It should not feel like a marketing dashboard, a toy security demo, or a dark-mode novelty app.

## Anti-references

Avoid generic cyber dashboards with neon green on black, fake threat-map drama, heavy gradients, oversized hero metrics, decorative glass panels, and security theater. Avoid enterprise bloat that hides simple local-development workflows. Avoid UI that suggests incident-response maturity the MVP does not yet have.

## Design Principles

1. Show real system state first: agents, telemetry, enrollment, and operational status should be visible without ceremony.
2. Make local testing obvious: Docker bootstrap, synthetic telemetry, and enrollment flows should feel direct and inspectable.
3. Favor dense clarity over decoration: the user is scanning events and endpoint status, not reading a pitch deck.
4. Keep trust visible: timestamps, IDs, token state, and raw payloads should be easy to verify.
5. Be honest about scope: MVP surfaces should look finished without implying enterprise-only features that do not exist yet.

## Accessibility & Inclusion

Target WCAG AA contrast for text and controls. Preserve visible keyboard focus, logical tab order, reduced-motion compatibility, and readable table content at laptop and desktop sizes. Avoid conveying state through color alone; pair status color with text labels.
