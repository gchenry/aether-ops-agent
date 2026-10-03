# AI Slide Generation Prompts — SF Tech Week 2026
## *"Vibe Coding Hangover: Securing Agentic AI with Zero-Trust Architecture"*

All prompts below are **Workspace Safety-Filter Safe** (avoiding exploit trigger strings) and strictly follow **Google CISO Guidelines**:
* Always use **Google Cloud Security** (never "Google Unified Security").
* Always state **built with Gemini models** (never "powered by Gemini").
* Grounded in the CISO thesis: *"In the AI era, defense must move beyond human speed and scale—we must fight AI with AI."*

---

## 1. Master Full-Deck Prompt (Copy & Paste into Gemini Canvas / Gamma / Marp)

```text
Act as a Principal Google Cloud Security Architect creating a 9-slide 301 Advanced Technical Masterclass presentation for SF Tech Week 2026 (Terrace Stage).

Session Title: "Vibe Coding Hangover: Securing Agentic AI with Zero-Trust Architecture"
Speaker: Len Henry, Global Founder Advocate, Google Cloud
Target Audience: ~300 Startup Founders, CTOs, and Lead AI Architects
CISO Thesis: "In the AI era, defense must move beyond human speed and scale—we must fight AI with AI."
Terminology Rules: Always use "Google Cloud Security" (never "Google Unified Security") and always state "built with Gemini models" (never "powered by Gemini").
Visual Theme: High-contrast dark slate background (#0F172A), Google Cloud Blue (#4285F4), Security Emerald (#34A853), Amber (#FBBC04), crisp vector architecture blueprints.

Generate a 9-slide deck with on-slide layout, tables, and speaker notes following this exact structure:

Slide 1: Title Slide — "Vibe Coding Hangover: Securing Agentic AI with Zero-Trust Architecture"
- Subtitle: Transitioning from Passive Code Transcribers to Zero-Trust Orchestrators of Intelligent Agents
- Speaker: Len Henry, Global Founder Advocate, Google Cloud
- Footer badges: Google Cloud Security | Built with Gemini Models | Model Armor | Cloud Run Agent Identity (NHI) | Agent Gateway | Security Command Center (SCC) + Wiz AI-APP

Slide 2: The Vibe Coding Hangover & The Shadow AI Crisis (00:00 - 08:00)
- Contrast Information Risk (what an LLM outputs) vs. Functional Risk (what an autonomous agent executes in production).
- Explain the East-West Blindspot: Undocumented "Shadow AI" sub-agents and default MCP servers (0.0.0.0:8080) bypassing perimeter gateways.
- Cite Mandiant & Google Threat Intelligence Group (GTIG) data: Mean Time to Exploit (MTTE) is minus 7 days, and automated threat hand-offs occur in 22 seconds.

Slide 3: The Two "Hero" Vectors — ASI01 & ASI02 (OWASP Agentic Top 10, 2026)
- 2-row comparison table:
  1. Hero #1 — ASI01 (Agent Goal Hijacking): Embedded directives inside external files, manifests, or tickets that redirect agent intent (triggers ASI06 Memory Poisoning). Mitigated by Google Cloud Model Armor + Context Hardening.
  2. Hero #2 — ASI02 (Tool Misuse & MCP Server Crisis): Direct unattested calls to internal MCP/tool endpoints on 0.0.0.0:8080 (triggers ASI03 Identity Abuse & ASI08 Cascading Failures). Mitigated by Google Cloud Agent Gateway + Cloud Run Agent Identity (principal://...).
- Callout banner: LIVE DEMO — ./generate_mtls_certs.py && ./tests/test_security.py

Slide 4: 301 Live Teardown — Multi-Agent Swarm Scenarios (08:00 - 22:00)
- Show the 3 live teardown stages executed by ./run_vibe_teardown.sh:
  1. Hero #1 (ASI01 + ASI06): Untrusted YAML manifest with embedded metadata directives intercepted by Model Armor and quarantined from session memory.
  2. Hero #2 (ASI02 + ASI03): Unregistered Shadow AI Non-Human Identity (spiffe://aether.internal/ns/shadow-ai/sa/vibe-coder) blocked from direct tool invocation.
  3. The Cascade (ASI08 + ASI09): Swarm hop-count circuit breaker (max_swarm_depth=2) and Human-in-the-Loop (HITL) enforcement for critical severity actions.

Slide 5: The Zero-Trust Production Blueprint — The 3Cs Framework (22:00 - 37:00)
- 3-column architectural blueprint:
  1. CONTAIN (Zero-Trust for Non-Human Identities): Cloud Run Agent Identity (principal://...), SPIFFE X.509-SVIDs, Mutual TLS (Certificate Manager TrustConfig & ServerTlsPolicy), and Cloud Run gVisor sandboxing (ASI05).
  2. CURATE (Context Hardening & Gateway Governance): Google Cloud Agent Gateway (single MCP/A2A inspection point), Google Cloud Model Armor (ASI01), bounded memory windows (ASI06), and blast-radius circuit breakers (ASI08).
  3. CONTROL (Dynamic Authorization & Runtime Telemetry): Attribute-Based Access Control (ABAC), Semantic Auditor built with Gemini models, HITL workflows (ASI09), and Security Command Center (SCC) + Wiz AI-APP (ASI04, ASI10).

Slide 6: 3Cs Deep Dive — CONTAIN & CURATE (NHI, Edge mTLS & Context Boundaries)
- Left card (CONTAIN): Cloud Run Agent Identity + SPIFFE X.509-SVID mTLS enforced at the Application Load Balancer (ServerTlsPolicy: REJECT_INVALID) and container socket layer (mitigating ASI03 & ASI07).
- Right card (CURATE): Google Cloud Model Armor pre-screening + SessionStore memory quarantine and sliding window cap (MAX_CONTEXT_WINDOW=6) preventing ASI06 Context Poisoning.

Slide 7: 3Cs Deep Dive — CONTROL (Runtime ABAC, Gemini Semantic Auditor & SCC + Wiz AI-APP)
- 5-row ABAC evaluation table showing how app/abac.py verifies:
  1. Subject NHI & mTLS X.509 Binding (ASI03, ASI07)
  2. Model Armor Cleanliness & Cryptographic Gate Attestation (ASI01, ASI02)
  3. Environment, Tenant Isolation & Swarm Circuit Breaker (ASI08)
  4. Action Severity & HITL Approval Token (ASI09)
  5. Security Command Center (SCC) + Wiz AI-APP Telemetry (ASI04, ASI10)
- Callout banner: LIVE DEMO — ./test_agent_gateway.sh

Slide 8: Full OWASP Agentic Top 10 (2026) Architectural Matrix
- 10-row summary table mapping ASI01 through ASI10 to the 3Cs Framework (Contain, Curate, Control) and the Google Cloud Security stack.

Slide 9: The Founder's 5-Point Monday Morning Checklist (37:00 - 45:00)
- 5 numbered takeaways:
  1. Sanitize Tool Endpoints (No raw 0.0.0.0 MCP servers; require Agent Gateway & mTLS).
  2. Assign Distinct NHIs (Cloud Run Agent Identity principal://... + SPIFFE X.509-SVIDs).
  3. Implement ABAC at Tool Boundaries (Evaluate NHI, environment, tenant, swarm depth, and severity).
  4. Deploy Guard Interceptors (Google Cloud Model Armor + semantic auditors built with Gemini models).
  5. Establish AI-BOM Hygiene (Continuous posture & dependency scanning with SCC + Wiz AI-APP).
- Footer: github.com/gchenry/aether-ops-agent
```

---

## 2. Individual Google Slides Gemini Side-Panel Prompts (Filter-Safe)

### Slide 1: Title Slide
> Create a dark-mode technical keynote title slide titled "Vibe Coding Hangover: Securing Agentic AI with Zero-Trust Architecture". Add subtitle "Transitioning from Passive Code Transcribers to Zero-Trust Orchestrators of Intelligent Agents" and speaker "Len Henry, Global Founder Advocate, Google Cloud". Add a bottom badge bar: Google Cloud Security | Built with Gemini Models | Model Armor | Cloud Run Agent Identity | Agent Gateway | SCC + Wiz AI-APP.

### Slide 2: The Vibe Coding Hangover & The Shadow AI Crisis
> Create a two-column executive technical slide titled "The Vibe Coding Hangover & The Shadow AI Crisis". Left column: three points covering "Information Risk vs. Functional Risk", "The East-West Blindspot (Undocumented Sub-Agents & Default 0.0.0.0:8080 MCP Servers)", and "Mandiant & Google Threat Intelligence Group (GTIG) Data: -7 Days MTTE & 22-Second Hand-Offs". Right column: a diagram contrasting North-South perimeter gateways with East-West multi-agent communication.

### Slide 3: The Two "Hero" Vectors — ASI01 & ASI02
> Create a structured comparison slide titled "OWASP Agentic Top 10 (2026): The Two Hero Vectors". Include a 2-row table comparing "Hero #1 — ASI01: Agent Goal Redirection" (embedded directives in external manifests/files mitigated by Google Cloud Model Armor and Context Hardening) and "Hero #2 — ASI02: Direct Tool Misuse" (unauthenticated calls to internal MCP/tool endpoints mitigated by Google Cloud Agent Gateway, Cloud Run Agent Identity, and ABAC).

### Slide 4: 301 Live Teardown — Multi-Agent Swarm Scenarios
> Create a 3-card technical walkthrough slide titled "301 Live Teardown: Multi-Agent Swarm Scenarios". Card 1: "Hero #1 (ASI01 & ASI06): Untrusted Manifest Directives & Memory Quarantine". Card 2: "Hero #2 (ASI02 & ASI03): Unregistered Shadow AI Non-Human Identity (`spiffe://.../vibe-coder`)". Card 3: "The Cascade (ASI08 & ASI09): Swarm Circuit Breakers (`max_swarm_depth=2`) & Human-in-the-Loop (HITL) Governance". Add bottom callout: "LIVE DEMO: `./run_vibe_teardown.sh`".

### Slide 5: The Zero-Trust Production Blueprint — The 3Cs Framework
> Create a 3-pillar architectural slide titled "The Zero-Trust Production Blueprint: The 3Cs Framework". Column 1: "1. CONTAIN (Non-Human Identities)" — Cloud Run Agent Identity (`principal://...`), SPIFFE X.509-SVID Mutual TLS, and gVisor sandboxing. Column 2: "2. CURATE (Context & Gateway Governance)" — Google Cloud Agent Gateway, Model Armor input filtering, and bounded memory windows. Column 3: "3. CONTROL (Dynamic ABAC & Telemetry)" — Runtime ABAC, Semantic Auditor built with Gemini models, HITL workflows, and Security Command Center (SCC) + Wiz AI-APP.

### Slide 6: 3Cs Deep Dive — CONTAIN & CURATE
> Create a two-column architecture deep-dive slide titled "CONTAIN & CURATE: Non-Human Identity, Edge mTLS & Context Hardening". Left card: "CONTAIN — Cryptographic NHI & Mutual TLS" detailing Cloud Run Agent Identity (`principal://...`), SPIFFE X.509-SVIDs, and Certificate Manager `TrustConfig` + `ServerTlsPolicy`. Right card: "CURATE — Model Armor & Memory Boundaries" detailing pre-persistence screening and sliding context windows (`MAX_CONTEXT_WINDOW = 6`) to prevent ASI06 Context Contamination.

### Slide 7: 3Cs Deep Dive — CONTROL (Filter-Safe Prompt)
> Create a 3-stage enterprise security architecture slide titled "CONTROL: Dynamic ABAC, Semantic Auditing & SCC + Wiz AI-APP". Format as three connected horizontal cards:
> Card 1: "Stage 1: Google Cloud Model Armor & Gate Attestation" — Validates incoming manifests and issues cryptographic HMAC attestations (ASI01 & ASI02 Protection).
> Card 2: "Stage 2: Semantic Auditor Built with Gemini Models & ABAC" — Evaluates Non-Human Identity, environment, tenant isolation, swarm hop depth (ASI08), and HITL approval tokens (ASI09).
> Card 3: "Stage 3: Google Cloud Security Command Center & Wiz AI-APP" — Correlates AI-BOM dependencies (ASI04), cloud posture, and rogue agent telemetry (ASI10).

### Slide 8: Complete OWASP Agentic Top 10 (2026) Architectural Matrix
> Create a 10-row reference table slide titled "OWASP Agentic Top 10 (2026) Architectural Matrix". Columns: "OWASP ID & Risk", "Architectural Pillar (Contain / Curate / Control)", and "Google Cloud Security & Zero-Trust Defense". Include rows for ASI01 Goal Redirection, ASI02 Tool Misuse, ASI03 Identity Abuse, ASI04 Supply Chain (AI-BOM + Wiz), ASI05 Code Execution (Cloud Run gVisor), ASI06 Memory Contamination, ASI07 Inter-Agent Comm (mTLS), ASI08 Cascading Failures (Circuit Breakers), ASI09 Trust Abuse (HITL), and ASI10 Drifting Agents (SCC + Wiz AI-APP).

### Slide 9: The Founder's 5-Point Takeaway Checklist
> Create an executive action plan slide titled "The Founder's 5-Point Monday Morning Security Checklist". List 5 numbered items:
> 1. Sanitize Tool Endpoints: Enforce Google Cloud Agent Gateway and Mutual TLS on all MCP/tool servers.
> 2. Assign Distinct NHIs: Bind every agent to a dedicated Cloud Run Agent Identity (`principal://...`) and SPIFFE X.509-SVID.
> 3. Implement ABAC at Tool Boundaries: Authorize calls dynamically based on NHI, environment, tenant, swarm depth, and severity.
> 4. Deploy Guard Interceptors: Place Google Cloud Model Armor and semantic auditors built with Gemini models ahead of execution tools.
> 5. Establish AI-BOM Hygiene: Track agent skills and runtime posture with Google Cloud Security Command Center (SCC) and Wiz AI-APP.
> Add footer quote: "In the AI era, defense must move beyond human speed and scale—we must fight AI with AI."
