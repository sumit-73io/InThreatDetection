# Core Banking Integration — Technical Architecture

How InThreatDetection integrates with a bank's core banking system (CBS) to
monitor privileged insider activity.

**Status.** Sections 1–8 describe the target architecture. Section 9 states
plainly which parts exist today and which are design-only, so this document can
be used for a real integration conversation without over-claiming. The platform
as built is a working insider-threat engine with a simulator front-end; the CBS
adapter layer described here is the work required to point it at a real bank.

---

## Table of contents

1. [Integration objective and scope](#1-integration-objective-and-scope)
2. [Topology and network zones](#2-topology-and-network-zones)
3. [Event ingestion contract](#3-event-ingestion-contract)
4. [Integration patterns per CBS capability](#4-integration-patterns-per-cbs-capability)
5. [Identity federation](#5-identity-federation)
6. [Mapping bank roles onto RBAC and PAM](#6-mapping-bank-roles-onto-rbac-and-pam)
7. [Detection and enforcement in a banking context](#7-detection-and-enforcement-in-a-banking-context)
8. [Compliance, audit and data protection](#8-compliance-audit-and-data-protection)
9. [Implementation status and gap analysis](#9-implementation-status-and-gap-analysis)
10. [Phased rollout](#10-phased-rollout)

---

## 1. Integration objective and scope

### The threat being addressed

A core banking system grants a small number of staff the ability to move money,
alter customer records, override limits and read account data at scale.
Perimeter controls do not see this: the actions are performed with valid
credentials, by people entitled to hold them. Detection has to be behavioural.

### In scope

- Continuous behavioural monitoring of CBS operator activity
- Per-person baselines ("normal environment") and deviation scoring
- Automated alerting and account freezing on material deviation
- Privileged access management over the monitoring platform's own controls
- A tamper-evident audit trail of monitored activity and operator actions

### Explicitly out of scope

- **Transaction fraud detection.** This platform watches *operators*, not
  transactions. It complements an AML/fraud engine; it does not replace one.
- **Customer-facing channel monitoring** (internet/mobile banking end users).
- **Being a system of record.** The CBS remains authoritative for all banking
  data. This platform stores behavioural telemetry and its own findings.
- **Automated reversal of banking transactions.** Enforcement here suspends
  *access*; it never rolls back a financial posting.

### The one architectural principle

**The integration is read-only against the CBS, except for identity
suspension.** The platform consumes events and, on a critical finding, requests
that a session or account be suspended. It never writes business data. This
keeps the blast radius of a compromise of the monitoring platform bounded, and
it is the single most important thing to be able to state to a bank's risk
committee.

---

## 2. Topology and network zones

```
┌─ Zone: CORE (highest trust, no inbound internet) ────────────────────────┐
│                                                                          │
│   ┌──────────────────┐      ┌─────────────────────┐                      │
│   │  Core Banking    │      │  CBS Audit / Journal│                      │
│   │  System          ├─────▶│  Tables · Log files │                      │
│   └────────┬─────────┘      └──────────┬──────────┘                      │
│            │ IAM events                │ activity events                │
│            ▼                           ▼                                 │
│   ┌──────────────────────────────────────────────────┐                   │
│   │  CBS Integration Adapter  (bank-side, per-CBS)   │                   │
│   │  · normalises to the canonical event contract     │                   │
│   │  · tokenises / drops customer identifiers         │                   │
│   │  · signs and batches                             │                   │
│   └────────────────────────┬─────────────────────────┘                   │
└────────────────────────────┼─────────────────────────────────────────────┘
                             │ mTLS, outbound-only, one direction
┌─ Zone: SECURITY (restricted) ───────────────────────────────────────────┐
│                             ▼                                            │
│   ┌──────────────────────────────────────────────────┐                   │
│   │  InThreatDetection API (FastAPI)                 │                   │
│   │  · ingestion  · risk + baseline  · anomaly       │                   │
│   │  · AI Twin    · unsupervised ML  · enforcement   │                   │
│   └───────┬──────────────────────────────┬───────────┘                   │
│           │                              │ suspension request            │
│   ┌───────▼────────┐            ┌────────▼──────────┐                    │
│   │  MongoDB       │            │  IAM / CBS admin  │  (narrow, audited, │
│   │  (encrypted)   │            │  suspension API   │   allow-listed)    │
│   └────────────────┘            └───────────────────┘                    │
└───────┬─────────────────────────────────────────────────────────────────┘
        │ HTTPS
┌─ Zone: CORPORATE ───────────────────────────────────────────────────────┐
│   SOC analyst workstations  →  SOC console (static SPA)                  │
└─────────────────────────────────────────────────────────────────────────┘
```

### Zone rules

| Boundary | Direction | Protocol | Notes |
|---|---|---|---|
| CORE → SECURITY | Outbound from CORE only | mTLS over HTTPS | The CBS zone initiates. Nothing in SECURITY may open a connection into CORE except the suspension call below. |
| SECURITY → CBS suspension API | Outbound, narrowly scoped | mTLS | Single endpoint, single verb, allow-listed by source IP and client cert. This is the only write path. |
| CORPORATE → SECURITY | Inbound | HTTPS | SOC console and API only. |
| SECURITY → internet | **Denied** | — | The detection stack is fully offline: statistical engines plus scikit-learn, no external model calls. |

The adapter living **inside** the CORE zone is deliberate: normalisation and
tokenisation of customer identifiers happen before data crosses a trust
boundary, so raw customer data never reaches the security zone.

---

## 3. Event ingestion contract

### Canonical event

The platform's internal model is `app/models/activity.py`. The adapter's job is
to map CBS-native events onto it. Extending `ActionType` with banking verbs is
the main code change on the platform side.

```json
{
  "employee_id":   "CBS-OP-4471",
  "action":        "VIEW_CUSTOMER",
  "timestamp":     "2026-07-26T09:14:22.118Z",
  "device_ip":     "10.42.8.31",
  "details":       "acct_ref=TKN_9f2c41a8; module=CIF; terminal=BR014-T3",
  "risk_score":    0
}
```

| Field | Required | Notes |
|---|---|---|
| `employee_id` | Yes | The **stable** CBS operator ID. Must not be an email or a display name — those change and would fragment the baseline. |
| `action` | Yes | A member of `ActionType`. Unmapped verbs must be mapped explicitly, never silently coerced. |
| `timestamp` | Yes | ISO 8601, UTC. Event time, not ingestion time. |
| `device_ip` | No | Encrypted at rest by the platform. |
| `details` | No | Free text. **Tokenised identifiers only** — see below. |
| `risk_score` | No | Ignored on input; the platform computes it. |

### Proposed banking action taxonomy

`ActionType` currently carries a generic set (`VIEW_CUSTOMER`,
`DOWNLOAD_CONFIDENTIAL`, `CHANGE_PERMISSION`, `DELETE_FILE`, `USB_CONNECTED`,
`FAILED_LOGIN`, …). For a CBS deployment, extend it and give each verb a static
weight in `risk_engine.RISK_WEIGHTS`:

| Proposed action | Suggested weight | CBS meaning |
|---|---|---|
| `VIEW_ACCOUNT` | 0 | Routine account inquiry |
| `VIEW_CUSTOMER_KYC` | 5 | KYC / CIF record access |
| `BULK_ACCOUNT_EXPORT` | 35 | Multi-account extract |
| `POSTING_CREATED` | 10 | Journal entry created |
| `POSTING_REVERSED` | 30 | Reversal — classic concealment step |
| `LIMIT_OVERRIDE` | 35 | Manual limit / hold override |
| `DORMANT_ACCOUNT_ACCESS` | 30 | Dormant accounts are a known target |
| `STANDING_ORDER_MODIFIED` | 25 | Beneficiary/payee change |
| `INTEREST_RATE_OVERRIDE` | 35 | Manual rate adjustment |
| `USER_PERMISSION_GRANTED` | 40 | Privilege grant inside the CBS |
| `MAKER_CHECKER_BYPASSED` | 45 | Dual-control bypass |
| `EOD_BATCH_MODIFIED` | 40 | End-of-day batch intervention |
| `AUDIT_LOG_ACCESSED` | 20 | Reading the audit trail itself |

Weights are the *static* layer only. The contextual layer — "this operator has
never done this, at this hour, at this volume" — comes from the baseline engine
and is where the real signal is.

### Data minimisation at the boundary

The adapter **must** apply before transmission:

1. **Tokenise** account numbers, customer IDs, card numbers and national IDs.
   Send `TKN_9f2c41a8`, never `1234567890123456`. The token must be stable per
   subject so volume patterns remain detectable, and non-reversible without a
   bank-held mapping.
2. **Drop** monetary amounts, balances and transaction narratives. The platform
   detects behavioural anomalies; it does not need values. Amount-based
   detection belongs in the AML engine.
3. **Retain** the operator identity, the action verb, the timestamp, the
   terminal/branch and the module. That is sufficient for behavioural detection.

This is what makes the security zone a low-value target: it holds behavioural
metadata about staff, not customer financial data.

### Transport

`POST /api/activities/` accepts one event per call and is currently
**unauthenticated** — acceptable for a simulator, unacceptable for a CBS feed.
For integration:

- Add mTLS client-certificate authentication on the ingestion route, or a
  dedicated service credential distinct from operator JWTs
- Add a batch endpoint (`POST /api/activities/batch`, e.g. up to 500 events) —
  per-event HTTP for CBS volumes is wasteful
- Make ingestion idempotent on a `(employee_id, timestamp, action, source_seq)`
  key so adapter retries cannot double-count. Double-counting directly inflates
  velocity and volume detectors into false positives.

---

## 4. Integration patterns per CBS capability

Choose by what the CBS actually offers, in descending order of preference.

### A. Native event stream (best)

The CBS publishes to Kafka/MQ. The adapter is a consumer.

- Latency: seconds. Enforcement is meaningful.
- Ordering and replay handled by the broker.
- Preferred whenever available.

### B. Database change capture

CDC (Debezium, Oracle GoldenGate, native CDC) on the CBS audit tables.

- Latency: seconds to a minute.
- Read-only on the CBS — attractive to bank DBAs.
- Requires a stable audit-table schema; couples you to it.

### C. Audit table polling

The adapter polls audit tables on a watermark column.

- Latency: the poll interval, typically 1–5 minutes.
- Simplest to authorise; works with almost any CBS.
- **Must** poll on a monotonic sequence/ID, not a timestamp — clock skew and
  same-timestamp batches silently drop events. Never poll a read-uncommitted
  view.

### D. Log shipping

Filebeat/Fluent Bit ships CBS application logs; the adapter parses them.

- Latency: near real time; reliability depends on the log format.
- Brittle — log formats change without notice between CBS releases.
- Acceptable as a supplementary source, poor as the primary one.

### Recommendation

Pattern **A** where the CBS supports it, **B** otherwise, **C** as the
pragmatic fallback for older cores. Whichever is chosen, the adapter is the only
component that knows the CBS's dialect; everything downstream sees the canonical
event.

---

## 5. Identity federation

### Operator identity

The platform's `employee_id` must be the CBS's **stable operator identifier**,
and the same value must appear in the event feed and in the identity directory.
If they differ, the adapter maintains the mapping — the platform must never see
two IDs for one human, or it will build two half-baselines and detect nothing.

### Console authentication

The console currently authenticates against its own `employees` collection with
plaintext passwords, plus a hardcoded built-in admin (see
`DEPLOYMENT.md` §12). Neither is acceptable in a bank. Target state:

- **OIDC / SAML SSO** against the bank's IdP (Entra ID, Ping, Keycloak)
- Console roles derived from **IdP group membership**, not from a locally stored
  job title
- MFA enforced at the IdP for every console role
- Local credentials removed entirely, except one sealed break-glass account with
  an offline-stored password and alerting on any use

Implementation shape: replace the password branch in `app/routers/auth.py` with
an OIDC authorization-code flow, keep `create_access_token` so the platform's
own short-lived JWT remains the session mechanism, and map IdP groups through
`console_role_for_job_title`'s replacement.

### Service identity

The adapter authenticates with an mTLS client certificate, not an operator
token. Certificate rotation is part of the bank's PKI lifecycle. The adapter's
identity holds exactly one permission: ingest events. It cannot read the
dashboard, and it cannot block anyone.

---

## 6. Mapping bank roles onto RBAC and PAM

The platform ships 5 console roles and 19 permissions, 4 of which are
privileged. A bank's roles map onto them roughly as follows:

| Bank function | Console role | Rationale |
|---|---|---|
| Head of Information Security | Super Admin | Only role holding `pam:approve` and `rbac:manage` |
| SOC Manager / Security Engineering | Security Admin | Can freeze accounts (with elevation), cannot approve their own elevation |
| SOC Analyst (L1/L2) | SOC Analyst | Investigate, scan, train; cannot freeze accounts |
| Internal Audit / Compliance | Auditor | Read-only across everything, plus the PAM audit trail |
| Branch/Ops staff under monitoring | Employee | No console access at all |

### Separation of duties

The design point a bank auditor will look for: **`pam:approve` sits only with
Super Admin, and Security Admin cannot self-approve.** A SOC Manager who wants
to freeze an account must obtain approval from Information Security. The one
exception is Super Admin break-glass self-approval, which is permitted so a lone
responder is never blocked during an incident — and is recorded with
`break_glass: true` in `pam_audit_log`, which should be a standing SIEM alert.

For a bank that requires strict four-eyes with no exception, remove
`pam:approve` from Super Admin's set and designate a second approver role. The
matrix is a single dictionary in `app/core/rbac.py`; this is a configuration
change, not a redesign.

### Privileged actions requiring just-in-time elevation

| Permission | Why it is privileged |
|---|---|
| `employees:block` | Freezing a banking operator's access has direct operational impact — a wrongly frozen teller stops serving customers |
| `aitwin:reset` | Wipes a learned baseline; an attacker would use it to erase evidence of their own deviation |
| `baseline:manage` | Locking/unlocking a baseline is how a poisoned "normal" could be installed |
| `rbac:manage` | Editing the role matrix is privilege escalation by definition |
| `overrides:manage` | Granting an enforcement exception deliberately weakens detection response for a named employee |

Elevation requires a justification of at least 15 characters, is capped at 60
minutes, and every request/approval/use/denial is appended to `pam_audit_log`.
Map the justification field to the bank's change-ticket reference so the audit
trail joins to the change management system.

---

## 7. Detection and enforcement in a banking context

### The layered detection stack

Seven detectors run against every scan, each catching a failure mode the others
miss:

| Layer | Catches | Bank-relevant example |
|---|---|---|
| Static risk weights | Inherently sensitive actions | Any `MAKER_CHECKER_BYPASSED` |
| Role–action matrix | Actions outside a role's remit | A teller performing a rate override |
| Velocity burst | Automation / scripted extraction | 3 bulk exports in 60 seconds |
| Off-hours | Activity outside normal working hours | Dormant-account access at 02:00 |
| Frequency z-score | Statistical outliers vs peers | One operator's reversals far above their branch |
| Unsupervised ML (IsolationForest + DBSCAN) | Patterns nobody wrote a rule for | An operator whose whole behavioural shape is unlike any peer group |
| AI Twin | Deviation from **that person's own** history | An operator behaving unlike themselves, even if normal for their role |

The AI Twin is the layer that matters most for insider threat, because a
long-tenured insider is *by definition* normal for their role. Comparing them to
themselves is what surfaces the change.

### Why the false-learning caps matter to a bank

Every learned layer can be poisoned by learning from bad data, and a
confidently-wrong baseline is worse than none: it makes the anomalous look
normal permanently. The platform therefore refuses to learn rather than learn
badly:

- **Baselines** refuse to build from a window that is already more than 35%
  high-risk activity (`contaminated_window`), and can be **locked** so
  recomputation cannot silently replace a verified baseline.
- **AI Twin training** clips values beyond 4σ of the partial baseline, counts
  every intervention, and **quarantines** a profile whose intervention rate
  exceeds 25% rather than promoting it to "trained".
- **Post-training drift** is capped at 0.5σ per update, bounding how fast a
  patient attacker can walk a baseline toward their own behaviour.
- **The ML detector** abstains entirely below 8 employees, refuses a
  high-risk-dominated training set, winsorises features before scaling, drops
  variance-collapsed features, and cannot emit `Critical` below 20 samples.

Operationally this means **`abstained` is a valid and expected answer, and it is
not the same as "no threats found"**. Any dashboard, report or SIEM rule built
on this feed must distinguish the two. Treating an abstention as an all-clear
reintroduces exactly the false confidence the caps exist to prevent.

### Enforcement

`enforcement_service` is the single decision point. Three triggers:

| Trigger | Threshold | Action |
|---|---|---|
| `BASELINE_DEVIATION` | contextual risk ≥ 60 | Alert + freeze |
| `AI_TWIN_CRITICAL` | composite threat ≥ 90 | Alert + freeze |
| `WINDOWED_RISK_THRESHOLD` | ≥ 120 risk in a rolling 24 h | Alert + freeze |

A freeze records the trigger, reason, severity and evidence, and stamps
`session_revoked_at` — which the client's status poll turns into a forced
logout.

The windowed threshold deserves note: an earlier implementation summed risk over
**all** activity ever, which guaranteed that every long-tenured employee
eventually crossed it through ordinary work. Scoping to a rolling window is what
makes the control usable in an environment where staff stay for decades.

### Banking-specific enforcement guidance

Freezing a live banking operator has customer impact. Recommended posture:

- **Alert-only** for the first 4–6 weeks in production. Tune thresholds against
  real behaviour before arming automatic freezing.
- **Time-of-day awareness.** Freezing a branch teller mid-transaction at 11:00
  is more disruptive than at 23:00. Consider alert-only during branch hours and
  automatic freeze outside them.
- **Never auto-freeze a break-glass or disaster-recovery operator account.**
  Maintain an exemption list; those accounts are legitimately anomalous by
  design.
- **Define the release path before go-live.** A frozen operator needs a
  documented, fast, audited route back. Manual unblock (requiring
  `employees:block` plus elevation) automatically attaches a short grace window,
  because the risk that caused the freeze is still inside the rolling window and
  would otherwise re-freeze the account on the operator's next action.
- **Use bounded overrides for planned exceptions.** Migrations, quarter-end,
  audits and cover arrangements are legitimately outside an operator's baseline.
  `overrides:manage` grants a time- or event-bounded exception scoped to specific
  actions, so authorised deviation is *recorded but not punished* — without
  resetting the baseline (which would destroy the history detection depends on)
  or disabling detection globally. Every grant, use and expiry is audited, and an
  unbounded grant is refused by policy.

---

## 8. Compliance, audit and data protection

### Tamper-evident audit trail

`activities` and `alerts` are hash-chained with SHA3-256: each document's hash
incorporates its predecessor's, so altering a historical record invalidates
every subsequent one. `GET /api/quantum/integrity/verify` reports the chain
state.

What this does and does not give you:
- **Does** detect after-the-fact modification of monitoring records, including
  by someone with database access.
- **Does not** prevent it, and does not protect against an attacker who can
  recompute the whole chain forward. For non-repudiation against a privileged
  insider, anchor periodic chain-head digests in an external append-only store
  (a WORM bucket, a notary service, or the bank's existing log-signing
  infrastructure). This is the gap to close for a regulator conversation.

### Data protection

- Sensitive activity fields (`device_ip`, `details`) are encrypted at rest with
  AES-256-GCM before storage
- The API exposes **status only** for cryptographic posture — no algorithm
  identifiers, key fingerprints, key strength, or per-record integrity hashes.
  Configuration detail is reconnaissance material and serves no operator
  decision
- Customer identifiers are tokenised **before** leaving the CORE zone (§3), so
  the security zone never holds raw customer data
- Enable MongoDB encryption at rest and TLS in transit

### Regulatory alignment

| Requirement | How it is met | Gap |
|---|---|---|
| Privileged access is controlled and time-boxed | RBAC + PAM elevation, 60 min cap, justification required | — |
| Privileged actions are logged and attributable | `pam_audit_log` records actor, target, permission, justification | Ship to an immutable store |
| Separation of duties | `pam:approve` held only by Super Admin; no self-approval below it | Break-glass is an audited exception |
| Audit records are tamper-evident | SHA3-256 hash chain | Needs external anchoring |
| Insider activity is monitored continuously | 60 s scan + per-event evaluation | — |
| Access reviews | Role matrix exposed via `GET /api/access/roles` | No periodic attestation workflow |
| Data minimisation | Tokenisation at the boundary; status-only crypto reporting | — |
| Strong authentication for privileged users | — | **Gap: SSO + MFA not implemented (§5)** |
| Credential protection | — | **Gap: employee passwords stored in plaintext** |

The two credential gaps are the blockers for a real banking deployment. They are
listed as OPEN in `DEPLOYMENT.md` §12 and should be closed in Phase 1.

### Retention

Align to the bank's policy, typically 5–7 years for audit records. Note from
`DEPLOYMENT.md` §10 that `activities` and `alerts` cannot be pruned from the
middle without breaking the hash chain — archive whole, never delete partially.

---

## 9. Implementation status and gap analysis

Stated plainly so this document can be used honestly.

### Built and verified

| Capability | Status |
|---|---|
| RBAC: 5 roles, 19 permissions, matrix + dependency enforcement | Built, tested |
| PAM: request → approve → time-boxed window → expire/revoke, full audit | Built, tested end to end |
| Privileged gating of block/reset/baseline-lock/rbac | Built, verified returns 403 without elevation |
| Normal-environment baselines with contamination guard and lock | Built, guard verified firing on real data |
| Contextual risk scoring with human-readable deviation reasons | Built, tested |
| Unified enforcement service, 3 triggers, forced logout | Built, verified end to end |
| Unsupervised ML detector with 7 false-learning caps | Built |
| AI Twin anti-poisoning caps + quarantine | Built |
| Tamper-evident hash chain + integrity verification | Pre-existing, retained |
| Data minimisation of cryptographic posture | Built, verified no leakage on any endpoint |
| SOC dashboard, charts with derived recommendations, theming | Built |

### Design-only — required for a real CBS integration

| Gap | Effort | Priority |
|---|---|---|
| CBS Integration Adapter (per-CBS; normalise, tokenise, sign, batch) | Large | P0 |
| Authenticated + batched + idempotent ingestion endpoint | Medium | P0 |
| Password hashing; remove hardcoded admin credentials | Small | P0 |
| OIDC/SAML SSO with MFA; role mapping from IdP groups | Medium | P0 |
| Banking action taxonomy added to `ActionType` and risk weights | Small | P1 |
| CBS suspension API client (the one write path) | Medium | P1 |
| External anchoring of hash-chain digests | Medium | P1 |
| Rate limiting and console account lockout | Small | P1 |
| SIEM forwarding of `pam_audit_log` and `enforcement_actions` | Small | P1 |
| Maker-checker / dual-control awareness in the detectors | Medium | P2 |
| Branch-hours-aware enforcement policy | Small | P2 |
| Periodic access-review attestation workflow | Medium | P2 |
| Externalised anomaly scan (to allow multi-worker scaling) | Small | P2 |

### Deliberate non-goals

Transaction fraud/AML detection, being a system of record, and automated
reversal of financial postings. Attempting any of these would expand the
platform's write authority into the CBS, which is precisely the property that
makes the integration defensible.

---

## 10. Phased rollout

### Phase 0 — Foundation (before any bank data)

Close the P0 credential gaps: hash passwords, remove the hardcoded admin, wire
SSO + MFA, set `JWT_SECRET_KEY`, lock down CORS, complete the
`DEPLOYMENT.md` §12 checklist. Nothing else should start until this is done.

### Phase 1 — Shadow ingestion (4–6 weeks)

Build the adapter for one CBS module (recommend CIF/customer inquiry — high
volume, low blast radius). Ingest to a non-production instance. Extend
`ActionType`. **Alert-only; enforcement disabled.** Goal: prove the event
contract and measure real volumes.

### Phase 2 — Baseline establishment (4 weeks minimum)

Accumulate behaviour, then build baselines and let AI Twin profiles train.
Expect and inspect refusals and quarantines — they are the system telling you
which populations are too noisy or already compromised to baseline. Lock the
verified baselines. Do not shorten this phase; a baseline built on too little
data is the false-confidence failure the caps exist to prevent.

### Phase 3 — Tuned alerting (4–6 weeks)

Enable full detection with human triage. Tune thresholds against real false
positives. Onboard SOC analysts against the real console. Stand up SIEM
forwarding. Still no automatic freezing.

### Phase 4 — Graduated enforcement

Enable automatic freezing, narrowly: outside branch hours first, on the highest
severity triggers only, with the exemption list in place and the release path
documented and rehearsed. Widen only on evidence.

### Phase 5 — Expansion

Additional CBS modules, additional detectors (maker-checker awareness,
branch-hours policy), the access-review workflow, external hash anchoring.

**Total realistic timeline to enforced production: 5–7 months**, dominated by
Phase 2, which cannot be compressed without undermining the detection quality
the whole platform depends on.

---

*Companion document: `DEPLOYMENT.md` covers installation, configuration and the
security hardening checklist.*
