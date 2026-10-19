# Email8:SDK - Business Requirements & Functionality

> Audience: product owners, business analysts, and anyone evaluating what
> Email8:SDK **does for the business**. For architecture read `README.md`;
> for wire-level detail read `DESIGN.md`.

## 1. Business Purpose

Email8:SDK is the **shared vocabulary of the Email product line**. It
delivers:

- **One mail stack, four consumers** - the SMTP/IMAP/JMAP/DAV/Sieve
  wire logic, mail parsing, authentication math, queue math, and spam
  scoring exist once, so protocol behavior is identical across the
  MTA, Store, Access, and Gate instead of drifting per service.
- **Standards compliance as a product feature** - RFC-faithful protocol
  codecs (5321, 5322, IMAP4rev2, 8620/8621, 5804, 5228, 5545, 6350)
  are what make third-party interop a guarantee rather than an
  aspiration.
- **A stable contract surface** - event payload shapes and Store data
  API DTOs published here are versioned with the SDK tag; service teams
  evolve against a pinned contract instead of a moving code target.
- **Fast vertical onboarding** - a new service or tooling team imports
  `email8::…` and is immediately protocol-capable without reading four
  different implementations.

## 2. Business Scope (What the Library Provides)

| # | Capability area | What the business gets |
|---|---|---|
| 1 | Contracts crate | Shared event payload shapes (`email8:*` envelopes), enums, queue schedules, Store data API DTOs, error vocabulary |
| 2 | SMTP codec | RFC 5321 wire protocol (receiver, commands incl. BDAT/STARTTLS/LHLO, replies with enhanced status codes) |
| 3 | IMAP codec | IMAP4rev2 wire protocol (literal-aware receiver, typed commands, fetch/store items, sequence sets, response builders) |
| 4 | JMAP shapes | RFC 8620/8621 request/response types, capability URNs, reference resolution |
| 5 | DAV toolkit | Hand-rolled XML parse/build for PROPFIND/PROPPATCH/REPORT, multistatus, ETags, locks, Depth |
| 6 | Sieve engine | RFC 5228 compiler + interpreter with the declared extension set (pure, no I/O) |
| 7 | Mail core | RFC 5322/MIME parsing, envelope/preview extraction, localized full-text analysis, thread keys |
| 8 | Mail auth | SPF/DKIM/DMARC/ARC evaluation + DKIM signing, DNS-abstracted for testability |
| 9 | Mail queue math | Reply classification, retry/notify/expiry schedules, RFC 3464 DSN building |
| 10 | Spam engine | Tag-scoring engine with per-env thresholds, URL/homograph scanners, DNSBL checks, FTRL classifier |
| 11 | iCal | RFC 5545 parse/build + RRULE expansion (VEVENT/VTODO subset) |
| 12 | vCard | RFC 6350 parse/build (FN, N, EMAIL+TYPE, ORG, TEL, NOTE, ADR) |
| 13 | Gate contracts | Listener registry publish/unpublish + PROXY v2 parse contract for the passthrough plane |
| 14 | Namespace facade | The `email8` facade crate re-exporting every leaf so consumers import one namespace only |

**What the library does NOT do (business boundary):**

| Out of scope | Owned by |
|---|---|
| Any persistence, HTTP serving, or listener running | The service repos (sdk is a pure library) |
| Identity issuance or token handling | Sentin8:Auth / the services |
| Network I/O (DNS, SMTP conversations as a client) | Services consume the codecs; sdk stays I/O-free where design requires |
| The platform facade (policy engine, shell, bus clients) | Sentin8 platform SDK (`sentin8`) - a separate pin |

## 3. Business Capabilities

### 3.1 Wire-protocol fidelity

| Capability | Business rule |
|---|---|
| SMTP dialect | Commands/enhanced replies model the real wire; helper replies (`rate_limited`, `queue_full`, `too_many_recipients`, …) encode operational semantics in one place |
| IMAP dialect | Server-role codec with incremental literal handling and a typed FETCH/STORE vocabulary - clients cannot desync on parsing quirks |
| JMAP shapes | Batch request/response and per-method capability gating mirror RFC 8620 exactly; capability URNs are constants, not strings |
| DAV XML | Parse/serialize without a heavy XML stack - the DAV surface stays predictable and testable |
| Sieve | Compile-check before activation is the same engine everywhere; extensions are a fixed declared set |

### 3.2 Mail semantics

| Capability | Business rule |
|---|---|
| Message parsing | Envelope, preview, MIME walk, calendar-body detection are shared logic - what MTA screens is what Store files and Access reads |
| Threading | One thread-key algorithm across services - conversations never fork per protocol |
| Auth math | SPF/DKIM/DMARC evaluation lives in the sdk; MTA only orchestrates - policy math is uniform and testable |
| Queue math | Retry ladders, DSN construction, reply classification are constants of the product, not per-service choices |
| Spam scoring | Tags/thresholds/FTRL are shared so Store's training and MTA's verdicts speak the same language |

### 3.3 Contract stability

| Capability | Business rule |
|---|---|
| Event shapes | Every `email8:*` payload struct is pinned here; producers/consumers compile against the same shapes |
| DTOs | Store's internal data API request/response types live here, so callers in Access/MTA cannot drift from Store's handlers |
| Error vocabulary | Registered error codes/types shared by all services |
| Schedules | `QueueName::retry_schedule()` / notify / expiry values are the business SLA numbers, declared once |
| Versioning | Services pin a git tag (`email8-v0.x.y`), so a contract change is an explicit upgrade, never a silent shift |

## 4. Business Events (Outbound)

The SDK publishes **no events** - it *defines* the event envelope
payloads (`MessageReceivedEvent`, `RecipientStatusEvent`,
`DsnGeneratedEvent`, `ReportDueEvent`, `MessageExpiredEvent`,
`EmailIngestedEvent`, `MailboxChangedEvent`, `ThreadMergeEvent`,
`StateChangedEvent`, `GroupwareChangedEvent`, `DkimRotatedEvent`,
`SpamSampleRecordedEvent`, `QueueRecipientEvent`) that producing
services emit through the platform's Bus.

## 5. Business Rules & Invariants

1. **Single implementation per protocol concern**: no service
   reimplements parsing, screening math, or schedule constants.
2. **The facade is the only import surface**: consumers use
   `email8::{leaf}`; service-to-service internal deps are siblings
   inside the workspace only - an external consumer never references a
   leaf crate directly.
3. **Pure where it must be**: protocol/queue/auth/spam logic is
   I/O-injected (e.g. `FnDnsTxt` test hooks), so correctness is test-
   able without networks.
4. **Contracts change via tag bumps**: a breaking DTO/event change is
   a new `email8-vX` tag with consumer lockfile updates - never
   in-place drift.
5. **No platform code lives here**: platform identity/TLS/bus/policy
   stay behind the `sentin8` pin; the vertical sdk depends on it, not
   the reverse.

## 6. Target-User Roles & Use Cases

| Persona | What they do with Email8:SDK |
|---|---|
| MTA engineers | Use `smtp_proto` + `mail_queue` + `mail_auth` for the transfer engine |
| Store engineers | Use `jmap_proto` + `mail_core` + contracts for the data core |
| Access engineers | Use `imap_proto`, `sieve`, `dav_proto`, `ical`, `vcard` for protocol sessions |
| Gate engineers | Use `email8::gate::contracts` for listener registry + PROXY v2 parsing |
| Tooling/integration developers | Build internal tools against the same DTO/event contracts |
| QA engineers | Write protocol tests with the I/O-injected engines (no network needed) |

## 7. KPIs / Success Criteria

| Category | Target |
|---|---|
| Interop | Protocol codecs pass the RFC conformance cases the platforms demand (Thunderbird/Apple Mail/Outlook/MX interop starts here) |
| Consistency | One algorithm per concern (threading, retry, scoring) across all services |
| Safety | No `unsafe`, no panics on malformed input in codecs (typed errors) |
| Testability | Pure-function engines with injected I/O cover the RFC edge cases in unit tests |
| Stability | Tag-pinned semver-ish cadence; zero silent contract changes |

## 8. Dependencies & Reliance on Other Services

| Relied on | For |
|---|---|
| Sentin8 platform SDK (`sentin8` git pin) | Platform types used by consumers at the edges (service layer, not sdk internals) |
| Consumer repos (email8-mta/store/access/gate) | Their build/test pipelines compile the sdk workspace via the facade pin |

The SDK is upstream-only: nothing in the email8 vertical exists that
the sdk must call.

## 9. Acceptance Criteria

1. Every wire-shape struct round-trips (serialize → deserialize →
   identical).
2. Protocol receivers accept the RFC-conformant forms their consumers
   advertise (SMTP BDAT/STARTTLS/LHLO; IMAP literals; JMAP `#refs`).
3. Mail-queue schedules and DSN builders produce the documented
   ladders and RFC 3464 documents.
4. Spam components compute deterministic results given fixed inputs
   (thresholds injectable).
5. The facade compiles standalone (`make build`) and consumers only
   import `email8::*` surfaces.
6. `make test` passes across crates; `make tag` prints the current
   `email8-vX` pin.

## 10. Open Business Questions

- SDK packaging as crates.io publication (currently git-tag pinned).
- Additional groupware codecs (iCalendar VTIMEZONE completeness,
  vCard photos) as webmail/DAV UX deepens.

---

**Design attribution:** email8:sdk and its underlying concepts were designed by Hamid Jahanzad <Hamid@Jahanzad.com>.