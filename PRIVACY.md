# Privacy (Stage 11)

This is an engineering description of what personal data fraud-ai stores and what can be
done with it. **It is not a legal assessment.** No GDPR (or other) compliance is claimed. A
real deployment needs, among other things:

* a lawful basis;
* a DPIA;
* a record of processing;
* subject-rights procedures owned by the data controller.

All bundled data is synthetic.

## 1. Inventory

`fraud-ai privacy inventory [--format json]` prints the inventory from
`fraud_ai/privacy/inventory.py`. It lists every stored field that holds, or is derived
from, personal data, with its:

* data class and table/field;
* purpose and retention;
* pseudonymisation;
* access path and deletion capability.

A test (`check_inventory`) fails if an entry no longer matches the schema.

The main points:

* **Hashed identifiers.** IPs, device ids, addresses and payment fingerprints are stored as
  keyed HMAC-SHA256 values, using `PSEUDONYMISATION_KEY`.
* **Raw IPs** are stored only with `STORE_RAW_IP=true`, and nulled after
  `RETENTION_RAW_IP_DAYS` (30).
* **Cards:** PAN, CVV and PIN are never stored; the event contract refuses them. Payment
  methods keep a processor token reference, the brand, the last 4 digits, the issuer
  country and a keyed fingerprint.
* **Immutable records:** risk assessments, model predictions, feature snapshots, fraud
  labels and the audit log are kept by design.

## 2. Free text

Every user-controlled free-text input is declared in `fraud_ai/privacy/freetext.py`, with a
maximum length and a rule:

| Input | Max | Rule |
|---|---|---|
| review note (`POST /v1/reviews/{id}/resolve`, CLI) | 500 | reject (plus the Stage 8 checks for UUIDs, street addresses and instructions) |
| policy approval note | 500 | reject |
| policy promotion note | 500 | reject |
| deployment note | 500 | reject |
| API key name | 100 | reject |
| `FRAUD_CONFIRMED.notes` | 1000 | sanitise |
| login `failure_reason`, decision `reason`, chargeback `reason_code` | 64 / 64 / 32 | sanitise |
| `network.asn_org` | 255 | sanitise |

**Detected:**

* e-mail addresses;
* phone numbers (9–15 digits; dates and times are not phones);
* valid IPv4/IPv6 addresses;
* Luhn-valid card-like numbers;
* obvious tokens and secrets: `key=value` secrets, bearer tokens,
  `sk_`/`rk_`/`whsec_`/`pk_`/`tok_` values, fraud-ai credentials and signatures.

**Rules:**

* **reject** (operator and analyst text): the request is refused, naming the kinds found.
  Nothing is stored.
* **sanitise** (merchant event text): each detected value is replaced by `[EMAIL]`,
  `[PHONE]`, `[IP]`, `[CARD]` or `[SECRET]` before storage. Refusing the event would lose
  a fraud label. Card numbers are refused outright by the event contract even here.

**Structured fields are not touched.** `metadata.network.ip` is hashed rather than
"sanitised". Codes such as `merchant_category`, `card_last4` and `country` are typed and
pattern-validated.

**Limit:** the patterns catch common formats, not names or every possible identifier.
They are a guard rail, not a guarantee.

## 3. Retention

The Stage 10 classes:

* replay tokens;
* idempotency records;
* WebAuthn challenges;
* payment requests;
* failed attempts;
* raw IPs.

The Stage 11 core classes are all **off by default** and need an explicit `RETENTION_*_DAYS`:

| Class | Action | Setting |
|---|---|---|
| raw network observations (`network_events`) | delete | `RETENTION_NETWORK_OBSERVATION_DAYS` (0, or ≥ 180: beyond every feature window) |
| request metadata (`security_events.details`) | empty the details; keep the event | `RETENTION_REQUEST_METADATA_DAYS` |
| old investigations (LLM explanations) | delete | `RETENTION_INVESTIGATION_DAYS` |
| review notes (`review_outcomes.note`) | set to NULL; keep the resolution | `RETENTION_REVIEW_NOTE_DAYS` |

Run it with `fraud-ai retention plan | run [--execute --yes] | status`. A run is a dry run
unless executed, and every run is audited.

**Never deleted by retention:**

* risk assessments;
* fraud labels;
* model, policy and deployment history;
* review items;
* the event log;
* audit events, signatures and approvals.

The code refuses to touch them (`PROTECTED_TABLES`). Review outcomes may only have their
note nulled.

## 4. Erasure analysis

`fraud-ai privacy erasure-plan <merchant-ref-or-user-id> [--format json]` is a **dry run**.
It changes nothing, and reports for that user:

* **erase:** passkeys, challenges, device links, raw network observations, investigations;
* **pseudonymise:**
  * the customer reference (replaced with a random value);
  * address and card attributes (nulled);
  * label and review notes (nulled);
* **must remain**, with the reason:
  * the immutable event log;
  * assessments, predictions, snapshots and labels;
  * transactions and login records;
  * review items and authentication evidence;
* **dependencies:** every foreign key to `users`, which is why the user row itself cannot
  simply be deleted.

Executing an erasure is deliberately **not implemented**. Whether evidence must be kept, and
for how long, is a legal decision for the controller. Deleting immutable fraud and audit
evidence would also break integrity guarantees that other stages rely on. The plan gives the
engineering facts for that decision.

## 5. Other known gaps

* **Pseudonymisation-key rotation:** not implemented. Rotating the key would break linkage
  to existing hashes.
* **IPv4 brute force:** the keyed IP hashes are only as strong as the secrecy of
  `PSEUDONYMISATION_KEY`. The IPv4 space is small.
* **`llamacpp-process` LLM runtime:** it passes the prompt as a process argument, which is
  visible to local users. Use `llamacpp-server` or `ollama` on shared hosts.
