# Privacy (Stages 11-12)

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

Executing an erasure is deliberately **not implemented** (§6 has the design and what is
missing). Whether evidence must be kept, and for how long, is a legal decision for the
controller. Deleting immutable fraud and audit
evidence would also break integrity guarantees that other stages rely on. The plan gives the
engineering facts for that decision.

## 5. Subject export (Stage 12)

`fraud-ai privacy export <merchant-ref-or-user-id> --out FILE` writes everything stored about
**one** user as JSON (`fraud_ai/privacy/export.py`). It serves an access request or an
investigation.

**Scope:**

* **One user only.** Rows are selected by that user's id, or through that user's own events
  and assessments. Tables shared between users (network identities, devices) are reached
  only through this user's links. No other user's id or data can appear. A test on a
  synthetic world, where users share networks, checks that no other user's id appears.
* **An explicit column allow-list per table** (`EXPORT`). A new column is not exported
  until someone adds it, so it is reviewed first. An allow-listed column that disappears
  from the schema makes the export fail loudly; it is never skipped silently.

**Nested JSON is redacted** (added after a staging finding, HARDENING.md §35).
Allow-listed JSON columns (event metadata, security-event details, signal values) are
exported with every nested key matching `NESTED_REDACT` removed: keyed hashes, token,
secret, credential and signature fields, and raw IPs. The number of removed keys is
reported (`redacted_nested_keys`).

**Never exported.** The export lists each exclusion and its reason in its own `excluded`
field:

* processor token references;
* WebAuthn credential ids, public keys and counters;
* challenge hashes;
* API keys;
* keyed pseudonyms (HMAC digests);
* feature vectors, raw model scores and LLM prompts or evidence packets;
* reviewer identities and staff notes;
* audit, operator-assertion and signature records;
* any signing material.

**Handling:**

* A `security_admin` action (`privacy.export`): an operator assertion is required when
  operator authentication is on, which is the default in staging and production.
* The file is created with mode `0600` and never overwritten.
* The audit event `privacy.exported` records who exported which pseudonym, and the row
  counts. It never records the data.

Tests: `tests/test_privacy_export.py`. The staging run is in HARDENING.md §35.

## 6. Erasure execution: design (not implemented)

**Status: erasure is NOT executed by any command.** The Stage 12 brief allowed irreversible
erasure only with complete safeguards. Four of them do not exist yet (§6.4), so only the
design and the dry run exist. This section is the design an implementation must follow.

### 6.1 Flow

1. **Plan (dry run, exists today).** `fraud-ai privacy erasure-plan <ref> --format json`
   lists, per table and column, what would be erased, pseudonymised or kept (§4).
   The implementation adds a **plan digest**: SHA-256 over the canonical plan plus the ids
   and counts of every affected row.
2. **Confirm.** `fraud-ai privacy erase --execute PLAN.json` would require all of:
   * an operator assertion from a `security_admin`, `action=privacy.erase`, bound to the
     plan digest, so a changed plan invalidates it;
   * a **second** authenticated person approving the same digest (the two-person rule, as
     for policy activation). Erasure is irreversible;
   * the operator typing the customer reference back (`--confirm <ref>`);
   * a fresh plan: at most one hour old, and the affected rows must still hash to the
     digest. If the customer produced new events since, it must re-plan;
   * an audit anchor taken immediately before, so the pre-erasure chain head is fixed in
     WORM storage;
   * a verified backup newer than the plan, so that a mistaken erasure is recoverable
     within the backup window (and see §6.3).
3. **Execute.** One transaction, as a **dedicated `fraud_privacy` database role**. It has
   exactly two kinds of rights:
   * DELETE on the erase classes;
   * column-level UPDATE on the pseudonymise columns.

   It has no rights on protected tables. The service role never gains them.
4. **Record.** The audit event `privacy.erased` holds:
   * the keyed pseudonym of the reference, never the reference;
   * the plan digest and per-table counts;
   * both operator ids and assertion ids.

   It never holds erased values. A tombstone row (the user id, the time, the plan digest)
   lets restores re-apply the erasure (§6.3).

### 6.2 What is erased, pseudonymised or kept

| Class | Treatment |
|---|---|
| passkeys, WebAuthn challenges, device links, raw network observations, LLM investigations | **delete** |
| customer reference | replaced with a random value |
| address and card attributes (country, region, postal prefix, brand, last 4) | set to NULL |
| label and review **notes** | set to NULL (the resolution stays) |
| **protected, never touched** (`PROTECTED_TABLES`): the event log, risk assessments, model predictions, feature snapshots, fraud labels, review items, audit events, signatures, approvals, operator assertions | kept, with the reason in the plan |

Protected records keep only pseudonymous links: keyed hashes and internal ids. Once the
reference is replaced, nothing in them names the customer. Whether that is enough is the
controller's legal decision. Deleting them would break the audit chain, the model
reproducibility and the fraud-evidence guarantees of other stages.

### 6.3 Backups and restores

An erasure does not reach existing backups. A restore must re-apply every tombstone
created after the backup was taken, **before** the service is started on the restored
database. The backup retention period therefore bounds how long erased data survives.
Both are procedures the controller must own.

### 6.4 Why it is not implemented

1. **No `fraud_privacy` role.** Without it, the only role able to execute is the migrator.
   That breaks the least-privilege model.
2. **No tombstone re-application in the restore procedure** (DISASTER_RECOVERY.md). A
   restore would silently resurrect erased data.
3. **Event metadata.** The immutable event log's `metadata` JSON can hold merchant-supplied
   attributes. Erasing inside it needs either crypto-shredding (per-user data keys), which
   is a schema change, or a legal decision that pseudonymous metadata may stay.
4. **The legal basis for keeping fraud evidence** is not decided (§4).

## 7. Retention in staging (Stage 12)

The request-metadata class was run on the staging stack (PostgreSQL, least-privilege
roles, operator authentication), on disposable synthetic data:

1. **Dry run** (`retention plan`): 361 `security_events.details` rows planned for
   emptying. Nothing changed.
2. **Execute without an operator assertion**: refused (`OPERATOR_AUTH_REQUIRED`). Nothing
   changed.
3. **Execute as `sec`** (`security_admin`, a `retention.execute` assertion): 361 rows emptied.
   The events stay, with empty details. A `retention.executed` audit event records the
   counts and the operator.
4. **Protected tables:** row counts identical before and after for:
   * risk assessments;
   * fraud labels;
   * the event log;
   * review items;
   * model, policy and deployment history;
   * audit events, approvals and signatures.
5. **Audit chain:** `audit verify` OK (27 events), and the anchors verified.

HARDENING.md §35 has the commands; the 5,000-user staging export run is there too.

## 8. Other known gaps

* **Pseudonymisation-key rotation:** not implemented. Rotating the key would break linkage
  to existing hashes.
* **IPv4 brute force:** the keyed IP hashes are only as strong as the secrecy of
  `PSEUDONYMISATION_KEY`. The IPv4 space is small.
* **`llamacpp-process` LLM runtime:** it passes the prompt as a process argument, which is
  visible to local users. Use `llamacpp-server` or `ollama` on shared hosts.
