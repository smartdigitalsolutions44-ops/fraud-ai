# Features

This document describes feature version **`fraud-features-1.0.0`**: what every feature
means, how it is calculated, why it exists, when it can be missing, and the point-in-time
rules that make the vectors safe to train on. The catalogue section at the end is generated
from `fraud_ai/features/definitions.py` (`fraud-ai features catalog --format markdown`) and
a test fails if the two ever disagree.

> Stage 2 produces *trustworthy inputs*, not decisions. No feature is a fraud rule, no
> feature carries a weight, and no model is trained here. A simple model on correct
> historical features beats a neural network trained on leaked data.

## 1. What a feature vector is

A `FraudFeatureVector` is computed for one **scored event** as of one **point in time**
(`as_of_timestamp`, by default the event's own timestamp). Two kinds of event are scored:

* **login events** (`LOGIN_ATTEMPT`, `LOGIN_SUCCESS`, `LOGIN_FAILURE`), including
  anonymous attempts against unknown usernames, and
* **transaction events** (`TRANSACTION_CREATED`).

Both kinds produce the *same* 107 features in the same order, so one model can consume
both. Features that do not apply to the event kind (for example transaction amounts on a
login) are `not_applicable`, and the context feature `event_kind` tells the model which kind
it is looking at.

The vector is typed by its feature set: every value is checked against its definition
(type, bounds, allowed categories, applicability) when the vector is built. An invalid
vector cannot be constructed, and validation rejects:

* NaN and infinite values, and wrong types (including booleans passed as integers);
* negative ages, counts or durations, and probabilities outside [0, 1];
* unknown categories;
* features that are missing without a reason, missing when they are non-nullable, or
  populated for an event kind they do not apply to;
* `as_of` earlier than the event;
* impossible combinations: more failed logins in 5 minutes than in 1 hour, more successful
  orders to an address than orders, or `shared_device_flag` disagreeing with
  `accounts_per_device`.

## 2. Missing data: zero is not unknown

Each feature is either **present** with a real value (including a genuine `0` or
`false`) or **missing** with an explicit reason:

| Reason | Meaning | Example |
|---|---|---|
| `unknown` | The source could not tell us. | Intel gave no VPN verdict; no email lifecycle event was ever received. |
| `not_observed` | Nothing in history to compute from yet. | No previous transaction, so there is no average. The device was never seen, so there is no "time since last seen". |
| `not_applicable` | The feature does not apply to this event. | Address features on a login; account features on an anonymous login; a ratio whose denominator is zero. |

Sentinels such as `-1` or `999` are **never** used. The vector keeps `values` and
`missing` separate. In Stage 3, ML preprocessing chooses how to encode each reason, for
example with indicator columns or model-native missing-value handling, and records that
choice with the model version.

Examples:

* With no previous transaction, `average_previous_transaction_amount` and
  `transaction_vs_average_ratio` are `not_observed`. They are never `0`.
* `transactions_last_24h = 0` is a real zero: the account made no transactions in the
  window.
* When no email lifecycle event exists, `email_verified` is `unknown`, not `false`.
* `recent_password_reset = false` is an observation: no reset was recorded in the window.

## 3. Point-in-time rules (no leakage)

For an event scored as of time **T**:

1. **Upper bound.** Every history query filters on `timestamp <= T`. Windows add a lower
   bound: a window of length *d* covers `(T - d, T]`, with the lower end excluded and T
   included. The windows are 5m, 15m, 1h, 6h, 24h, 7d and 30d, defined in
   `fraud_ai/features/windows.py`. "Recent" and "new" always mean the 24h window.
2. **Self-exclusion.** The scored event, and its transaction, never counts as its own
   history (for example, `logins_last_5m` does not count the login being scored). Ages
   include the current observation, so a brand-new device has `device_age_days = 0`.
3. **Immutable sources only.** Entity rows carry current-state caches such as device
   counters, `last_seen_at`, `user_devices.is_trusted`, the current IP intel and
   `transactions.status`, which a later chargeback overwrites. Features **never read
   them**. Everything is derived from timestamped event and observation rows:
   * network intel comes from the observation recorded with the event;
   * transaction outcomes come from the immutable `decision_outcome` with `decided_at <= T`;
   * device trust comes from prior MFA logins;
   * verification comes from `verified_at <= T` or from lifecycle event ordering.
4. **Labels.**
   * Fraud labels count toward `historical_chargebacks` and
     `historical_confirmed_fraud_events` only when their `labelled_at <= T`.
   * Labels on the scored event or transaction are always excluded, even when rescoring
     later.
   * Labels are never part of a vector. The dataset builder returns them separately.
5. **as_of.**
   * The default `as_of` is the event time, and it is the only valid choice for training.
   * A later `as_of` produces a retrospective vector: history up to that moment, still
     excluding the event itself.
   * An earlier `as_of` is rejected, because the event did not exist yet.
6. **Known limitation: ingestion time.**
   * Queries use *event time*. If events arrive late, a real-time scorer would not have
     seen them at T, but a recomputation would.
   * `feature_snapshots` store exactly what was computed and when; recomputation that
     disagrees is reported as drift.
   * Ingestion-time availability (`events.ingested_at <= generated_at`) is a Stage 8
     real-time-scoring concern.

### How leakage prevention is tested

* **The canonical test** (`tests/test_point_in_time.py`):
  1. Compute a 10:00 vector.
  2. Add a new device, a new IP, a password reset, an email change, two chargebacks, a
     fraud confirmation and a second account sharing the device and IP, all at 11:00.
  3. Recompute: the 10:00 vector is **identical**, and a vector as of 11:30 differs.
  This runs on SQLite and PostgreSQL.
* **Label leakage:**
  * A Jan 1 transaction with a Jan 20 chargeback: the Jan 1 vector does not know.
  * Labels on the scored transaction never count, even when they are linked only by
    transaction id.
* **Property test.** Database A holds a synthetic scenario's full history. Database B was
  built only from events up to T. For a sample of events at or before T, A and B give
  identical vectors. That covers every feature at once, including the "future" state
  sitting in A's entity caches.
* **Corruption test.** Overwriting every current-state cache column leaves historical
  vectors unchanged.
* **Mutation checks.** Removing any single `<= as_of` bound or self-exclusion from the
  history queries makes these tests fail. This was verified during development.

## 4. Determinism, hashing and versions

* **Determinism.** The same database state, event and feature version always produce the
  same vector.
  * Floats are rounded to 6 decimals, and `-0.0` is normalised.
  * Averages and medians are computed from integer minor units.
  * Ties are broken deterministically.
  * A test checks that SQLite and PostgreSQL produce byte-identical canonical JSON.
* **Hash.** The hash is the SHA-256 of the canonical JSON (sorted keys, no whitespace, no
  NaN) of `{feature_version, values, missing}`. Identifiers, `as_of`, generation time and
  provenance are *not* hashed, so recomputation never differs because of wall-clock time.
* **Versioning.** A released feature version is immutable.
  * The set's `fingerprint()` covers every feature's name, type, category, nullability,
    units, bounds, categories and applicability, plus the window and parameter
    configuration. It is pinned in the tests.
  * Changing any of these requires a new version (`fraud-features-1.1.0`) with its own
    pipeline entry in `fraud_ai/features/extractor.py`. Old versions keep producing exactly
    the vectors they always did.

## 5. Snapshots

`feature_snapshots` stores the exact vector used, or to be used, for a prediction:

| Column | Contents |
|---|---|
| `event_id` | The scored event. |
| `user_id`, `transaction_id`, `login_event_id` | Links to the account, transaction or login row. |
| `feature_version` | The feature version the vector was computed with. |
| `as_of_timestamp` | The point in time the vector describes. |
| `generated_at` | When the vector was computed. |
| `features` | The canonical payload, as JSON (JSONB on PostgreSQL). |
| `feature_hash` | SHA-256 of the canonical payload. |
| `source_event_count` | Size of the history behind the vector. |

* **Unique** on `(event_id, feature_version, as_of_timestamp)`.
* **Idempotent**: persisting the same vector again returns the stored row.
* **Immutable**: a recomputation with a different hash raises `SnapshotDriftError`.
  Nothing is overwritten.
* **Tamper-evident**: loading verifies the stored JSON against its hash.
* `fraud-ai features validate` recomputes every snapshot and reports integrity failures and
  drift.
* `model_predictions.feature_snapshot_reference` will point at these rows in Stage 3.

## 6. Training datasets and label availability

`fraud-ai dataset build` (and `fraud_ai.datasets.TrainingDatasetBuilder`) produces:

* `features.jsonl`: point-in-time vectors, one per example;
* `labels.jsonl`: labels with full provenance (label id, source, `labelled_at`, fraud
  type), joined to features by `event_id`;
* `excluded.jsonl`: refused examples and the reason each was refused;
* `manifest.json`: the feature version and fingerprint, the label policy, and counts.

The label availability policy (`label-policy-1`) applies these rules in order:

1. Only labels from allowed sources count.
2. A label timestamped before its own event is refused (`invalid_provenance`).
3. Labels with `labelled_at` after the `label_cutoff` do not exist yet. If only such
   labels exist, the example is refused (`label_not_yet_known`).
4. Any known FRAUD label makes the example positive.
5. Negatives require **maturity**: `event_time + maturity <= label_cutoff` (30 days by
   default), so late chargebacks have had time to arrive (`immature` otherwise).
6. Unlabelled mature events are negatives only with `--implicit-negatives`. Otherwise they
   are refused (`unlabelled`).

The event range must end at or before the label cutoff.

## 7. Privacy

* Features are numbers, booleans and coarse categories. They never contain an IP address,
  device identifier, postal address, email, phone number or payment data.
* Cross-account reuse (addresses, card fingerprints, devices, networks) is measured with
  the keyed hashes from Stage 1, so reuse is countable without revealing the value.
* Lifecycle events (email or phone change, MFA) carry no contact details at all. Their
  payload schema rejects extra fields.
* VPN, proxy, Tor and datacenter flags are evidence only. Nothing attempts to discover a
  user's origin behind them. The synthetic data includes long-term legitimate VPN users
  and legitimately shared carrier NAT, office and household networks, so models can learn
  that these are not fraud by themselves.

## 8. Future ML use

* **Logistic regression and neural networks** need an explicit encoding for each missing
  reason (indicator columns), scaling, and one-hot `network_type`, `event_kind` and
  `login_outcome`. Counts and ages are heavy-tailed; `log1p` is the natural transform.
* **Tree ensembles** (random forest, gradient boosting) can use the raw values with native
  missing-value handling.
* **Anomaly detection** (Stage 6) can use the same vectors without labels. Per-account
  baselines come from the transaction statistics.
* All preprocessing belongs to the *model* version, not the feature version. The stored
  vectors stay raw.

## 9. Example vector

The vector for an account-takeover purchase from the synthetic data, computed as of the
purchase. The chargeback that followed is invisible to it (`historical_chargebacks = 0`).
It shows a password reset 15 minutes earlier, a new device and shipping address,
`rapid_multi_change_count = 5`, and an amount 8.8 times the customer's median.

```json
{
  "as_of_timestamp": "2026-05-10T00:18:40+00:00",
  "event_id": "<uuid>",
  "event_kind": "transaction",
  "feature_hash": "1fa489dc50c39df163b51b6a2ff08d7f02cb7673efb7ad99e9c73cf7db47040b",
  "feature_version": "fraud-features-1.0.0",
  "missing": {
    "login_outcome": "not_applicable",
    "mfa_enabled": "unknown",
    "minutes_since_email_change": "not_observed",
    "minutes_since_mfa_change": "not_observed",
    "proxy_probability": "not_applicable",
    "time_since_address_last_used_hours": "not_observed",
    "vpn_probability": "not_applicable"
  },
  "values": {
    "account_age_days": 790.045602,
    "accounts_per_device": 0,
    "accounts_per_network": 0,
    "accounts_seen_from_network": 1,
    "accounts_seen_from_network_last_1h": 1,
    "accounts_seen_on_device": 1,
    "accounts_seen_on_device_last_24h": 1,
    "accounts_sharing_address": 0,
    "accounts_sharing_payment_fingerprint": 0,
    "address_age_days": 0.003472,
    "address_changed_recently": true,
    "address_seen_before": false,
    "address_verified": false,
    "addresses_per_account": 2,
    "asn_changed": false,
    "asn_changed_recently": true,
    "authenticated_user": true,
    "average_previous_transaction_amount": 7365.875,
    "country_changed": false,
    "country_changed_recently": true,
    "datacenter_detected": false,
    "device_age_days": 0.012963,
    "device_changed_recently": true,
    "device_failed_login_count": 4,
    "device_seen_before": true,
    "device_successful_login_count": 1,
    "device_trusted": false,
    "devices_per_account": 2,
    "distinct_devices_last_1h": 1,
    "distinct_networks_last_1h": 1,
    "email_verified": true,
    "event_kind": "transaction",
    "failed_logins_from_network": 4,
    "failed_logins_from_network_last_1h": 4,
    "failed_logins_last_15m": 0,
    "failed_logins_last_1h": 4,
    "failed_logins_last_5m": 0,
    "failed_logins_total": 6,
    "failed_orders_to_address": 0,
    "failed_transactions_on_payment_method": 0,
    "failed_transactions_total": 0,
    "historical_chargebacks": 0,
    "historical_confirmed_fraud_events": 0,
    "issuing_country_changed": true,
    "logins_last_15m": 1,
    "logins_last_1h": 5,
    "logins_last_24h": 5,
    "logins_last_30d": 28,
    "logins_last_5m": 0,
    "logins_last_7d": 10,
    "maximum_previous_transaction_amount": 14928,
    "median_previous_transaction_amount": 6166.5,
    "minutes_since_password_reset": 15.0,
    "minutes_since_phone_change": 5.5,
    "mobile_network": false,
    "network_first_seen_days": 0.012963,
    "network_seen_before": true,
    "network_type": "residential",
    "network_type_changed": false,
    "networks_per_account": 2,
    "new_address": true,
    "new_device": true,
    "new_payment_method": true,
    "orders_to_address": 0,
    "payment_method_age_days": 0.002083,
    "payment_method_changed_recently": true,
    "payment_method_seen_before": false,
    "payment_method_verified": false,
    "payment_methods_per_account": 2,
    "phone_verified": false,
    "previous_transactions_same_currency": 8,
    "proxy_detected": false,
    "rapid_multi_change_count": 5,
    "recent_email_change": false,
    "recent_mfa_removed": false,
    "recent_password_reset": true,
    "recent_phone_change": true,
    "shared_device_flag": false,
    "shared_network_flag": false,
    "successful_logins_from_network": 1,
    "successful_logins_last_1h": 1,
    "successful_logins_total": 22,
    "successful_orders_to_address": 0,
    "successful_transactions_on_payment_method": 0,
    "successful_transactions_total": 8,
    "time_since_device_last_seen_hours": 0.05,
    "time_since_previous_transaction_minutes": 21180.883333,
    "tor_detected": false,
    "transaction_amount_minor_units": 54448,
    "transaction_currency": "GBP",
    "transaction_value_last_24h": 0,
    "transaction_vs_average_ratio": 7.391926,
    "transaction_vs_median_ratio": 8.829644,
    "transactions_last_1h": 0,
    "transactions_last_24h": 0,
    "transactions_last_30d": 8,
    "transactions_last_5m": 0,
    "transactions_last_7d": 0,
    "unusually_high_transaction": true,
    "vpn_detected": false
  }
}
```

## 10. Catalogue

<!-- BEGIN GENERATED FEATURE CATALOGUE -->

Feature version `fraud-features-1.0.0` - 107 features - fingerprint `2b7b6d6afba0f83c`

### Context

| Feature | Type | Units | Nullable | Applies to | Description | Source | Missing when | Leakage notes |
|---|---|---|---|---|---|---|---|---|
| `event_kind` | categorical |  | no | both | Kind of scored event. *Why:* Lets one model consume login and transaction vectors in a shared space. | `events.event_type` |  | An attribute of the scored event itself, known at the moment it occurred. |
| `login_outcome` | categorical |  | yes | login | Outcome of the scored login event. *Why:* Failed and successful logins carry different risk. | `login_events.outcome` | not_applicable for transactions. | An attribute of the scored event itself, known at the moment it occurred. |
| `authenticated_user` | boolean |  | no | both | Whether the event is attributed to a known account. *Why:* Credential-stuffing traffic often targets unknown usernames. | `events.user_id` |  | An attribute of the scored event itself, known at the moment it occurred. |

### Account

| Feature | Type | Units | Nullable | Applies to | Description | Source | Missing when | Leakage notes |
|---|---|---|---|---|---|---|---|---|
| `account_age_days` | float | days | yes | both | Days between account creation and as_of. *Why:* Young accounts have little history; old accounts are takeover targets. | `users.account_created_at` | not_applicable for anonymous events (no resolved account). | Filtered to records with timestamp <= as_of_timestamp. |
| `email_verified` | boolean |  | yes | both | Email verified and not changed since the last verification (as of as_of). *Why:* An email change after verification is a classic takeover step. | `security_events.security_event_type`, `security_events.occurred_at` | unknown when no email lifecycle event exists; not_applicable for anonymous events (no resolved account). | Filtered to records with timestamp <= as_of_timestamp. |
| `phone_verified` | boolean |  | yes | both | Phone verified and not changed since the last verification (as of as_of). | `security_events.security_event_type`, `security_events.occurred_at` | unknown when no phone lifecycle event exists; not_applicable for anonymous events (no resolved account). | Filtered to records with timestamp <= as_of_timestamp. |
| `mfa_enabled` | boolean |  | yes | both | MFA enrolled at as_of (latest MFA event is enable). | `security_events.security_event_type`, `security_events.occurred_at` | unknown when no MFA event exists; not_applicable for anonymous events (no resolved account). | Filtered to records with timestamp <= as_of_timestamp. |
| `successful_logins_total` | integer | count | yes | both | Prior successful logins of the account. | `login_events.outcome`, `login_events.occurred_at` | not_applicable for anonymous events (no resolved account). | Only records with timestamp <= as_of_timestamp, excluding the scored event itself. |
| `failed_logins_total` | integer | count | yes | both | Prior failed logins of the account. | `login_events.outcome`, `login_events.occurred_at` | not_applicable for anonymous events (no resolved account). | Only records with timestamp <= as_of_timestamp, excluding the scored event itself. |
| `successful_transactions_total` | integer | count | yes | both | Prior transactions approved by as_of (decision time <= as_of). | `transactions.decision_outcome`, `transactions.decided_at` | not_applicable for anonymous events (no resolved account). | Uses the immutable decision_outcome and decided_at <= as_of; never the mutable transactions.status. |
| `failed_transactions_total` | integer | count | yes | both | Prior transactions declined by as_of (decision time <= as_of). | `transactions.decision_outcome`, `transactions.decided_at` | not_applicable for anonymous events (no resolved account). | As successful_transactions_total. |
| `historical_chargebacks` | integer | count | yes | both | Chargebacks on the account whose label became known by as_of. | `fraud_labels.label_source`, `fraud_labels.labelled_at` | not_applicable for anonymous events (no resolved account). | Label leakage guard: labelled_at <= as_of, and labels on the scored event/transaction itself are always excluded. |
| `historical_confirmed_fraud_events` | integer | count | yes | both | Non-chargeback fraud confirmations (analyst/customer) known by as_of. | `fraud_labels.label`, `fraud_labels.label_source`, `fraud_labels.labelled_at` | not_applicable for anonymous events (no resolved account). | As historical_chargebacks. |

### Device

| Feature | Type | Units | Nullable | Applies to | Description | Source | Missing when | Leakage notes |
|---|---|---|---|---|---|---|---|---|
| `device_age_days` | float | days | yes | both | Days since the device was first seen for this account (0 if first seen now). | `events.device_id`, `events.user_id`, `events.occurred_at` | not_observed when the event carries no device identifier. not_applicable for anonymous events (no resolved account). | Filtered to records with timestamp <= as_of_timestamp. |
| `device_seen_before` | boolean |  | yes | both | The account used this device before. | `events.device_id`, `events.user_id`, `events.occurred_at` | not_observed when the event carries no device identifier. not_applicable for anonymous events (no resolved account). | Only records with timestamp <= as_of_timestamp, excluding the scored event itself. |
| `device_trusted` | boolean |  | yes | both | The account completed an MFA login on this device before (application trust rule). | `login_events.device_id`, `login_events.mfa_used`, `login_events.outcome` | not_observed when the event carries no device identifier. not_applicable for anonymous events (no resolved account). | Derived from prior login rows; the mutable user_devices.is_trusted flag is never read. |
| `device_successful_login_count` | integer | count | yes | both | Prior successful logins on this device (any account). | `login_events.device_id`, `login_events.outcome` | not_observed when the event carries no device identifier. | Only records with timestamp <= as_of_timestamp, excluding the scored event itself. |
| `device_failed_login_count` | integer | count | yes | both | Prior failed logins on this device (any account). | `login_events.device_id`, `login_events.outcome` | not_observed when the event carries no device identifier. | Only records with timestamp <= as_of_timestamp, excluding the scored event itself. |
| `accounts_seen_on_device` | integer | count | yes | both | Distinct accounts with prior activity on this device (including this account). | `events.device_id`, `events.user_id` | not_observed when the event carries no device identifier. | Only records with timestamp <= as_of_timestamp, excluding the scored event itself. |
| `accounts_seen_on_device_last_24h` | integer | count | yes | both | Distinct accounts with activity on this device in the last 24 hours. *Why:* One automation client cycling through accounts. | `events.device_id`, `events.user_id`, `events.occurred_at` | not_observed when the event carries no device identifier. | Only records with timestamp <= as_of_timestamp, excluding the scored event itself. |
| `time_since_device_last_seen_hours` | float | hours | yes | both | Hours since the device's previous activity (any account). | `events.device_id`, `events.occurred_at` | not_observed when the device was never seen before; not_observed when the event carries no device identifier. | Only records with timestamp <= as_of_timestamp, excluding the scored event itself. |
| `new_device` | boolean |  | yes | both | Device first seen for this account within the last 24 hours (including now). | `events.device_id`, `events.user_id`, `events.occurred_at` | not_observed when the event carries no device identifier. not_applicable for anonymous events (no resolved account). | Filtered to records with timestamp <= as_of_timestamp. |

### Network

| Feature | Type | Units | Nullable | Applies to | Description | Source | Missing when | Leakage notes |
|---|---|---|---|---|---|---|---|---|
| `network_first_seen_days` | float | days | yes | both | Days since the network (IP) was first observed by the platform (0 if new). | `network_events.network_identity_id`, `network_events.observed_at` | not_observed when the event carries no network context. | Filtered to records with timestamp <= as_of_timestamp. |
| `network_seen_before` | boolean |  | yes | both | The network was observed before (any account). | `network_events.network_identity_id` | not_observed when the event carries no network context. | Only records with timestamp <= as_of_timestamp, excluding the scored event itself. |
| `network_type` | categorical |  | yes | both | Network type from intel at the time of the event. | `network_events.network_type` | unknown when intel did not classify the network; not_observed when the event carries no network context. | Taken from the network observation recorded with the scored event (the intel as it was then), never from the mutable network_identities row. |
| `vpn_detected` | boolean |  | yes | both | Intel flagged the network as a known VPN. *Why:* A risk signal only - many legitimate customers use VPNs. | `network_events.is_known_vpn` | unknown when intel gave no VPN verdict; not_observed when the event carries no network context. | Taken from the network observation recorded with the scored event (the intel as it was then), never from the mutable network_identities row. |
| `vpn_probability` | float | probability | yes | both | Intel confidence for a network flagged as VPN. | `network_events.proxy_confidence`, `network_events.is_known_vpn` | not_applicable when not flagged as VPN; unknown when the flag or confidence is absent; not_observed when the event carries no network context. | Taken from the network observation recorded with the scored event (the intel as it was then), never from the mutable network_identities row. |
| `proxy_detected` | boolean |  | yes | both | Intel flagged the network as a known proxy. | `network_events.is_known_proxy` | unknown when intel gave no proxy verdict; not_observed when the event carries no network context. | Taken from the network observation recorded with the scored event (the intel as it was then), never from the mutable network_identities row. |
| `proxy_probability` | float | probability | yes | both | Intel confidence for a network flagged as proxy. | `network_events.proxy_confidence`, `network_events.is_known_proxy` | not_applicable when not flagged as proxy; unknown when absent; not_observed when the event carries no network context. | Taken from the network observation recorded with the scored event (the intel as it was then), never from the mutable network_identities row. |
| `tor_detected` | boolean |  | yes | both | Intel flagged a Tor exit. | `network_events.is_tor` | unknown when absent; not_observed when the event carries no network context. | Taken from the network observation recorded with the scored event (the intel as it was then), never from the mutable network_identities row. |
| `datacenter_detected` | boolean |  | yes | both | Intel flagged a datacenter/hosting network. | `network_events.is_datacenter` | unknown when absent; not_observed when the event carries no network context. | Taken from the network observation recorded with the scored event (the intel as it was then), never from the mutable network_identities row. |
| `mobile_network` | boolean |  | yes | both | Intel flagged a mobile-carrier network. *Why:* Carrier NAT legitimately puts many customers on one IP. | `network_events.is_mobile_network` | unknown when absent (including observations recorded before revision 0002); not_observed when the event carries no network context. | Taken from the network observation recorded with the scored event (the intel as it was then), never from the mutable network_identities row. |
| `country_changed` | boolean |  | yes | both | Network country differs from the account's previous network observation. | `network_events.country`, `network_events.observed_at` | not_observed without a previous observation; unknown when either country is unknown; not_observed when the event carries no network context. not_applicable for anonymous events (no resolved account). | Only records with timestamp <= as_of_timestamp, excluding the scored event itself. |
| `asn_changed` | boolean |  | yes | both | ASN differs from the account's previous network observation. | `network_events.asn`, `network_events.observed_at` | as country_changed. | Only records with timestamp <= as_of_timestamp, excluding the scored event itself. |
| `network_type_changed` | boolean |  | yes | both | Network type differs from the account's previous network observation. | `network_events.network_type`, `network_events.observed_at` | as country_changed. | Only records with timestamp <= as_of_timestamp, excluding the scored event itself. |
| `accounts_seen_from_network` | integer | count | yes | both | Distinct accounts previously observed on this network. *Why:* High for shared infrastructure - offices, carrier NAT, hotels - which is not by itself suspicious. | `network_events.user_id`, `network_events.network_identity_id` | not_observed when the event carries no network context. | Only records with timestamp <= as_of_timestamp, excluding the scored event itself. |
| `accounts_seen_from_network_last_1h` | integer | count | yes | both | Distinct accounts observed on this network in the last hour. | `network_events.user_id`, `network_events.observed_at` | not_observed when the event carries no network context. | Only records with timestamp <= as_of_timestamp, excluding the scored event itself. |
| `successful_logins_from_network` | integer | count | yes | both | Prior successful logins from this network (any account). | `login_events.network_identity_id`, `login_events.outcome` | not_observed when the event carries no network context. | Only records with timestamp <= as_of_timestamp, excluding the scored event itself. |
| `failed_logins_from_network` | integer | count | yes | both | Prior failed logins from this network (any account, including unknown usernames). | `login_events.network_identity_id`, `login_events.outcome` | not_observed when the event carries no network context. | Only records with timestamp <= as_of_timestamp, excluding the scored event itself. |
| `failed_logins_from_network_last_1h` | integer | count | yes | both | Failed logins from this network in the last hour. | `login_events.network_identity_id`, `login_events.occurred_at` | not_observed when the event carries no network context. | Only records with timestamp <= as_of_timestamp, excluding the scored event itself. |

### Address

| Feature | Type | Units | Nullable | Applies to | Description | Source | Missing when | Leakage notes |
|---|---|---|---|---|---|---|---|---|
| `address_age_days` | float | days | yes | transaction | Days since the shipping address was added. | `addresses.added_at` | not_applicable for logins and for transactions without a shipping address. | Filtered to records with timestamp <= as_of_timestamp. |
| `address_seen_before` | boolean |  | yes | transaction | A previous transaction was shipped to this address. | `transactions.shipping_address_id` | not_applicable for logins and for transactions without a shipping address. | Only records with timestamp <= as_of_timestamp, excluding the scored event itself. |
| `address_verified` | boolean |  | yes | transaction | Address verified by as_of. | `addresses.verified_at` | not_applicable for logins and for transactions without a shipping address. | verified_at <= as_of. |
| `orders_to_address` | integer | count | yes | transaction | Prior transactions shipped to this address. | `transactions.shipping_address_id` | not_applicable for logins and for transactions without a shipping address. | Only records with timestamp <= as_of_timestamp, excluding the scored event itself. |
| `successful_orders_to_address` | integer | count | yes | transaction | Prior transactions to this address approved by as_of. | `transactions.decision_outcome`, `transactions.decided_at` | not_applicable for logins and for transactions without a shipping address. | Only records with timestamp <= as_of_timestamp, excluding the scored event itself. |
| `failed_orders_to_address` | integer | count | yes | transaction | Prior transactions to this address declined by as_of. | `transactions.decision_outcome`, `transactions.decided_at` | not_applicable for logins and for transactions without a shipping address. | Only records with timestamp <= as_of_timestamp, excluding the scored event itself. |
| `new_address` | boolean |  | yes | transaction | Address added within the last 24 hours. *Why:* Common in takeovers - but also in house moves, so never decisive alone. | `addresses.added_at` | not_applicable for logins and for transactions without a shipping address. | Filtered to records with timestamp <= as_of_timestamp. |
| `time_since_address_last_used_hours` | float | hours | yes | transaction | Hours since the previous transaction to this address. | `transactions.shipping_address_id`, `transactions.occurred_at` | not_observed when the address was never used before; not_applicable for logins and for transactions without a shipping address. | Only records with timestamp <= as_of_timestamp, excluding the scored event itself. |
| `accounts_sharing_address` | integer | count | yes | transaction | Other accounts that registered the same address (keyed hash) by as_of. *Why:* Drop addresses reused across accounts; households also share addresses. | `addresses.address_hash`, `addresses.added_at` | not_applicable for logins and for transactions without a shipping address. | Only records with timestamp <= as_of_timestamp, excluding the scored event itself. |

### Payment

| Feature | Type | Units | Nullable | Applies to | Description | Source | Missing when | Leakage notes |
|---|---|---|---|---|---|---|---|---|
| `payment_method_age_days` | float | days | yes | transaction | Days since the payment method was added. | `payment_methods.added_at` | not_applicable for logins and for transactions without a payment method. | Filtered to records with timestamp <= as_of_timestamp. |
| `payment_method_seen_before` | boolean |  | yes | transaction | The payment method was used in a previous transaction. | `transactions.payment_method_id` | not_applicable for logins and for transactions without a payment method. | Only records with timestamp <= as_of_timestamp, excluding the scored event itself. |
| `payment_method_verified` | boolean |  | yes | transaction | Payment method verified by as_of. | `payment_methods.verified_at` | not_applicable for logins and for transactions without a payment method. | verified_at <= as_of. |
| `successful_transactions_on_payment_method` | integer | count | yes | transaction | Prior transactions on this payment method approved by as_of. | `transactions.decision_outcome`, `transactions.decided_at` | not_applicable for logins and for transactions without a payment method. | Only records with timestamp <= as_of_timestamp, excluding the scored event itself. |
| `failed_transactions_on_payment_method` | integer | count | yes | transaction | Prior transactions on this payment method declined by as_of. | `transactions.decision_outcome`, `transactions.decided_at` | not_applicable for logins and for transactions without a payment method. | Only records with timestamp <= as_of_timestamp, excluding the scored event itself. |
| `issuing_country_changed` | boolean |  | yes | transaction | Issuer country differs from that of the account's previous transaction. | `payment_methods.issuer_country`, `transactions.occurred_at` | not_observed without a previous transaction with a payment method; unknown when an issuer country is unknown; not_applicable for logins and for transactions without a payment method. | Only records with timestamp <= as_of_timestamp, excluding the scored event itself. |
| `new_payment_method` | boolean |  | yes | transaction | Payment method added within the last 24 hours. | `payment_methods.added_at` | not_applicable for logins and for transactions without a payment method. | Filtered to records with timestamp <= as_of_timestamp. |
| `accounts_sharing_payment_fingerprint` | integer | count | yes | transaction | Other accounts holding a payment method with the same vault fingerprint by as_of. | `payment_methods.fingerprint_hash`, `payment_methods.added_at` | unknown when the vault supplied no fingerprint; not_applicable for logins and for transactions without a payment method. | Only records with timestamp <= as_of_timestamp, excluding the scored event itself. |

### Transaction

| Feature | Type | Units | Nullable | Applies to | Description | Source | Missing when | Leakage notes |
|---|---|---|---|---|---|---|---|---|
| `transaction_amount_minor_units` | integer | minor currency units | yes | transaction | Amount of the scored transaction in minor units. | `transactions.amount_minor` | not_applicable for login events. | An attribute of the scored event itself, known at the moment it occurred. |
| `transaction_currency` | categorical |  | yes | transaction | ISO 4217 currency of the transaction. | `transactions.currency` | not_applicable for login events. | An attribute of the scored event itself, known at the moment it occurred. |
| `previous_transactions_same_currency` | integer | count | yes | transaction | Number of prior transactions in the same currency (the history behind the stats). | `transactions.currency` | not_applicable for login events. | Only records with timestamp <= as_of_timestamp, excluding the scored event itself. |
| `average_previous_transaction_amount` | float | minor currency units | yes | transaction | Mean amount of prior same-currency transactions. | `transactions.amount_minor` | not_observed when there is no previous transaction in the same currency; not_applicable for login events. | Only records with timestamp <= as_of_timestamp, excluding the scored event itself. |
| `median_previous_transaction_amount` | float | minor currency units | yes | transaction | Median amount of prior same-currency transactions. | `transactions.amount_minor` | not_observed when there is no previous transaction in the same currency; not_applicable for login events. | Only records with timestamp <= as_of_timestamp, excluding the scored event itself. |
| `maximum_previous_transaction_amount` | integer | minor currency units | yes | transaction | Largest prior same-currency transaction. | `transactions.amount_minor` | not_observed when there is no previous transaction in the same currency; not_applicable for login events. | Only records with timestamp <= as_of_timestamp, excluding the scored event itself. |
| `transaction_vs_average_ratio` | float | ratio | yes | transaction | Amount divided by the previous average. | `transactions.amount_minor` | not_observed when there is no previous transaction in the same currency; not_applicable for login events. not_applicable when the average is zero (division by zero). | Only records with timestamp <= as_of_timestamp, excluding the scored event itself. |
| `transaction_vs_median_ratio` | float | ratio | yes | transaction | Amount divided by the previous median. | `transactions.amount_minor` | not_observed when there is no previous transaction in the same currency; not_applicable for login events. not_applicable when the median is zero. | Only records with timestamp <= as_of_timestamp, excluding the scored event itself. |
| `transactions_last_5m` | integer | count | yes | transaction | Prior transactions of the account in the last 5m (any currency). | `transactions.occurred_at` | not_applicable for login events. | Only records with timestamp <= as_of_timestamp, excluding the scored event itself. |
| `transactions_last_1h` | integer | count | yes | transaction | Prior transactions of the account in the last 1h (any currency). | `transactions.occurred_at` | not_applicable for login events. | Only records with timestamp <= as_of_timestamp, excluding the scored event itself. |
| `transactions_last_24h` | integer | count | yes | transaction | Prior transactions of the account in the last 24h (any currency). | `transactions.occurred_at` | not_applicable for login events. | Only records with timestamp <= as_of_timestamp, excluding the scored event itself. |
| `transactions_last_7d` | integer | count | yes | transaction | Prior transactions of the account in the last 7d (any currency). | `transactions.occurred_at` | not_applicable for login events. | Only records with timestamp <= as_of_timestamp, excluding the scored event itself. |
| `transactions_last_30d` | integer | count | yes | transaction | Prior transactions of the account in the last 30d (any currency). | `transactions.occurred_at` | not_applicable for login events. | Only records with timestamp <= as_of_timestamp, excluding the scored event itself. |
| `transaction_value_last_24h` | integer | minor currency units | yes | transaction | Sum of prior same-currency amounts in the last 24 hours (excluding this one). | `transactions.amount_minor`, `transactions.occurred_at` | not_applicable for login events. | Only records with timestamp <= as_of_timestamp, excluding the scored event itself. |
| `time_since_previous_transaction_minutes` | float | minutes | yes | transaction | Minutes since the account's previous transaction. | `transactions.occurred_at` | not_observed without a previous transaction; not_applicable for login events. | Only records with timestamp <= as_of_timestamp, excluding the scored event itself. |
| `unusually_high_transaction` | boolean |  | yes | transaction | Amount exceeds the account's previous same-currency maximum (descriptive, not a rule). | `transactions.amount_minor` | not_observed with fewer than 3 prior same-currency transactions; not_applicable for login events. | Only records with timestamp <= as_of_timestamp, excluding the scored event itself. |

### Login Velocity

| Feature | Type | Units | Nullable | Applies to | Description | Source | Missing when | Leakage notes |
|---|---|---|---|---|---|---|---|---|
| `logins_last_5m` | integer | count | yes | both | Prior login events of the account (attempts, successes and failures) in the last 5m. | `login_events.user_id`, `login_events.occurred_at` | not_applicable for anonymous events (no resolved account). | Only records with timestamp <= as_of_timestamp, excluding the scored event itself. |
| `logins_last_15m` | integer | count | yes | both | Prior login events of the account (attempts, successes and failures) in the last 15m. | `login_events.user_id`, `login_events.occurred_at` | not_applicable for anonymous events (no resolved account). | Only records with timestamp <= as_of_timestamp, excluding the scored event itself. |
| `logins_last_1h` | integer | count | yes | both | Prior login events of the account (attempts, successes and failures) in the last 1h. | `login_events.user_id`, `login_events.occurred_at` | not_applicable for anonymous events (no resolved account). | Only records with timestamp <= as_of_timestamp, excluding the scored event itself. |
| `logins_last_24h` | integer | count | yes | both | Prior login events of the account (attempts, successes and failures) in the last 24h. | `login_events.user_id`, `login_events.occurred_at` | not_applicable for anonymous events (no resolved account). | Only records with timestamp <= as_of_timestamp, excluding the scored event itself. |
| `logins_last_7d` | integer | count | yes | both | Prior login events of the account (attempts, successes and failures) in the last 7d. | `login_events.user_id`, `login_events.occurred_at` | not_applicable for anonymous events (no resolved account). | Only records with timestamp <= as_of_timestamp, excluding the scored event itself. |
| `logins_last_30d` | integer | count | yes | both | Prior login events of the account (attempts, successes and failures) in the last 30d. | `login_events.user_id`, `login_events.occurred_at` | not_applicable for anonymous events (no resolved account). | Only records with timestamp <= as_of_timestamp, excluding the scored event itself. |
| `failed_logins_last_5m` | integer | count | yes | both | Prior failed logins of the account in the last 5m. | `login_events.outcome`, `login_events.occurred_at` | not_applicable for anonymous events (no resolved account). | Only records with timestamp <= as_of_timestamp, excluding the scored event itself. |
| `failed_logins_last_15m` | integer | count | yes | both | Prior failed logins of the account in the last 15m. | `login_events.outcome`, `login_events.occurred_at` | not_applicable for anonymous events (no resolved account). | Only records with timestamp <= as_of_timestamp, excluding the scored event itself. |
| `failed_logins_last_1h` | integer | count | yes | both | Prior failed logins of the account in the last 1h. | `login_events.outcome`, `login_events.occurred_at` | not_applicable for anonymous events (no resolved account). | Only records with timestamp <= as_of_timestamp, excluding the scored event itself. |
| `successful_logins_last_1h` | integer | count | yes | both | Prior successful logins of the account in the last hour. | `login_events.outcome`, `login_events.occurred_at` | not_applicable for anonymous events (no resolved account). | Only records with timestamp <= as_of_timestamp, excluding the scored event itself. |
| `distinct_networks_last_1h` | integer | count | yes | both | Distinct networks used by the account's logins in the last hour. | `login_events.network_identity_id` | not_applicable for anonymous events (no resolved account). | Only records with timestamp <= as_of_timestamp, excluding the scored event itself. |
| `distinct_devices_last_1h` | integer | count | yes | both | Distinct devices used by the account's logins in the last hour. | `login_events.device_id` | not_applicable for anonymous events (no resolved account). | Only records with timestamp <= as_of_timestamp, excluding the scored event itself. |

### Security

| Feature | Type | Units | Nullable | Applies to | Description | Source | Missing when | Leakage notes |
|---|---|---|---|---|---|---|---|---|
| `minutes_since_password_reset` | float | minutes | yes | both | Minutes since the latest password reset. | `security_events.security_event_type`, `security_events.occurred_at` | not_observed when none happened; not_applicable for anonymous events (no resolved account). | Filtered to records with timestamp <= as_of_timestamp. |
| `minutes_since_email_change` | float | minutes | yes | both | Minutes since the latest email change. | `security_events.security_event_type`, `security_events.occurred_at` | not_observed when none happened; not_applicable for anonymous events (no resolved account). | Filtered to records with timestamp <= as_of_timestamp. |
| `minutes_since_phone_change` | float | minutes | yes | both | Minutes since the latest phone change. | `security_events.security_event_type`, `security_events.occurred_at` | not_observed when none happened; not_applicable for anonymous events (no resolved account). | Filtered to records with timestamp <= as_of_timestamp. |
| `minutes_since_mfa_change` | float | minutes | yes | both | Minutes since the latest MFA enrol/removal. | `security_events.security_event_type`, `security_events.occurred_at` | not_observed when none happened; not_applicable for anonymous events (no resolved account). | Filtered to records with timestamp <= as_of_timestamp. |
| `recent_password_reset` | boolean |  | yes | both | A password reset in the last 24 hours. | `security_events.security_event_type`, `security_events.occurred_at` | not_applicable for anonymous events (no resolved account). | Filtered to records with timestamp <= as_of_timestamp. |
| `recent_email_change` | boolean |  | yes | both | A email change in the last 24 hours. | `security_events.security_event_type`, `security_events.occurred_at` | not_applicable for anonymous events (no resolved account). | Filtered to records with timestamp <= as_of_timestamp. |
| `recent_phone_change` | boolean |  | yes | both | A phone change in the last 24 hours. | `security_events.security_event_type`, `security_events.occurred_at` | not_applicable for anonymous events (no resolved account). | Filtered to records with timestamp <= as_of_timestamp. |
| `recent_mfa_removed` | boolean |  | yes | both | A MFA removal in the last 24 hours. | `security_events.security_event_type`, `security_events.occurred_at` | not_applicable for anonymous events (no resolved account). | Filtered to records with timestamp <= as_of_timestamp. |

### Behavioural

| Feature | Type | Units | Nullable | Applies to | Description | Source | Missing when | Leakage notes |
|---|---|---|---|---|---|---|---|---|
| `country_changed_recently` | boolean |  | yes | both | The account's network country changed within the last 24 hours. | `network_events.country`, `network_events.observed_at` | not_observed without network observations; unknown when all countries are unknown; not_applicable for anonymous events (no resolved account). | Filtered to records with timestamp <= as_of_timestamp. |
| `asn_changed_recently` | boolean |  | yes | both | The account's network ASN changed within the last 24 hours. | `network_events.asn`, `network_events.observed_at` | as country_changed_recently. | Filtered to records with timestamp <= as_of_timestamp. |
| `device_changed_recently` | boolean |  | yes | both | A device first seen in the last 24 hours on an account with an older device. | `events.device_id`, `events.occurred_at` | not_applicable for anonymous events (no resolved account). | Filtered to records with timestamp <= as_of_timestamp. |
| `address_changed_recently` | boolean |  | yes | both | An address added in the last 24 hours on an account with an older address. | `addresses.added_at` | not_applicable for anonymous events (no resolved account). | Filtered to records with timestamp <= as_of_timestamp. |
| `payment_method_changed_recently` | boolean |  | yes | both | A payment method added in the last 24 hours on an account with an older one. | `payment_methods.added_at` | not_applicable for anonymous events (no resolved account). | Filtered to records with timestamp <= as_of_timestamp. |
| `rapid_multi_change_count` | integer | count | yes | both | How many of {password reset, email change, phone change, MFA change, device change, address change, payment-method change} happened in the last 24 hours. *Why:* Takeovers chain several changes quickly; onboarding is excluded because the change features require pre-existing devices/addresses/payment methods. | `security_events.occurred_at`, `events.occurred_at`, `addresses.added_at`, `payment_methods.added_at` | not_applicable for anonymous events (no resolved account). | Filtered to records with timestamp <= as_of_timestamp. |

### Cross Entity

| Feature | Type | Units | Nullable | Applies to | Description | Source | Missing when | Leakage notes |
|---|---|---|---|---|---|---|---|---|
| `accounts_per_device` | integer | count | yes | both | Other accounts seen on this device by as_of. | `events.device_id`, `events.user_id` | not_observed when the event carries no device identifier. | Filtered to records with timestamp <= as_of_timestamp. |
| `accounts_per_network` | integer | count | yes | both | Other accounts seen on this network by as_of. | `network_events.user_id` | not_observed when the event carries no network context. | Filtered to records with timestamp <= as_of_timestamp. |
| `addresses_per_account` | integer | count | yes | both | Addresses registered by as_of. | `addresses.added_at` | not_applicable for anonymous events (no resolved account). | Filtered to records with timestamp <= as_of_timestamp. |
| `devices_per_account` | integer | count | yes | both | Distinct devices used by as_of. | `events.device_id` | not_applicable for anonymous events (no resolved account). | Filtered to records with timestamp <= as_of_timestamp. |
| `payment_methods_per_account` | integer | count | yes | both | Payment methods registered by as_of. | `payment_methods.added_at` | not_applicable for anonymous events (no resolved account). | Filtered to records with timestamp <= as_of_timestamp. |
| `networks_per_account` | integer | count | yes | both | Distinct networks observed by as_of. | `network_events.network_identity_id` | not_applicable for anonymous events (no resolved account). | Filtered to records with timestamp <= as_of_timestamp. |
| `shared_device_flag` | boolean |  | yes | both | accounts_per_device >= 1. *Why:* Households share devices; a descriptive flag, not a verdict. | `events.device_id` | not_observed when the event carries no device identifier. | Filtered to records with timestamp <= as_of_timestamp. |
| `shared_network_flag` | boolean |  | yes | both | accounts_per_network >= 1. *Why:* Carrier NAT, offices, schools, hotels and households share networks legitimately; a descriptive flag, not a verdict. | `network_events.user_id` | not_observed when the event carries no network context. | Filtered to records with timestamp <= as_of_timestamp. |

<!-- END GENERATED FEATURE CATALOGUE -->
