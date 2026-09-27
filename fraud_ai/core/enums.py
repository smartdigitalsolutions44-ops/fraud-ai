"""Enumerations shared by the event model and the database schema.

Values are persisted as strings (VARCHAR + CHECK constraint) so that adding a value is a
simple, reviewable migration on both PostgreSQL and SQLite.
"""

from enum import StrEnum


class EventType(StrEnum):
    ACCOUNT_CREATED = "ACCOUNT_CREATED"
    LOGIN_ATTEMPT = "LOGIN_ATTEMPT"
    LOGIN_SUCCESS = "LOGIN_SUCCESS"
    LOGIN_FAILURE = "LOGIN_FAILURE"
    PASSWORD_RESET = "PASSWORD_RESET"
    NEW_DEVICE = "NEW_DEVICE"
    ADDRESS_ADDED = "ADDRESS_ADDED"
    ADDRESS_CHANGED = "ADDRESS_CHANGED"
    PAYMENT_METHOD_ADDED = "PAYMENT_METHOD_ADDED"
    TRANSACTION_CREATED = "TRANSACTION_CREATED"
    TRANSACTION_APPROVED = "TRANSACTION_APPROVED"
    TRANSACTION_DECLINED = "TRANSACTION_DECLINED"
    CHARGEBACK = "CHARGEBACK"
    FRAUD_CONFIRMED = "FRAUD_CONFIRMED"
    # Added in migration 0002: account-lifecycle and verification events. They carry no
    # contact details - only the fact and time of the change/verification.
    EMAIL_VERIFIED = "EMAIL_VERIFIED"
    EMAIL_CHANGED = "EMAIL_CHANGED"
    PHONE_VERIFIED = "PHONE_VERIFIED"
    PHONE_CHANGED = "PHONE_CHANGED"
    MFA_ENABLED = "MFA_ENABLED"
    MFA_DISABLED = "MFA_DISABLED"
    ADDRESS_VERIFIED = "ADDRESS_VERIFIED"
    PAYMENT_METHOD_VERIFIED = "PAYMENT_METHOD_VERIFIED"


class EventSource(StrEnum):
    WEB = "web"
    MOBILE_APP = "mobile_app"
    API = "api"
    BACKOFFICE = "backoffice"
    BATCH_IMPORT = "batch_import"
    SYNTHETIC = "synthetic"


class NetworkType(StrEnum):
    RESIDENTIAL = "residential"
    MOBILE = "mobile"
    BUSINESS = "business"
    DATACENTER = "datacenter"
    EDUCATION = "education"
    UNKNOWN = "unknown"


class DeviceType(StrEnum):
    MOBILE = "mobile"
    TABLET = "tablet"
    DESKTOP = "desktop"
    OTHER = "other"
    UNKNOWN = "unknown"


class AuthMethod(StrEnum):
    PASSWORD = "password"
    PASSKEY = "passkey"
    SSO = "sso"
    MAGIC_LINK = "magic_link"
    SESSION_REFRESH = "session_refresh"


class LoginOutcome(StrEnum):
    ATTEMPT = "ATTEMPT"
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"


class UserStatus(StrEnum):
    ACTIVE = "active"
    LOCKED = "locked"
    CLOSED = "closed"


class AddressType(StrEnum):
    HOME = "home"
    BILLING = "billing"
    SHIPPING = "shipping"


class PaymentMethodType(StrEnum):
    CARD = "card"
    BANK_ACCOUNT = "bank_account"
    WALLET = "wallet"


class CardFunding(StrEnum):
    CREDIT = "credit"
    DEBIT = "debit"
    PREPAID = "prepaid"
    UNKNOWN = "unknown"


class TransactionStatus(StrEnum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    DECLINED = "DECLINED"
    CHARGEBACK = "CHARGEBACK"


class TransactionChannel(StrEnum):
    WEB = "web"
    MOBILE_APP = "mobile_app"
    API = "api"


class LabelValue(StrEnum):
    FRAUD = "FRAUD"
    LEGITIMATE = "LEGITIMATE"


class LabelSource(StrEnum):
    CHARGEBACK = "chargeback"
    ANALYST = "analyst"
    CUSTOMER_REPORT = "customer_report"
    SYNTHETIC_GROUND_TRUTH = "synthetic_ground_truth"


class FraudType(StrEnum):
    ACCOUNT_TAKEOVER = "account_takeover"
    CREDENTIAL_STUFFING = "credential_stuffing"
    STOLEN_PAYMENT_METHOD = "stolen_payment_method"
    FRIENDLY_FRAUD = "friendly_fraud"
    OTHER = "other"


class SecurityEventType(StrEnum):
    PASSWORD_RESET = "PASSWORD_RESET"
    NEW_DEVICE = "NEW_DEVICE"
    ADDRESS_CHANGED = "ADDRESS_CHANGED"
    PAYMENT_METHOD_ADDED = "PAYMENT_METHOD_ADDED"
    EMAIL_VERIFIED = "EMAIL_VERIFIED"
    EMAIL_CHANGED = "EMAIL_CHANGED"
    PHONE_VERIFIED = "PHONE_VERIFIED"
    PHONE_CHANGED = "PHONE_CHANGED"
    MFA_ENABLED = "MFA_ENABLED"
    MFA_DISABLED = "MFA_DISABLED"


class TransactionDecision(StrEnum):
    """Immutable outcome of the authorisation decision (unlike ``status``, which a later
    chargeback overwrites)."""

    APPROVED = "APPROVED"
    DECLINED = "DECLINED"


class SignalSource(StrEnum):
    RULE = "rule"
    MODEL = "model"
    NETWORK_INTEL = "network_intel"
    ANALYST = "analyst"
    FEATURE = "feature"


class Decision(StrEnum):
    """Internal risk-policy outcomes, ordered from least to most restrictive.

    These are *policy outputs*, not actions executed anywhere: no payment system is called.
    There is deliberately no permanent ban. ``TEMPORARY_BLOCK`` always expires and always
    goes to manual review.
    """

    ALLOW = "ALLOW"
    ALLOW_WITH_MONITORING = "ALLOW_WITH_MONITORING"
    STEP_UP_AUTHENTICATION = "STEP_UP_AUTHENTICATION"
    MANUAL_REVIEW = "MANUAL_REVIEW"
    TEMPORARY_BLOCK = "TEMPORARY_BLOCK"

    @property
    def severity(self) -> int:
        return _DECISION_ORDER.index(self)


_DECISION_ORDER = [
    Decision.ALLOW,
    Decision.ALLOW_WITH_MONITORING,
    Decision.STEP_UP_AUTHENTICATION,
    Decision.MANUAL_REVIEW,
    Decision.TEMPORARY_BLOCK,
]


class RuleSeverity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ReviewStatus(StrEnum):
    OPEN = "open"
    NEEDS_MORE_INFORMATION = "needs_more_information"
    RESOLVED = "resolved"


class ReviewResolution(StrEnum):
    LEGITIMATE = "legitimate"
    FRAUD = "fraud"
    NEEDS_MORE_INFORMATION = "needs_more_information"
