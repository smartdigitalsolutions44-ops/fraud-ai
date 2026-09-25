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


class SignalSource(StrEnum):
    RULE = "rule"
    MODEL = "model"
    NETWORK_INTEL = "network_intel"
    ANALYST = "analyst"
    FEATURE = "feature"


class Decision(StrEnum):
    """Final risk-engine outcomes, ordered from least to most restrictive."""

    ALLOW = "ALLOW"
    STEP_UP_AUTHENTICATION = "STEP_UP_AUTHENTICATION"
    MANUAL_REVIEW = "MANUAL_REVIEW"
    BLOCK = "BLOCK"

    @property
    def severity(self) -> int:
        return _DECISION_ORDER.index(self)


_DECISION_ORDER = [
    Decision.ALLOW,
    Decision.STEP_UP_AUTHENTICATION,
    Decision.MANUAL_REVIEW,
    Decision.BLOCK,
]
