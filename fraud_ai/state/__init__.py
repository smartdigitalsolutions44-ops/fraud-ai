"""Shared, short-lived coordination state (Stage 10): rate limits and replay claims.

Durable records (assessments, attempts, audit events, idempotency records) stay in the
database. Only ephemeral, expiring coordination state lives here.
"""
