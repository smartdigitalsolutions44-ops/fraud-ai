#!/usr/bin/env bash
# Create a local PostgreSQL role and databases for development/testing.
# Usage: sudo -u postgres scripts/dev_postgres.sh [password]
set -euo pipefail
PASSWORD="${1:?usage: dev_postgres.sh <password>}"
psql -v ON_ERROR_STOP=1 <<SQL
CREATE ROLE fraud_ai LOGIN PASSWORD '${PASSWORD}';
CREATE DATABASE fraud_ai OWNER fraud_ai;
CREATE DATABASE fraud_ai_test OWNER fraud_ai;
SQL
echo "DATABASE_URL=postgresql+psycopg://fraud_ai:<password>@localhost:5432/fraud_ai"
echo "TEST_POSTGRES_URL=postgresql+psycopg://fraud_ai:<password>@localhost:5432/fraud_ai_test"
