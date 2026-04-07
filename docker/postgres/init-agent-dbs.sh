#!/bin/bash
# Create databases for agent bundles that need Postgres persistence.
# This script runs as part of Postgres docker-entrypoint-initdb.d on first start only.
set -e

# Letta requires its own database with pgvector extension
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
    SELECT 'CREATE DATABASE letta OWNER yashigani_app'
    WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'letta')\gexec
EOSQL

# Enable pgvector extension in the letta database
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "letta" <<-EOSQL
    CREATE EXTENSION IF NOT EXISTS vector;
EOSQL
