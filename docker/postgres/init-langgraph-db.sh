#!/bin/bash
# Create the langgraph database if the langgraph profile is active.
# This script runs as part of Postgres docker-entrypoint-initdb.d on first start only.
set -e

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
    SELECT 'CREATE DATABASE langgraph OWNER yashigani_app'
    WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'langgraph')\gexec
EOSQL
