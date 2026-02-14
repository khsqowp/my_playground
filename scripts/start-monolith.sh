#!/bin/bash
set -e

# DB 초기화 및 시작
if [ ! -d "/var/lib/postgresql/data/base" ]; then
    echo "Initializing database..."
    chown -R postgres:postgres /var/lib/postgresql/data
    su - postgres -c "/usr/lib/postgresql/13/bin/initdb -D /var/lib/postgresql/data"
    
    echo "Starting PostgreSQL..."
    su - postgres -c "/usr/lib/postgresql/13/bin/pg_ctl -D /var/lib/postgresql/data -l /var/lib/postgresql/data/logfile start"
    
    echo "Waiting for PostgreSQL to start..."
    sleep 5
    
    echo "Creating User/DB..."
    su - postgres -c "psql -c \"CREATE USER postgres WITH PASSWORD 'postgres';\"" || true
    su - postgres -c "psql -c \"CREATE DATABASE \\\"88motorcycle\\\";\"" || true
    su - postgres -c "psql -c \"GRANT ALL PRIVILEGES ON DATABASE \\\"88motorcycle\\\" TO postgres;\""
    # su - postgres -c "psql -d 88motorcycle -c \"CREATE EXTENSION IF NOT EXISTS vector;\"" # pgvector not supported in standard package yet
else
    echo "Starting PostgreSQL (Existing Data)..."
    chown -R postgres:postgres /var/lib/postgresql/data
    chmod 700 /var/lib/postgresql/data
    su - postgres -c "/usr/lib/postgresql/13/bin/pg_ctl -D /var/lib/postgresql/data -l /var/lib/postgresql/data/logfile start"
    echo "Waiting for PostgreSQL to start..."
    sleep 5
fi

# Prisma Migration & Seed
echo "Running Prisma Migrations..."
npx prisma db push --accept-data-loss

echo "Seeding Database..."
npx prisma db seed

# 앱 시작
echo "Starting Next.js..."
exec "$@"
