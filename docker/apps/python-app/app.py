#!/usr/bin/env python3
import os
import time
import psycopg2
from psycopg2 import sql

def main():
    conn_params = {
        'host': os.getenv('PGHOST', 'postgres'),
        'port': os.getenv('PGPORT', '5432'),
        'user': os.getenv('PGUSER', 'testuser'),
        'password': os.getenv('PGPASSWORD', 'testpass'),
        'database': os.getenv('PGDATABASE', 'testdb')
    }
    
    print("Connecting to PostgreSQL...")
    conn = psycopg2.connect(**conn_params)
    cursor = conn.cursor()
    print("Connected successfully")
    
    queries = [
        "SELECT version()",
        "SELECT current_date",
        "SELECT pg_database_size(current_database())",
        "SELECT md5(random()::text)"
    ]
    
    for i, query in enumerate(queries, 1):
        try:
            cursor.execute(query)
            result = cursor.fetchone()
            print(f"Query {i} result: {result[0]}")
        except Exception as e:
            print(f"Query {i} failed: {e}")
        time.sleep(2)
    
    cursor.close()
    conn.close()
    print("Completed all queries")

if __name__ == "__main__":
    main()