import sqlite3
import json
import time


class Cache:
    def __init__(self, path, ttl_seconds=86400):
        self.ttl_seconds = ttl_seconds
        self.conn = sqlite3.connect(path)

        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS cache (
                provider TEXT NOT NULL,
                ioc TEXT NOT NULL,
                data TEXT NOT NULL,
                created_at REAL NOT NULL,
                PRIMARY KEY (provider, ioc)
            )
        """)

        self.conn.commit()


    def get(self, provider, ioc):
        cut = time.time() - self.ttl_seconds

        row = self.conn.execute("""
                SELECT data FROM cache
                WHERE provider = ?
                    AND ioc = ?
                    AND created_at > ?
        """, (provider, ioc, cut)).fetchone()

        if row:
            return json.loads(row[0])
        else:
            return None


    def set(self, provider, ioc, data):
        json_data = json.dumps(data)
        now = time.time()

        self.conn.execute("""
            INSERT OR REPLACE INTO cache (
                provider, ioc, data, created_at
            ) VALUES (?, ?, ?, ?)
        """, (provider, ioc, json_data, now))

        self.conn.commit()

    def close(self):
        self.conn.close()