# db.py
import mariadb

DB_CONFIG = {
    "user": "saeuser",
    "password": "sae123",
    "host": "127.0.0.1",
    "port": 3306,
    "database": "sae302"
}

class Database:

    def _get_conn(self):
        return mariadb.connect(**DB_CONFIG)

    # -------- CLIENT --------
    def log_message(self, source, destination, route, payload):
        conn = self._get_conn()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO messages (source, destination, route, payload) VALUES (?, ?, ?, ?)",
            (source, destination, route, payload)
        )
        conn.commit()
        conn.close()

    # -------- ROUTEUR --------
    def log_router_event(self, router_port, next_port, action):
        conn = self._get_conn()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO router_logs (router_port, next_port, action) VALUES (?, ?, ?)",
            (router_port, next_port, action)
        )
        conn.commit()
        conn.close()

    # -------- MASTER --------
    def log_master_event(self, event):
        conn = self._get_conn()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO master_logs (event) VALUES (?)",
            (event,)
        )
        conn.commit()
        conn.close()
