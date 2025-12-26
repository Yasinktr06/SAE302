import sys
import socket
import threading
import time

from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QTextEdit, QMessageBox
)
from PyQt5.QtCore import QTimer

from db import Database

HEARTBEAT_TIMEOUT = 10     # seconds
CLEAN_INTERVAL = 2


class MasterBackend:
    def __init__(self, bind_ip="0.0.0.0", port=4000):
        self.bind_ip = bind_ip
        self.port = port
        self.db = Database()

        self._lock = threading.Lock()
        self._running = threading.Event()
        self._running.clear()

        # key = (real_ip, port)  (important: distinguishes nodes behind same IP)
        self.clients = {}
        self.routers = {}

    def _classify(self, port: int) -> str:
        # simple rule: 5000-5999 routers, else clients
        if 5000 <= port <= 5999:
            return "ROUTER"
        return "CLIENT"

    def start(self):
        self._running.set()
        threading.Thread(target=self._cleanup_loop, daemon=True).start()

        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self.bind_ip, self.port))
        srv.listen(100)
        print(f"[MASTER] Écoute sur {self.bind_ip}:{self.port}")

        while self._running.is_set():
            conn, addr = srv.accept()
            threading.Thread(target=self._handle, args=(conn, addr), daemon=True).start()

    def _recv_all(self, conn):
        data = b""
        while True:
            part = conn.recv(4096)
            if not part:
                break
            data += part
            if len(part) < 4096:
                break
        return data

    def _cleanup_loop(self):
        while self._running.is_set():
            time.sleep(CLEAN_INTERVAL)
            now = time.time()
            with self._lock:
                self.clients = {k: v for k, v in self.clients.items()
                                if now - v["last_seen"] <= HEARTBEAT_TIMEOUT}
                self.routers = {k: v for k, v in self.routers.items()
                                if now - v["last_seen"] <= HEARTBEAT_TIMEOUT}

    def _handle(self, conn, addr):
        real_ip = addr[0]
        try:
            req = self._recv_all(conn).decode(errors="ignore").strip()
            if not req:
                conn.sendall(b"ERR")
                return

            # REGISTER declared_ip port n e
            if req.startswith("REGISTER"):
                parts = req.split()
                if len(parts) != 5:
                    conn.sendall(b"ERR")
                    return

                _, declared_ip, port_s, n_s, e_s = parts
                port = int(port_s); n = int(n_s); e = int(e_s)
                role = self._classify(port)

                entry = {
                    "declared_ip": declared_ip,
                    "real_ip": real_ip,
                    "port": port,
                    "n": n,
                    "e": e,
                    "last_seen": time.time()
                }

                with self._lock:
                    key = (real_ip, port)
                    if role == "ROUTER":
                        self.routers[key] = entry
                    else:
                        self.clients[key] = entry

                try:
                    self.db.log_master_event(f"{role} REGISTER {real_ip}:{port} declared={declared_ip}")
                except Exception:
                    pass

                conn.sendall(b"OK")
                return

            # PING port
            if req.startswith("PING"):
                parts = req.split()
                if len(parts) != 2:
                    conn.sendall(b"ERR")
                    return
                port = int(parts[1])

                with self._lock:
                    key = (real_ip, port)
                    if key in self.clients:
                        self.clients[key]["last_seen"] = time.time()
                        conn.sendall(b"PONG")
                        return
                    if key in self.routers:
                        self.routers[key]["last_seen"] = time.time()
                        conn.sendall(b"PONG")
                        return

                # unknown node
                conn.sendall(b"UNKNOWN")
                return

            # GET_ALL -> clients??routers
            if req == "GET_ALL":
                with self._lock:
                    clients_part = "||".join(
                        f'{e["real_ip"]}/!{e["port"]}/!{e["n"]}/!{e["e"]}'
                        for e in self.clients.values()
                    )
                    routers_part = "||".join(
                        f'{e["real_ip"]}/!{e["port"]}/!{e["n"]}/!{e["e"]}'
                        for e in self.routers.values()
                    )
                out = f"{clients_part}??{routers_part}"
                conn.sendall(out.encode())
                return

            conn.sendall(b"ERR")

        except Exception:
            try:
                conn.sendall(b"ERR")
            except Exception:
                pass
        finally:
            try:
                conn.close()
            except Exception:
                pass


class MasterWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Master – Alive Clients & Routers")
        self.resize(920, 520)

        self.backend = None

        root = QVBoxLayout()

        top = QHBoxLayout()
        self.in_bind = QLineEdit("0.0.0.0")
        self.in_port = QLineEdit("4000")
        self.btn_start = QPushButton("Lancer")
        self.btn_start.clicked.connect(self.start_master)
        self.lbl_status = QLabel("Status: arrêté")

        top.addWidget(QLabel("Bind IP"))
        top.addWidget(self.in_bind)
        top.addWidget(QLabel("Port"))
        top.addWidget(self.in_port)
        top.addWidget(self.btn_start)
        top.addWidget(self.lbl_status)
        root.addLayout(top)

        mid = QHBoxLayout()
        self.box_clients = QTextEdit(); self.box_clients.setReadOnly(True)
        self.box_routers = QTextEdit(); self.box_routers.setReadOnly(True)
        mid.addWidget(self.box_clients)
        mid.addWidget(self.box_routers)
        root.addLayout(mid)

        self.setLayout(root)

        self.timer = QTimer()
        self.timer.timeout.connect(self.refresh)
        self.timer.start(1000)

    def start_master(self):
        if self.backend:
            QMessageBox.information(self, "Info", "Master déjà lancé.")
            return

        bind_ip = self.in_bind.text().strip()
        try:
            port = int(self.in_port.text().strip())
        except Exception:
            QMessageBox.critical(self, "Erreur", "Port invalide.")
            return

        self.backend = MasterBackend(bind_ip, port)
        threading.Thread(target=self.backend.start, daemon=True).start()

        self.lbl_status.setText(f"écoute {bind_ip}:{port}")
        self.btn_start.setEnabled(False)
        self.in_bind.setEnabled(False)
        self.in_port.setEnabled(False)

    def refresh(self):
        if not self.backend:
            return
        now = time.time()
        with self.backend._lock:
            clients = list(self.backend.clients.values())
            routers = list(self.backend.routers.values())

        self.box_clients.setText(
            "CLIENTS (alive)\n" + ("\n".join(
                f'{e["real_ip"]}:{e["port"]}  last={int(now-e["last_seen"])}s'
                for e in clients
            ) if clients else "Aucun")
        )
        self.box_routers.setText(
            "ROUTERS (alive)\n" + ("\n".join(
                f'{e["real_ip"]}:{e["port"]}  last={int(now-e["last_seen"])}s'
                for e in routers
            ) if routers else "Aucun")
        )


if __name__ == "__main__":
    app = QApplication(sys.argv)
    w = MasterWindow()
    w.show()
    sys.exit(app.exec_())
