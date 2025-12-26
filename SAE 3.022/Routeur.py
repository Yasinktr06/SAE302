import socket
import threading
import argparse
import sys
import time

from rsa_utils import (
    generate_rsa_key, rsa_decrypt_int,
    xor_bytes, b64d, int_to_bytes_fixed
)
from db import Database


class Routeur:
    def __init__(self, ip, port, master_ip, master_port):
        self.ip = ip
        self.port = port
        self.master_ip = master_ip
        self.master_port = master_port
        self.db = Database()

        self.n, self.e, self.d = generate_rsa_key()

    def register_to_master(self):
        msg = f"REGISTER {self.ip} {self.port} {self.n} {self.e}"
        s = socket.socket()
        s.connect((self.master_ip, self.master_port))
        s.sendall(msg.encode())
        resp = s.recv(1024).decode(errors="ignore").strip()
        s.close()
        if resp != "OK":
            print("[ROUTEUR] REGISTER refusé:", resp)
            sys.exit(1)
        print(f"[ROUTEUR {self.port}] enregistré au Master")

    def start_heartbeat(self):
        def loop():
            while True:
                try:
                    s = socket.socket()
                    s.connect((self.master_ip, self.master_port))
                    s.sendall(f"PING {self.port}".encode())
                    s.close()
                except Exception:
                    pass
                time.sleep(3)
        threading.Thread(target=loop, daemon=True).start()

    def start(self):
        self.register_to_master()
        self.start_heartbeat()
        self.listen()

    def listen(self):
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self.ip, self.port))
        srv.listen(50)
        print(f"[ROUTEUR {self.port}] écoute {self.ip}:{self.port}")

        while True:
            conn, addr = srv.accept()
            threading.Thread(target=self.handle, args=(conn,), daemon=True).start()

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

    def handle(self, conn):
        try:
            raw = self._recv_all(conn)
            conn.close()
            if not raw:
                return

            txt = raw.decode(errors="ignore").strip()
            parts = txt.split("/!")
            if len(parts) != 3:
                print(f"[ROUTEUR {self.port}] format invalide")
                return

            next_ip = parts[0]
            next_port = int(parts[1])

            enc = parts[2]
            if "::" not in enc:
                print(f"[ROUTEUR {self.port}] chiffrement invalide")
                return

            key_cipher_s, data_b64 = enc.split("::", 1)
            key_cipher_int = int(key_cipher_s)

            key_int = rsa_decrypt_int(self.n, self.d, key_cipher_int)
            key = int_to_bytes_fixed(key_int, 16)

            cipher_bytes = b64d(data_b64)
            plain = xor_bytes(cipher_bytes, key)

            self.db.log_router_event(self.port, next_port, "FORWARD")

            out = socket.socket()
            out.connect((next_ip, next_port))
            out.sendall(plain)
            out.close()

            print(f"[ROUTEUR {self.port}] → {next_ip}:{next_port}")

        except Exception as e:
            print(f"[ROUTEUR {self.port}] erreur:", e)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--ip", default="0.0.0.0")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--master-ip", required=True)
    parser.add_argument("--master-port", type=int, default=4000)
    args = parser.parse_args()

    Routeur(args.ip, args.port, args.master_ip, args.master_port).start()
