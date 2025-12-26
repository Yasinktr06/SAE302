import socket
import threading
import random
import time

from rsa_utils import (
    generate_rsa_key,
    rsa_encrypt_int,
    xor_bytes,
    b64e,
    bytes_to_int
)
from db import Database


def guess_my_ip(master_ip: str) -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((master_ip, 1))
        return s.getsockname()[0]
    finally:
        s.close()


class Client:
    def __init__(self, name, master_ip, master_port, listen_port):
        self.name = name
        self.master_ip = master_ip
        self.master_port = master_port
        self.listen_port = listen_port
        self.db = Database()

        self.on_message = None

        self.n, self.e, self.d = generate_rsa_key()
        self.my_ip = guess_my_ip(master_ip)

        self.clients = []  # [(ip,port,n,e), ...]
        self.routers = []  # [(ip,port,n,e), ...]

    # ---------- REGISTER ----------
    def register_to_master(self):
        msg = f"REGISTER {self.my_ip} {self.listen_port} {self.n} {self.e}"
        s = socket.socket()
        s.connect((self.master_ip, self.master_port))
        s.sendall(msg.encode())
        resp = s.recv(1024).decode(errors="ignore").strip()
        s.close()
        if resp != "OK":
            raise Exception("REGISTER refusé par le Master")

    def start_heartbeat(self):
        def loop():
            while True:
                try:
                    s = socket.socket()
                    s.connect((self.master_ip, self.master_port))
                    s.sendall(f"PING {self.listen_port}".encode())
                    s.close()
                except Exception:
                    pass
                time.sleep(3)
        threading.Thread(target=loop, daemon=True).start()

    # ---------- GET_ALL ----------
    def refresh_nodes(self):
        s = socket.socket()
        s.connect((self.master_ip, self.master_port))
        s.sendall(b"GET_ALL")
        data = s.recv(300000).decode(errors="ignore")
        s.close()

        self.clients = []
        self.routers = []
        if "??" not in data:
            return

        clients_part, routers_part = data.split("??", 1)

        def parse(part):
            out = []
            part = part.strip()
            if not part:
                return out
            for entry in part.split("||"):
                f = entry.split("/!")
                if len(f) != 4:
                    continue
                ip = f[0]
                port = int(f[1])
                n = int(f[2])
                e = int(f[3])
                out.append((ip, port, n, e))
            return out

        self.clients = parse(clients_part)
        self.routers = parse(routers_part)

    # ---------- RECEIVER ----------
    def start_receiver(self):
        threading.Thread(target=self._listen, daemon=True).start()

    def _listen(self):
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", self.listen_port))
        srv.listen(50)
        print(f"[CLIENT {self.name}] écoute sur {self.listen_port}")

        while True:
            conn, _ = srv.accept()
            data = conn.recv(300000)
            conn.close()
            if not data:
                continue

            msg = data.decode(errors="ignore")
            if self.on_message:
                self.on_message(msg)
            else:
                print(f"[{self.name}] reçu :", msg)

    # ---------- CRYPTO helper (hybrid) ----------
    def _encrypt_for_router(self, router_n, router_e, plaintext: bytes) -> str:
        key = bytes(random.getrandbits(8) for _ in range(16))
        cipher = xor_bytes(plaintext, key)
        key_cipher_int = rsa_encrypt_int(router_n, router_e, bytes_to_int(key))
        return f"{key_cipher_int}::{b64e(cipher)}"

    # ---------- MULTI ROUTING ----------
    def build_multihop_packet(self, route_routers, dest_ip, dest_port, message_text: str) -> bytes:
        """
        route_routers: list of tuples (ip, port, n, e) in the order to traverse
        Output: bytes to send to first router
        """
        # base payload to destination client
        inner = f"MSG={self.name}: {message_text}".encode()

        # build from LAST router back to FIRST router
        for i in range(len(route_routers) - 1, -1, -1):
            r_ip, r_port, r_n, r_e = route_routers[i]

            if i == len(route_routers) - 1:
                next_ip, next_port = dest_ip, dest_port
            else:
                next_ip, next_port = route_routers[i + 1][0], route_routers[i + 1][1]

            enc = self._encrypt_for_router(r_n, r_e, inner)  # string key::b64
            packet = f"{next_ip}/!{next_port}/!{enc}".encode()

            inner = packet  # next layer plaintext is the whole packet for the next hop

        return inner  # send to first router

    def send_to_client_multihop(self, dest_ip, dest_port, message_text: str, route_routers):
        if not route_routers:
            raise Exception("Aucun routeur dans la route")

        pkt = self.build_multihop_packet(route_routers, dest_ip, dest_port, message_text)
        first_ip, first_port = route_routers[0][0], route_routers[0][1]

        s = socket.socket()
        s.connect((first_ip, first_port))
        s.sendall(pkt)
        s.close()

        self.db.log_message(
            source=self.name,
            destination=f"{dest_ip}:{dest_port}",
            route=",".join([f"{ip}:{p}" for ip, p, _, _ in route_routers]),
            payload=message_text
        )
