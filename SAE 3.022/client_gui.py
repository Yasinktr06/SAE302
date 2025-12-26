import sys
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QTextEdit,
    QListWidget, QMessageBox, QListWidgetItem, QAbstractItemView
)
from PyQt5.QtCore import QTimer

from client import Client


class ClientGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Client – Multi-routage")
        self.resize(950, 700)

        self.client = None
        self.selected_dest = None
        self.selected_routers = set()  # {"ip:port", ...}

        root = QVBoxLayout()

        # CONFIG
        cfg = QHBoxLayout()
        self.in_master_ip = QLineEdit("127.0.0.1")
        self.in_master_port = QLineEdit("4000")
        self.in_listen = QLineEdit("6001")
        self.in_name = QLineEdit("Alice")

        cfg.addWidget(QLabel("IP Master"))
        cfg.addWidget(self.in_master_ip)
        cfg.addWidget(QLabel("Port Master"))
        cfg.addWidget(self.in_master_port)
        cfg.addWidget(QLabel("Port écoute"))
        cfg.addWidget(self.in_listen)
        cfg.addWidget(QLabel("Nom"))
        cfg.addWidget(self.in_name)

        self.btn_start = QPushButton("Lancer")
        self.btn_start.clicked.connect(self.start_client)
        cfg.addWidget(self.btn_start)
        root.addLayout(cfg)

        # LISTS
        lists = QHBoxLayout()

        left = QVBoxLayout()
        left.addWidget(QLabel("Clients (choisir destinataire)"))
        self.list_clients = QListWidget()
        self.list_clients.itemSelectionChanged.connect(self.save_dest_selection)
        left.addWidget(self.list_clients)

        right = QVBoxLayout()
        right.addWidget(QLabel("Routeurs (Ctrl+clic pour multi-sélection)"))
        self.list_routers = QListWidget()
        self.list_routers.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.list_routers.itemSelectionChanged.connect(self.save_router_selection)
        right.addWidget(self.list_routers)

        lists.addLayout(left)
        lists.addLayout(right)
        root.addLayout(lists)

        # SEND
        send = QHBoxLayout()
        self.in_msg = QLineEdit()
        self.in_msg.setPlaceholderText("Message à envoyer…")
        send.addWidget(self.in_msg)

        self.btn_send = QPushButton("Envoyer")
        self.btn_send.setEnabled(False)
        self.btn_send.clicked.connect(self.send_message)
        send.addWidget(self.btn_send)
        root.addLayout(send)

        # RECEIVE
        root.addWidget(QLabel("Messages reçus"))
        self.box_recv = QTextEdit()
        self.box_recv.setReadOnly(True)
        root.addWidget(self.box_recv)

        # LOGS
        root.addWidget(QLabel("Logs"))
        self.logs = QTextEdit()
        self.logs.setReadOnly(True)
        root.addWidget(self.logs)

        self.setLayout(root)

        self.timer = QTimer()
        self.timer.timeout.connect(self.refresh_lists)
        self.timer.start(1500)

    def log(self, s):
        self.logs.append(s)

    def on_receive_message(self, msg):
        self.box_recv.append(msg)

    def save_dest_selection(self):
        item = self.list_clients.currentItem()
        self.selected_dest = item.text() if item else None

    def save_router_selection(self):
        self.selected_routers = set([i.text() for i in self.list_routers.selectedItems()])

    def start_client(self):
        if self.client:
            return
        try:
            self.client = Client(
                name=self.in_name.text().strip(),
                master_ip=self.in_master_ip.text().strip(),
                master_port=int(self.in_master_port.text().strip()),
                listen_port=int(self.in_listen.text().strip())
            )
            self.client.on_message = self.on_receive_message

            self.client.register_to_master()
            self.client.start_heartbeat()
            self.client.refresh_nodes()
            self.client.start_receiver()

            self.btn_start.setEnabled(False)
            self.btn_send.setEnabled(True)

            self.in_master_ip.setEnabled(False)
            self.in_master_port.setEnabled(False)
            self.in_listen.setEnabled(False)
            self.in_name.setEnabled(False)

            self.log("Client lancé, enregistré, heartbeat actif.")
        except Exception as e:
            QMessageBox.critical(self, "Erreur", str(e))

    def refresh_lists(self):
        if not self.client:
            return
        try:
            self.client.refresh_nodes()
        except Exception:
            return

        # Preserve selections
        dest_keep = self.selected_dest
        routers_keep = set(self.selected_routers)

        # Clients list
        self.list_clients.blockSignals(True)
        self.list_clients.clear()
        for ip, port, _, _ in self.client.clients:
            if ip == self.client.my_ip and port == self.client.listen_port:
                continue
            label = f"{ip}:{port}"
            self.list_clients.addItem(label)
            if label == dest_keep:
                self.list_clients.setCurrentRow(self.list_clients.count() - 1)
        self.list_clients.blockSignals(False)

        # Routers list
        self.list_routers.blockSignals(True)
        self.list_routers.clear()
        for ip, port, _, _ in self.client.routers:
            label = f"{ip}:{port}"
            item = QListWidgetItem(label)
            self.list_routers.addItem(item)
            if label in routers_keep:
                item.setSelected(True)
        self.list_routers.blockSignals(False)

        # update cached selections (in case removed)
        self.save_dest_selection()
        self.save_router_selection()

    def send_message(self):
        if not self.client:
            return
        if not self.selected_dest:
            QMessageBox.warning(self, "Erreur", "Choisis un destinataire client.")
            return
        msg = self.in_msg.text().strip()
        if not msg:
            return

        # build route routers from selected items
        selected_labels = [i.text() for i in self.list_routers.selectedItems()]
        if not selected_labels:
            QMessageBox.warning(self, "Erreur", "Sélectionne au moins 1 routeur (à droite).")
            return

        # map label -> (ip,port,n,e) from client.routers
        router_map = {f"{ip}:{port}": (ip, port, n, e) for ip, port, n, e in self.client.routers}
        route = []
        for lab in selected_labels:
            if lab in router_map:
                route.append(router_map[lab])

        if not route:
            QMessageBox.warning(self, "Erreur", "Aucun routeur sélectionné valide.")
            return

        dest_ip, dest_port_s = self.selected_dest.split(":")
        dest_port = int(dest_port_s)

        try:
            self.client.send_to_client_multihop(dest_ip, dest_port, msg, route)
            self.log(f"Envoyé à {self.selected_dest} via {len(route)} routeur(s).")
            self.in_msg.clear()
        except Exception as e:
            QMessageBox.critical(self, "Erreur", str(e))


if __name__ == "__main__":
    app = QApplication(sys.argv)
    w = ClientGUI()
    w.show()
    sys.exit(app.exec_())
