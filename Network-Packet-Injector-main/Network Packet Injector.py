import sys
from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QLineEdit, QTextEdit, QPushButton, QComboBox
)
from PyQt6.QtCore import Qt
from scapy.all import IP, TCP, UDP, ICMP, send
from PyQt6.QtWidgets import QGraphicsDropShadowEffect
from PyQt6.QtGui import QColor

class PacketInjector(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Network Packet Injector")
        self.setMinimumSize(500, 400)

        shadow = QGraphicsDropShadowEffect()
        shadow.setBlurRadius(20)
        shadow.setColor(QColor(0, 0, 0))
        shadow.setOffset(0, 0)
        self.setGraphicsEffect(shadow)

        self.init_ui()
        self.apply_dark_theme()

    def init_ui(self):
        main_layout = QVBoxLayout()

        # Target IP and Port
        ip_layout = QHBoxLayout()
        ip_label = QLabel("Target IP:")
        self.ip_input = QLineEdit()
        ip_layout.addWidget(ip_label)
        ip_layout.addWidget(self.ip_input)

        port_layout = QHBoxLayout()
        port_label = QLabel("Port:")
        self.port_input = QLineEdit()
        self.port_input.setPlaceholderText("Optional for ICMP")
        port_layout.addWidget(port_label)
        port_layout.addWidget(self.port_input)

        # Protocol selection
        proto_layout = QHBoxLayout()
        proto_label = QLabel("Protocol:")
        self.protocol_input = QComboBox()
        self.protocol_input.addItems(["TCP", "UDP", "ICMP"])
        proto_layout.addWidget(proto_label)
        proto_layout.addWidget(self.protocol_input)

        # Payload input
        payload_label = QLabel("Payload (Hex or ASCII):")
        self.payload_input = QTextEdit()
        self.payload_input.setPlaceholderText("Type your payload here")

        # Send Button
        self.send_btn = QPushButton("Send Packet")
        self.send_btn.clicked.connect(self.send_packet)

        # Status box
        self.status_box = QTextEdit()
        self.status_box.setReadOnly(True)
        self.status_box.setPlaceholderText("Status messages will appear here...")

        # Add widgets to main layout
        main_layout.addLayout(ip_layout)
        main_layout.addLayout(port_layout)
        main_layout.addLayout(proto_layout)
        main_layout.addWidget(payload_label)
        main_layout.addWidget(self.payload_input)
        main_layout.addWidget(self.send_btn)
        main_layout.addWidget(self.status_box)

        self.setLayout(main_layout)

    def apply_dark_theme(self):
        self.setStyleSheet("""
            QWidget {
                background-color: #121212;
                color: #e0e0e0;
                font-family: Arial, sans-serif;
                font-size: 14px;
            }
            QLineEdit, QTextEdit {
                background-color: #1e1e1e;
                border: 1px solid #444;
                border-radius: 5px;
                padding: 5px;
                color: #e0e0e0;
            }
            QPushButton {
                background-color: #2979ff;
                color: white;
                border-radius: 5px;
                padding: 8px;
            }
            QPushButton:hover {
                background-color: #5393ff;
            }
            QComboBox {
                background-color: #1e1e1e;
                border: 1px solid #444;
                border-radius: 5px;
                padding: 3px;
                color: #e0e0e0;
            }
        """)

    def send_packet(self):
        ip = self.ip_input.text().strip()
        port_text = self.port_input.text().strip()
        proto = self.protocol_input.currentText()
        payload_text = self.payload_input.toPlainText().strip()

        if not ip:
            self.status_box.append("❌ Error: Target IP is required.")
            return

        try:
            port = int(port_text) if port_text else None
        except ValueError:
            self.status_box.append("❌ Error: Port must be a number.")
            return

        try:
            payload = bytes.fromhex(payload_text.replace(" ", ""))
        except ValueError:
            payload = payload_text.encode("utf-8") if payload_text else b""

        try:
            pkt = IP(dst=ip)
            if proto == "TCP":
                if not port:
                    self.status_box.append("❌ TCP protocol requires a port.")
                    return
                pkt /= TCP(dport=port) / payload
            elif proto == "UDP":
                if not port:
                    self.status_box.append("❌ UDP protocol requires a port.")
                    return
                pkt /= UDP(dport=port) / payload
            else:
                pkt /= ICMP() / payload

            send(pkt, verbose=False)
            self.status_box.append(f"✅ Packet sent to {ip} via {proto} port {port if port else '-'}")
        except PermissionError:
            self.status_box.append("❌ Permission denied: Run as administrator/root.")
        except Exception as e:
            self.status_box.append(f"❌ Error sending packet: {e}")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = PacketInjector()
    window.show()
    sys.exit(app.exec())
