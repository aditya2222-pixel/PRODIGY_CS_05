import threading
import tkinter as tk
from tkinter import messagebox, ttk
from scapy.all import IP, Raw, sniff


class NetworkPacketAnalyzerGUI:

    def __init__(self, root):
        self.root = root
        self.root.title("PRODIGY_CS_05 - Network Packet Analyzer")
        self.root.geometry("850x600")

        self.is_sniffing = False
        self.sniff_thread = None
        self.captured_packets = []

        self._build_ui()

    def _build_ui(self):
        # 1. Title Header
        title_label = tk.Label(
            self.root,
            text="Network Packet Analyzer",
            font=("Arial", 16, "bold"),
        )
        title_label.pack(pady=10)

        # 2. Controls & Filter Frame
        control_frame = tk.Frame(self.root)
        control_frame.pack(padx=20, fill=tk.X, pady=5)

        tk.Label(
            control_frame, text="Protocol Filter:", font=("Arial", 10, "bold")
        ).pack(side=tk.LEFT, padx=5)
        self.filter_combo = ttk.Combobox(
            control_frame,
            values=["ALL", "TCP", "UDP", "ICMP"],
            state="readonly",
            width=10,
        )
        self.filter_combo.set("ALL")
        self.filter_combo.pack(side=tk.LEFT, padx=5)

        self.btn_start = tk.Button(
            control_frame,
            text="Start Capture",
            command=self.start_capture,
            bg="#4CAF50",
            fg="white",
            font=("Arial", 9, "bold"),
            width=14,
        )
        self.btn_start.pack(side=tk.LEFT, padx=10)

        self.btn_stop = tk.Button(
            control_frame,
            text="Stop Capture",
            command=self.stop_capture,
            bg="#f44336",
            fg="white",
            font=("Arial", 9, "bold"),
            width=14,
            state=tk.DISABLED,
        )
        self.btn_stop.pack(side=tk.LEFT, padx=5)

        self.btn_clear = tk.Button(
            control_frame,
            text="Clear",
            command=self.clear_table,
            bg="#2196F3",
            fg="white",
            font=("Arial", 9, "bold"),
            width=10,
        )
        self.btn_clear.pack(side=tk.RIGHT, padx=5)

        # 3. Status Display
        self.lbl_status = tk.Label(
            self.root,
            text="Status: Idle",
            font=("Arial", 10, "italic"),
            fg="gray",
        )
        self.lbl_status.pack(pady=5)

        # 4. Captured Packets Table (Treeview)
        table_frame = tk.Frame(self.root)
        table_frame.pack(padx=20, pady=5, fill=tk.BOTH, expand=True)

        columns = ("No", "Source IP", "Destination IP", "Protocol", "Length")
        self.tree = ttk.Treeview(
            table_frame, columns=columns, show="headings", height=10
        )

        self.tree.heading("No", text="#")
        self.tree.heading("Source IP", text="Source IP")
        self.tree.heading("Destination IP", text="Destination IP")
        self.tree.heading("Protocol", text="Protocol")
        self.tree.heading("Length", text="Length (Bytes)")

        self.tree.column("No", width=50, anchor=tk.CENTER)
        self.tree.column("Source IP", width=180, anchor=tk.CENTER)
        self.tree.column("Destination IP", width=180, anchor=tk.CENTER)
        self.tree.column("Protocol", width=100, anchor=tk.CENTER)
        self.tree.column("Length", width=100, anchor=tk.CENTER)

        scrollbar = ttk.Scrollbar(
            table_frame, orient=tk.VERTICAL, command=self.tree.yview
        )
        self.tree.configure(yscroll=scrollbar.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.tree.bind("<<TreeviewSelect>>", self.on_packet_select)

        # 5. Payload Inspector
        inspector_frame = tk.LabelFrame(
            self.root,
            text="Payload Data / Packet Inspection",
            font=("Arial", 10, "bold"),
        )
        inspector_frame.pack(padx=20, pady=10, fill=tk.BOTH, expand=True)

        self.txt_payload = tk.Text(
            inspector_frame, height=6, font=("Consolas", 9)
        )
        self.txt_payload.pack(padx=5, pady=5, fill=tk.BOTH, expand=True)

    def _add_packet_to_tree(self, pkt_id, src_ip, dst_ip, proto_name, length):
        """Thread-safe UI insertion callback."""
        self.tree.insert(
            "",
            tk.END,
            values=(pkt_id, src_ip, dst_ip, proto_name, length),
        )

    def _packet_callback(self, packet):
        if not self.is_sniffing:
            return

        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            proto = packet[IP].proto
            length = len(packet)

            proto_name = "OTHER"
            if proto == 6:
                proto_name = "TCP"
            elif proto == 17:
                proto_name = "UDP"
            elif proto == 1:
                proto_name = "ICMP"

            selected_filter = self.filter_combo.get()
            if selected_filter != "ALL" and selected_filter != proto_name:
                return

            self.captured_packets.append(packet)
            pkt_id = len(self.captured_packets)

            # Fixed: Using lambda for thread-safe GUI updates without keyword argument errors
            self.root.after(
                0,
                lambda: self._add_packet_to_tree(
                    pkt_id, src_ip, dst_ip, proto_name, length
                ),
            )

    def _sniff_worker(self):
        try:
            sniff(
                prn=self._packet_callback,
                stop_filter=lambda p: not self.is_sniffing,
                store=False,
            )
        except Exception as e:
            err_msg = str(e)
            self.root.after(
                0,
                lambda: messagebox.showerror(
                    "Sniffing Error",
                    f"Failed to capture packets:\n{err_msg}\n\nMake sure to run as Administrator and install Npcap.",
                ),
            )
            self.root.after(0, self.stop_capture)

    def start_capture(self):
        self.is_sniffing = True
        self.btn_start.config(state=tk.DISABLED)
        self.btn_stop.config(state=tk.NORMAL)
        self.filter_combo.config(state=tk.DISABLED)
        self.lbl_status.config(
            text="Status: Capturing Live Packets...", fg="green"
        )

        self.sniff_thread = threading.Thread(
            target=self._sniff_worker, daemon=True
        )
        self.sniff_thread.start()

    def stop_capture(self):
        self.is_sniffing = False
        self.btn_start.config(state=tk.NORMAL)
        self.btn_stop.config(state=tk.DISABLED)
        self.filter_combo.config(state="readonly")
        self.lbl_status.config(text="Status: Capture Stopped", fg="red")

    def clear_table(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.captured_packets.clear()
        self.txt_payload.delete("1.0", tk.END)

    def on_packet_select(self, event):
        selected_item = self.tree.selection()
        if not selected_item:
            return

        item_values = self.tree.item(selected_item[0], "values")
        pkt_idx = int(item_values[0]) - 1

        if pkt_idx < len(self.captured_packets):
            packet = self.captured_packets[pkt_idx]

            self.txt_payload.delete("1.0", tk.END)
            self.txt_payload.insert(
                tk.END, f"--- PACKET #{pkt_idx + 1} SUMMARY ---\n"
            )
            self.txt_payload.insert(tk.END, f"{packet.summary()}\n\n")

            if Raw in packet:
                payload = packet[Raw].load
                self.txt_payload.insert(tk.END, "--- PAYLOAD DATA ---\n")
                self.txt_payload.insert(
                    tk.END, f"Raw Bytes: {payload}\n\n"
                )
                try:
                    decoded = payload.decode("utf-8", errors="replace")
                    self.txt_payload.insert(
                        tk.END, f"Decoded Text:\n{decoded}\n"
                    )
                except Exception:
                    pass
            else:
                self.txt_payload.insert(
                    tk.END, "--- PAYLOAD DATA ---\n[No Raw Payload Layer Found]"
                )


if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkPacketAnalyzerGUI(root)
    root.mainloop()