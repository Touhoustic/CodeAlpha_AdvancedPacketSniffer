import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import sys
import signal
from datetime import datetime
from scapy.all import (sniff, IP, TCP, UDP, ICMP, ARP, DNS, Raw, 
                       wrpcap, get_if_list, conf, Ether)
import threading
from collections import defaultdict
import binascii

class PacketSnifferGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Packet Sniffer - Network Traffic Analyzer")
        self.root.geometry("1400x800")
        
        self.captured_packets = []
        self.is_capturing = False
        self.capture_thread = None
        self.packet_count = 0
        
        self.stats = {
            'total': 0,
            'tcp': 0,
            'udp': 0,
            'icmp': 0,
            'arp': 0,
            'dns': 0,
            'http': 0,
            'other': 0
        }
        
        self.protocol_colors = {
            "TCP": "#E3F2FD",    # Light blue
            "UDP": "#E8F5E9",    # Light green
            "ICMP": "#FFEBEE",   # Light red
            "ARP": "#FFF3E0",    # Light orange
            "DNS": "#F3E5F5",    # Light purple
            "HTTP": "#E1F5FE",   # Cyan
            "OTHER": "#F5F5F5"   # Light gray
        }
        
        self.filter_protocol = tk.StringVar(value="All")
        self.filter_ip = tk.StringVar()
        self.filter_port = tk.StringVar()
        
        self.setup_protocol_tags()
        self.create_gui()
        self.update_stats_display()
        
    def setup_protocol_tags(self):
        self.configured_tags = set()
        
    def create_gui(self):
        main_paned = ttk.PanedWindow(self.root, orient=tk.VERTICAL)
        main_paned.pack(fill=tk.BOTH, expand=True)
        
        top_frame = ttk.Frame(main_paned)
        main_paned.add(top_frame, weight=3)
        
        self.create_control_frame(top_frame)
        
        self.create_stats_frame(top_frame)

        self.create_packet_tree(top_frame)
        
        self.create_detail_panel(main_paned)
        
    def create_control_frame(self, parent):
        control_frame = ttk.LabelFrame(parent, text="Capture Controls", padding=10)
        control_frame.pack(fill=tk.X, padx=5, pady=5)
        
        row1 = ttk.Frame(control_frame)
        row1.pack(fill=tk.X, pady=(0, 5))
        
        ttk.Label(row1, text="Interface:").pack(side=tk.LEFT, padx=5)
        self.interface_var = tk.StringVar()
        self.interface_combo = ttk.Combobox(row1, 
                                          textvariable=self.interface_var,
                                          state="readonly",
                                          width=25)
        self.interface_combo.pack(side=tk.LEFT, padx=5)
        
        interfaces = get_if_list()
        self.interface_combo['values'] = interfaces
        if interfaces:
            self.interface_combo.set(conf.iface)
            
        self.start_button = ttk.Button(row1, 
                                     text="▶ Start Capture",
                                     command=self.toggle_capture,
                                     width=15)
        self.start_button.pack(side=tk.LEFT, padx=5)
        
        self.save_button = ttk.Button(row1,
                                    text="💾 Save Capture",
                                    command=self.save_capture,
                                    state=tk.DISABLED,
                                    width=15)
        self.save_button.pack(side=tk.LEFT, padx=5)
        
        self.clear_button = ttk.Button(row1,
                                     text="🗑 Clear",
                                     command=self.clear_capture,
                                     width=12)
        self.clear_button.pack(side=tk.LEFT, padx=5)
        
        row2 = ttk.Frame(control_frame)
        row2.pack(fill=tk.X)
        
        ttk.Label(row2, text="Filter:").pack(side=tk.LEFT, padx=5)
        
        ttk.Label(row2, text="Protocol:").pack(side=tk.LEFT, padx=(15, 2))
        protocol_filter = ttk.Combobox(row2, 
                                      textvariable=self.filter_protocol,
                                      values=["All", "TCP", "UDP", "ICMP", "ARP", "DNS", "HTTP"],
                                      state="readonly",
                                      width=10)
        protocol_filter.pack(side=tk.LEFT, padx=2)
        protocol_filter.bind("<<ComboboxSelected>>", lambda e: self.apply_filter())
        
        ttk.Label(row2, text="IP:").pack(side=tk.LEFT, padx=(15, 2))
        ip_filter = ttk.Entry(row2, textvariable=self.filter_ip, width=15)
        ip_filter.pack(side=tk.LEFT, padx=2)
        ip_filter.bind("<Return>", lambda e: self.apply_filter())
        
        ttk.Label(row2, text="Port:").pack(side=tk.LEFT, padx=(15, 2))
        port_filter = ttk.Entry(row2, textvariable=self.filter_port, width=8)
        port_filter.pack(side=tk.LEFT, padx=2)
        port_filter.bind("<Return>", lambda e: self.apply_filter())
        
        ttk.Button(row2, text="Apply Filter", 
                  command=self.apply_filter).pack(side=tk.LEFT, padx=10)
        ttk.Button(row2, text="Clear Filter", 
                  command=self.clear_filter).pack(side=tk.LEFT)
        
    def create_stats_frame(self, parent):
        stats_frame = ttk.LabelFrame(parent, text="Capture Statistics", padding=10)
        stats_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.stats_labels = {}
        
        labels_info = [
            ("Total", "total"), ("TCP", "tcp"), ("UDP", "udp"), 
            ("ICMP", "icmp"), ("ARP", "arp"), ("DNS", "dns"),
            ("HTTP", "http"), ("Other", "other")
        ]
        
        for i, (display, key) in enumerate(labels_info):
            frame = ttk.Frame(stats_frame)
            frame.pack(side=tk.LEFT, padx=15)
            
            ttk.Label(frame, text=f"{display}:", 
                     font=("Arial", 9, "bold")).pack()
            label = ttk.Label(frame, text="0", 
                            font=("Arial", 11),
                            foreground="#1976D2")
            label.pack()
            self.stats_labels[key] = label
        
    def create_packet_tree(self, parent):
        tree_frame = ttk.LabelFrame(parent, text="Captured Packets", padding=5)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.tree = ttk.Treeview(tree_frame, 
                                columns=("No.", "Time", "Source", "Destination", 
                                        "Protocol", "Length", "Info"),
                                show="headings",
                                selectmode="browse",
                                height=15)
        
        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        self.tree.grid(column=0, row=0, sticky="nsew")
        vsb.grid(column=1, row=0, sticky="ns")
        hsb.grid(column=0, row=1, sticky="ew")
        tree_frame.grid_columnconfigure(0, weight=1)
        tree_frame.grid_rowconfigure(0, weight=1)
        
        columns_config = [
            ("No.", 60, 60),
            ("Time", 100, 100),
            ("Source", 150, 120),
            ("Destination", 150, 120),
            ("Protocol", 80, 80),
            ("Length", 80, 80),
            ("Info", 400, 200)
        ]
        
        for col, width, minwidth in columns_config:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=width, minwidth=minwidth)
        
        for proto, color in self.protocol_colors.items():
            tag = f"proto_{proto}"
            self.tree.tag_configure(tag, background=color)
            self.configured_tags.add(tag)
        
        self.tree.bind("<<TreeviewSelect>>", self.on_packet_select)
        
    def create_detail_panel(self, parent):
        detail_frame = ttk.LabelFrame(parent, text="Packet Details", padding=5)
        parent.add(detail_frame, weight=1)
        
        self.detail_notebook = ttk.Notebook(detail_frame)
        self.detail_notebook.pack(fill=tk.BOTH, expand=True)
        
        summary_frame = ttk.Frame(self.detail_notebook)
        self.detail_notebook.add(summary_frame, text="Summary")
        
        self.detail_text = scrolledtext.ScrolledText(summary_frame, 
                                                     height=10,
                                                     font=("Courier", 9))
        self.detail_text.pack(fill=tk.BOTH, expand=True)
        
        hex_frame = ttk.Frame(self.detail_notebook)
        self.detail_notebook.add(hex_frame, text="Hex Dump")
        
        self.hex_text = scrolledtext.ScrolledText(hex_frame, 
                                                  height=10,
                                                  font=("Courier", 9))
        self.hex_text.pack(fill=tk.BOTH, expand=True)
        
        ascii_frame = ttk.Frame(self.detail_notebook)
        self.detail_notebook.add(ascii_frame, text="ASCII Payload")
        
        self.ascii_text = scrolledtext.ScrolledText(ascii_frame, 
                                                    height=10,
                                                    font=("Courier", 9))
        self.ascii_text.pack(fill=tk.BOTH, expand=True)
        
    def packet_callback(self, pkt):
        if not self.is_capturing:
            return
            
        self.captured_packets.append(pkt)
        self.packet_count += 1
        packet_no = self.packet_count
        
        ts = datetime.fromtimestamp(pkt.time).strftime("%H:%M:%S.%f")[:-3]
        
        src, dst, proto, info, length = "N/A", "N/A", "OTHER", "", len(pkt)
        
        # Analyze packet
        if ARP in pkt:
            proto = "ARP"
            arp = pkt[ARP]
            src = arp.psrc
            dst = arp.pdst
            info = f"Who has {dst}? Tell {src}"
            self.stats['arp'] += 1
            
        elif IP in pkt:
            ip = pkt[IP]
            src, dst = ip.src, ip.dst
            
            if TCP in pkt:
                t = pkt[TCP]
                proto = "TCP"
                flags = self.get_tcp_flags(t.flags)
                info = f"{t.sport} → {t.dport} [{flags}]"
                self.stats['tcp'] += 1
                
                if t.dport in [80, 8080] or t.sport in [80, 8080]:
                    if Raw in pkt:
                        payload = bytes(pkt[Raw])
                        if payload.startswith(b'GET ') or payload.startswith(b'POST ') or payload.startswith(b'HTTP/'):
                            proto = "HTTP"
                            self.stats['http'] += 1
                            self.stats['tcp'] -= 1
                            # Extract HTTP info
                            try:
                                first_line = payload.split(b'\r\n')[0].decode('utf-8', errors='ignore')
                                info = f"{t.sport} → {t.dport} {first_line[:60]}"
                            except:
                                pass
                
            elif UDP in pkt:
                u = pkt[UDP]
                proto = "UDP"
                info = f"{u.sport} → {u.dport}"
                self.stats['udp'] += 1
                
                if u.dport == 53 or u.sport == 53:
                    if DNS in pkt:
                        proto = "DNS"
                        dns = pkt[DNS]
                        if dns.qr == 0:  # Query
                            if dns.qd:
                                info = f"Query: {dns.qd.qname.decode('utf-8', errors='ignore')}"
                        else:  # Response
                            info = f"Response"
                        self.stats['dns'] += 1
                        self.stats['udp'] -= 1
                
            elif ICMP in pkt:
                ic = pkt[ICMP]
                proto = "ICMP"
                info = f"Type={ic.type} Code={ic.code}"
                self.stats['icmp'] += 1
                
            else:
                proto = "OTHER"
                info = f"IP Protocol {ip.proto}"
                self.stats['other'] += 1
        else:
            info = pkt.summary()
            self.stats['other'] += 1
        
        self.stats['total'] += 1
        
        tag = f"proto_{proto}"
        packet_data = (packet_no, ts, src, dst, proto, length, info, tag)
        self.root.after(0, self.insert_packet, packet_data)
        
        self.root.after(0, self.update_stats_display)
        
    def get_tcp_flags(self, flags):
        """Convert TCP flags to readable string"""
        flag_names = []
        if flags & 0x01: flag_names.append("FIN")
        if flags & 0x02: flag_names.append("SYN")
        if flags & 0x04: flag_names.append("RST")
        if flags & 0x08: flag_names.append("PSH")
        if flags & 0x10: flag_names.append("ACK")
        if flags & 0x20: flag_names.append("URG")
        return ", ".join(flag_names) if flag_names else str(flags)
        
    def insert_packet(self, packet_data):
        packet_no, ts, src, dst, proto, length, info, tag = packet_data
        
        if not self.matches_filter(src, dst, proto, info):
            return
        
        if tag not in self.configured_tags:
            color = self.protocol_colors.get(proto, self.protocol_colors["OTHER"])
            self.tree.tag_configure(tag, background=color)
            self.configured_tags.add(tag)
            
        self.tree.insert("", "end", 
                        values=(packet_no, ts, src, dst, proto, length, info), 
                        tags=(tag,))
        
        if self.tree.yview()[1] > 0.9:
            self.tree.yview_moveto(1)
    
    def matches_filter(self, src, dst, proto, info):
        """Check if packet matches current filter settings"""
        if self.filter_protocol.get() != "All":
            if proto != self.filter_protocol.get():
                return False
        
        filter_ip = self.filter_ip.get().strip()
        if filter_ip:
            if filter_ip not in src and filter_ip not in dst:
                return False
        
        filter_port = self.filter_port.get().strip()
        if filter_port:
            if filter_port not in info:
                return False
        
        return True
    
    def apply_filter(self):
        """Reapply filter to existing packets"""
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        for i, pkt in enumerate(self.captured_packets, 1):
            ts = datetime.fromtimestamp(pkt.time).strftime("%H:%M:%S.%f")[:-3]
            
            src, dst, proto, info, length = self.extract_packet_info(pkt)
            tag = f"proto_{proto}"
            
            if self.matches_filter(src, dst, proto, info):
                self.tree.insert("", "end", 
                               values=(i, ts, src, dst, proto, length, info), 
                               tags=(tag,))
    
    def clear_filter(self):
        """Clear all filters"""
        self.filter_protocol.set("All")
        self.filter_ip.set("")
        self.filter_port.set("")
        self.apply_filter()
    
    def extract_packet_info(self, pkt):
        """Extract basic info from packet for filtering"""
        src, dst, proto, info, length = "N/A", "N/A", "OTHER", "", len(pkt)
        
        if ARP in pkt:
            proto = "ARP"
            arp = pkt[ARP]
            src, dst = arp.psrc, arp.pdst
            info = f"Who has {dst}? Tell {src}"
        elif IP in pkt:
            ip = pkt[IP]
            src, dst = ip.src, ip.dst
            
            if TCP in pkt:
                t = pkt[TCP]
                proto = "TCP"
                info = f"{t.sport} → {t.dport}"
                if t.dport in [80, 8080] or t.sport in [80, 8080]:
                    if Raw in pkt:
                        payload = bytes(pkt[Raw])
                        if payload.startswith(b'GET ') or payload.startswith(b'POST ') or payload.startswith(b'HTTP/'):
                            proto = "HTTP"
            elif UDP in pkt:
                u = pkt[UDP]
                proto = "UDP"
                info = f"{u.sport} → {u.dport}"
                if u.dport == 53 or u.sport == 53:
                    if DNS in pkt:
                        proto = "DNS"
            elif ICMP in pkt:
                proto = "ICMP"
        
        return src, dst, proto, info, length
    
    def update_stats_display(self):
        """Update statistics labels"""
        for key, label in self.stats_labels.items():
            label.config(text=str(self.stats[key]))
            
    def on_packet_select(self, event):
        """Handle packet selection to show details"""
        selection = self.tree.selection()
        if not selection:
            return
        
        item = self.tree.item(selection[0])
        packet_no = int(item['values'][0]) - 1
        
        if packet_no >= len(self.captured_packets):
            return
        
        pkt = self.captured_packets[packet_no]
        self.detail_text.delete(1.0, tk.END)
        self.detail_text.insert(tk.END, self.get_packet_summary(pkt))
        
        self.hex_text.delete(1.0, tk.END)
        self.hex_text.insert(tk.END, self.get_hex_dump(pkt))
        
        self.ascii_text.delete(1.0, tk.END)
        self.ascii_text.insert(tk.END, self.get_ascii_payload(pkt))
    
    def get_packet_summary(self, pkt):
        """Generate detailed packet summary"""
        lines = []
        lines.append("=" * 80)
        lines.append("PACKET SUMMARY")
        lines.append("=" * 80)
        lines.append(f"\nPacket Length: {len(pkt)} bytes")
        lines.append(f"Timestamp: {datetime.fromtimestamp(pkt.time)}")
        lines.append("\n" + "-" * 80)
        
        if Ether in pkt:
            eth = pkt[Ether]
            lines.append("\n[Ethernet Layer]")
            lines.append(f"  Source MAC: {eth.src}")
            lines.append(f"  Dest MAC: {eth.dst}")
            lines.append(f"  Type: {hex(eth.type)}")
        
        if ARP in pkt:
            arp = pkt[ARP]
            lines.append("\n[ARP Layer]")
            lines.append(f"  Operation: {'Request' if arp.op == 1 else 'Reply'}")
            lines.append(f"  Sender MAC: {arp.hwsrc}")
            lines.append(f"  Sender IP: {arp.psrc}")
            lines.append(f"  Target MAC: {arp.hwdst}")
            lines.append(f"  Target IP: {arp.pdst}")
        
        if IP in pkt:
            ip = pkt[IP]
            lines.append("\n[IP Layer]")
            lines.append(f"  Version: {ip.version}")
            lines.append(f"  Source IP: {ip.src}")
            lines.append(f"  Dest IP: {ip.dst}")
            lines.append(f"  Protocol: {ip.proto}")
            lines.append(f"  TTL: {ip.ttl}")
            lines.append(f"  Length: {ip.len}")
            
            if TCP in pkt:
                tcp = pkt[TCP]
                lines.append("\n[TCP Layer]")
                lines.append(f"  Source Port: {tcp.sport}")
                lines.append(f"  Dest Port: {tcp.dport}")
                lines.append(f"  Sequence: {tcp.seq}")
                lines.append(f"  Ack: {tcp.ack}")
                lines.append(f"  Flags: {self.get_tcp_flags(tcp.flags)}")
                lines.append(f"  Window: {tcp.window}")
                
            elif UDP in pkt:
                udp = pkt[UDP]
                lines.append("\n[UDP Layer]")
                lines.append(f"  Source Port: {udp.sport}")
                lines.append(f"  Dest Port: {udp.dport}")
                lines.append(f"  Length: {udp.len}")
                
                if DNS in pkt:
                    dns = pkt[DNS]
                    lines.append("\n[DNS Layer]")
                    lines.append(f"  Query/Response: {'Response' if dns.qr else 'Query'}")
                    lines.append(f"  Questions: {dns.qdcount}")
                    lines.append(f"  Answers: {dns.ancount}")
                    
            elif ICMP in pkt:
                icmp = pkt[ICMP]
                lines.append("\n[ICMP Layer]")
                lines.append(f"  Type: {icmp.type}")
                lines.append(f"  Code: {icmp.code}")
        
        if Raw in pkt:
            raw = pkt[Raw]
            lines.append(f"\n[Raw Payload]")
            lines.append(f"  Length: {len(raw.load)} bytes")
            
            # Try to detect HTTP
            if raw.load.startswith(b'GET ') or raw.load.startswith(b'POST ') or raw.load.startswith(b'HTTP/'):
                lines.append("  Type: HTTP")
                try:
                    payload_str = raw.load.decode('utf-8', errors='ignore')
                    lines.append(f"\n{payload_str[:500]}")
                except:
                    pass
        
        lines.append("\n" + "=" * 80)
        return "\n".join(lines)
    
    def get_hex_dump(self, pkt):
        """Generate hex dump of packet"""
        raw_bytes = bytes(pkt)
        lines = []
        
        for i in range(0, len(raw_bytes), 16):
            chunk = raw_bytes[i:i+16]
            hex_part = ' '.join(f'{b:02x}' for b in chunk)
            ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
            lines.append(f'{i:04x}  {hex_part:<48}  {ascii_part}')
        
        return '\n'.join(lines)
    
    def get_ascii_payload(self, pkt):
        """Extract and display ASCII payload (robust across layers)."""
        payload_bytes = b''
        try:
            if Raw in pkt:
                raw = pkt[Raw]
                payload_bytes = raw.load if hasattr(raw, 'load') else bytes(raw)
            elif TCP in pkt:
                payload_bytes = bytes(pkt[TCP].payload)
            elif UDP in pkt:
                payload_bytes = bytes(pkt[UDP].payload)
            elif DNS in pkt:
                dns = pkt[DNS]
                try:
                    if hasattr(dns, 'qd') and dns.qd:
                        q = dns.qd
                        qnames = []
                        if isinstance(q, list):
                            for entry in q:
                                qnames.append(getattr(entry, 'qname', b'').decode('utf-8', errors='ignore'))
                        else:
                            qnames.append(getattr(q, 'qname', b'').decode('utf-8', errors='ignore'))
                        if qnames:
                            return '\n'.join(qnames)
                except Exception:
                    pass
                payload_bytes = bytes(dns)
            else:
                p = pkt
                while True:
                    nxt = getattr(p, 'payload', None)
                    if not nxt or nxt.__class__.__name__ == 'NoPayload':
                        break
                    p = nxt
                    if Raw in p or (hasattr(p, 'load') and getattr(p, 'load')):
                        payload_bytes = getattr(p, 'load', b'') if hasattr(p, 'load') else bytes(p)
                        break
        except Exception:
            payload_bytes = b''
        
        
        if payload_bytes:
            try:
                return payload_bytes.decode('utf-8', errors='replace')
            except Exception:
                return ''.join(chr(b) if 32 <= b < 127 else '.' for b in payload_bytes)
        return "No payload data available"
            
    def toggle_capture(self):
        if not self.is_capturing:
            self.start_capture()
        else:
            self.stop_capture()
            
    def start_capture(self):
        interface = self.interface_var.get()
        if not interface:
            messagebox.showerror("Error", "Please select an interface")
            return
            
        self.is_capturing = True
        self.start_button.config(text="⏸ Stop Capture")
        self.interface_combo.config(state="disabled")
        self.save_button.config(state=tk.DISABLED)
        
        self.capture_thread = threading.Thread(target=self.capture_packets)
        self.capture_thread.daemon = True
        self.capture_thread.start()
        
    def stop_capture(self):
        self.is_capturing = False
        self.start_button.config(text="▶ Start Capture")
        self.interface_combo.config(state="readonly")
        if self.captured_packets:
            self.save_button.config(state=tk.NORMAL)
        
    def capture_packets(self):
        try:
            sniff(prn=self.packet_callback,
                 store=False,
                 iface=self.interface_var.get(),
                 stop_filter=lambda _: not self.is_capturing)
        except Exception as e:
            self.root.after(0, messagebox.showerror, "Error", str(e))
            self.root.after(0, self.stop_capture)
            
    def save_capture(self):
        if not self.captured_packets:
            messagebox.showwarning("Warning", "No packets to save")
            return
            
        filename = f"capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
        try:
            wrpcap(filename, self.captured_packets)
            messagebox.showinfo("Success", 
                              f"Saved {len(self.captured_packets)} packets to {filename}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save capture: {str(e)}")
    
    def clear_capture(self):
        self.tree.delete(*self.tree.get_children())
        self.captured_packets.clear()
        self.packet_count = 0
        self.save_button.config(state=tk.DISABLED)
        
        for key in self.stats:
            self.stats[key] = 0
        self.update_stats_display()
        
        self.detail_text.delete(1.0, tk.END)
        self.hex_text.delete(1.0, tk.END)
        self.ascii_text.delete(1.0, tk.END)
            
def main():
    root = tk.Tk()
    app = PacketSnifferGUI(root)
    root.protocol("WM_DELETE_WINDOW", root.quit)
    root.mainloop()

if __name__ == "__main__":
    main()