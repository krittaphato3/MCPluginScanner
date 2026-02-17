import threading
import requests
import re
import queue
import time
import ipaddress
import socket
import os
import sys
from collections import Counter
from datetime import datetime
import customtkinter as ctk
from tkinter import filedialog, messagebox
from mcstatus import JavaServer

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("green")
socket.setdefaulttimeout(3.0)

IGNORED_DEFAULTS = ["paper", "spigot", "bukkit", "craftbukkit", "purpur", "tuinity", "velocity", "bungeecord", "waterfall"]

class DarkSearchUltraV5(ctk.CTk):
    def __init__(self):
        super().__init__()
        
        self.title("DarkSearch ULTRA V5 - Summary & Stability Fix")
        self.geometry("1150x850")
        self.minsize(950, 650)
        
        self.stop_event = threading.Event()
        self.stop_fetch_event = threading.Event()
        
        self.work_queue = queue.Queue()
        self.gui_queue = queue.Queue()
        
        self.seen_ips = set()
        self.scanned_history = set()
        self.memory_buffer = []
        self.session_matches = []
        
        self.total_targets = 0        
        self.active_workers = 0

        self.stats = {
            "fetched": 0, "checked": 0, "hits": 0, "errors": 0, "threads": 0
        }

        self._init_files()

        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self._build_sidebar()
        self._build_dashboard()
        
        self.after(200, self.ui_update_loop)

    def _init_files(self):
        if not os.path.exists("scanned.txt"): 
            with open("scanned.txt", "w") as f: pass
        if not os.path.exists("matches.txt"): 
            with open("matches.txt", "w") as f: f.write("--- MATCHES ---\n")
        with open("debug.log", "w") as f: 
            f.write(f"--- SESSION START {datetime.now()} ---\n")

    def _build_sidebar(self):
        self.sidebar = ctk.CTkFrame(self, width=280, corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_rowconfigure(12, weight=1)

        self.logo = ctk.CTkLabel(self.sidebar, text="DARKSEARCH\nULTRA V5", 
                                 font=ctk.CTkFont(size=26, weight="bold"), text_color="#00E676")
        self.logo.grid(row=0, column=0, padx=20, pady=(30, 20))

        self._add_header("  PERFORMANCE", row=1)
        self.threads_entry = self._add_input("Threads (Max 500)", "350", row=2)
        
        t_frame = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        t_frame.grid(row=3, column=0, padx=20, pady=5, sticky="ew")
        
        self.knock_timeout = ctk.CTkEntry(t_frame, placeholder_text="Knock", width=90)
        self.knock_timeout.pack(side="left", padx=(0,5))
        self.knock_timeout.insert(0, "0.5")
        
        self.query_timeout = ctk.CTkEntry(t_frame, placeholder_text="Query", width=90)
        self.query_timeout.pack(side="right")
        self.query_timeout.insert(0, "1.5")

        self.use_knock = ctk.CTkSwitch(self.sidebar, text="  Fast Knock (Skip Dead)")
        self.use_knock.grid(row=4, column=0, padx=20, pady=10, sticky="w")
        self.use_knock.select()

        self._add_header("  RULES & TARGETS", row=5)
        self.targets_box = ctk.CTkTextbox(self.sidebar, height=100, font=("Consolas", 12))
        self.targets_box.grid(row=6, column=0, padx=20, pady=5, sticky="ew")
        self.targets_box.insert("0.0", "Vulcan, Spartan, Matrix, AAC")
        
        self.strict_mode = ctk.CTkSwitch(self.sidebar, text="  Strict Match Only")
        self.strict_mode.grid(row=7, column=0, padx=20, pady=10, sticky="w")
        self.strict_mode.select()

        self.ignore_history = ctk.CTkSwitch(self.sidebar, text="  Rescan All (Ignore History)", progress_color="#AB47BC")
        self.ignore_history.grid(row=8, column=0, padx=20, pady=10, sticky="w")

        self.btn_start = ctk.CTkButton(self.sidebar, text="START NEW SESSION", fg_color="#00C853", hover_color="#009624", height=50, font=("Arial", 14, "bold"), command=self.start_session)
        self.btn_start.grid(row=9, column=0, padx=20, pady=(30, 10), sticky="ew")

        self.btn_proceed = ctk.CTkButton(self.sidebar, text="STOP FETCH & SCAN >", fg_color="#FF9800", hover_color="#F57C00", height=40, state="disabled", font=("Arial", 12, "bold"), command=self.proceed_to_scan)
        self.btn_proceed.grid(row=10, column=0, padx=20, pady=5, sticky="ew")

        self.btn_stop = ctk.CTkButton(self.sidebar, text="FORCE STOP & SUMMARY", fg_color="#D32F2F", hover_color="#B71C1C", state="disabled", command=self.force_stop)
        self.btn_stop.grid(row=11, column=0, padx=20, pady=10, sticky="ew")

    def _build_dashboard(self):
        self.main = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")
        self.main.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)
        self.main.grid_rowconfigure(4, weight=1)
        self.main.grid_columnconfigure(0, weight=1)

        self.status_frame = ctk.CTkFrame(self.main, height=60)
        self.status_frame.grid(row=0, column=0, sticky="ew", pady=(0, 15))
        
        self.lbl_status = ctk.CTkLabel(self.status_frame, text="READY", font=("Arial", 18, "bold"), text_color="gray")
        self.lbl_status.pack(side="left", padx=20)
        
        self.lbl_prog_text = ctk.CTkLabel(self.status_frame, text="Waiting...", font=("Consolas", 14))
        self.lbl_prog_text.pack(side="right", padx=20)

        self.progress_bar = ctk.CTkProgressBar(self.main, height=15)
        self.progress_bar.grid(row=1, column=0, sticky="ew", pady=(0, 20))
        self.progress_bar.set(0)

        self.tabs = ctk.CTkTabview(self.main, height=180)
        self.tabs.grid(row=2, column=0, sticky="ew")
        
        tab_web = self.tabs.add("  Web Scraper  ")
        ctk.CTkLabel(tab_web, text="Source:").grid(row=0, column=0, padx=10, pady=15, sticky="e")
        self.site_select = ctk.CTkOptionMenu(tab_web, values=["MinecraftServers.org", "Minecraft-MP.com", "TopG.org", "Minecraft-Server-List.com"], width=220)
        self.site_select.grid(row=0, column=1, padx=10, pady=15, sticky="w")
        
        ctk.CTkLabel(tab_web, text="Storage:").grid(row=1, column=0, padx=10, pady=15, sticky="e")
        self.storage_mode = ctk.CTkSegmentedButton(tab_web, values=["Temp Memory", "File (Resumable)"])
        self.storage_mode.grid(row=1, column=1, padx=10, pady=15, sticky="w")
        self.storage_mode.set("File (Resumable)")
        
        self.chk_rewrite = ctk.CTkCheckBox(tab_web, text="Always Rewrite File (Clean Start)")
        self.chk_rewrite.grid(row=2, column=1, padx=10, pady=10, sticky="w")

        tab_file = self.tabs.add("  Custom List  ")
        self.btn_load_file = ctk.CTkButton(tab_file, text="Select .txt File", command=self.load_custom_file)
        self.btn_load_file.pack(pady=30)
        self.lbl_file_name = ctk.CTkLabel(tab_file, text="No file selected", text_color="gray")
        self.lbl_file_name.pack()
        self.custom_file_path = None
        tab_ip = self.tabs.add("  IP Range  ")
        self.ip_input = ctk.CTkEntry(tab_ip, width=400, placeholder_text="192.168.1.0/24")
        self.ip_input.pack(pady=40)

        self.stats_grid = ctk.CTkFrame(self.main, fg_color="transparent")
        self.stats_grid.grid(row=3, column=0, sticky="ew", pady=10)
        self.stats_grid.grid_columnconfigure((0,1,2,3), weight=1)
        
        self.stat_threads = self._make_stat_card("Active Threads", "#FF9800", 0)
        self.stat_scanned = self._make_stat_card("Scanned", "#AB47BC", 1)
        self.stat_hits = self._make_stat_card("HITS FOUND", "#00E676", 2)
        self.stat_errors = self._make_stat_card("Errors", "#FF5252", 3)

        self.console = ctk.CTkTextbox(self.main, font=("Consolas", 11), activate_scrollbars=True)
        self.console.grid(row=4, column=0, sticky="nsew", pady=(10, 0))
        self.console.configure(state="disabled")
        self.console.tag_config("HIT", foreground="#00E676")
        self.console.tag_config("SYS", foreground="#29B6F6")
        self.console.tag_config("ERR", foreground="#FF5252")
        self.console.tag_config("WARN", foreground="#FF9800")

    def _add_header(self, text, row):
        l = ctk.CTkLabel(self.sidebar, text=text, font=("Arial", 11, "bold"), text_color="gray60")
        l.grid(row=row, column=0, padx=20, pady=(20, 5), sticky="w")

    def _add_input(self, placeholder, default, row):
        e = ctk.CTkEntry(self.sidebar, placeholder_text=placeholder)
        e.grid(row=row, column=0, padx=20, pady=5, sticky="ew")
        e.insert(0, default)
        return e

    def _make_stat_card(self, title, color, col):
        f = ctk.CTkFrame(self.stats_grid, fg_color=("gray85", "gray17"))
        f.grid(row=0, column=col, padx=5, sticky="ew")
        ctk.CTkLabel(f, text=title, font=("Arial", 10, "bold"), text_color="gray50").pack(pady=(5,0))
        lbl = ctk.CTkLabel(f, text="0", font=("Arial", 22, "bold"), text_color=color)
        lbl.pack(pady=(0,5))
        return lbl

    def load_custom_file(self):
        path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
        if path:
            self.custom_file_path = path
            self.lbl_file_name.configure(text=os.path.basename(path))

    def log(self, text, tag="INFO"):
        self.gui_queue.put(("LOG", (text, tag)))
        try:
            with open("debug.log", "a", encoding="utf-8") as f:
                f.write(f"[{datetime.now().strftime('%H:%M:%S')}] {text}\n")
        except: pass

    def ui_update_loop(self):
        try:
            self.stat_threads.configure(text=str(self.active_workers))
            
            for _ in range(50):
                try:
                    kind, data = self.gui_queue.get_nowait()
                    if kind == "LOG":
                        txt, tag = data
                        self.console.configure(state="normal")
                        self.console.insert("end", f"[{datetime.now().strftime('%H:%M:%S')}] {txt}\n", tag)
                        self.console.see("end")
                        self.console.configure(state="disabled")
                    elif kind == "STAT":
                        key, val = data
                        self.stats[key] = val
                    elif kind == "DONE":
                        self.show_summary()
                except queue.Empty: break
            
            self.stat_scanned.configure(text=f"{self.stats['checked']:,}")
            self.stat_hits.configure(text=f"{self.stats['hits']:,}")
            self.stat_errors.configure(text=f"{self.stats['errors']:,}")

            if self.total_targets > 0:
                prog = self.stats['checked'] / self.total_targets
                self.progress_bar.set(prog)
                self.lbl_prog_text.configure(text=f"{self.stats['checked']:,} / {self.total_targets:,}")
            
        except: pass
        self.after(100, self.ui_update_loop)

    def update_stat(self, key, val):
        self.gui_queue.put(("STAT", (key, val)))

    def show_summary(self):
        total = self.stats['checked']
        hits = self.stats['hits']
        
        all_plugins = []
        for match in self.session_matches:
            for p in match['detected']:
                all_plugins.append(p)
        
        common = Counter(all_plugins).most_common(5)
        top_str = "\n".join([f"- {p[0]}: {p[1]}" for p in common]) if common else "None"

        summary = f"""
        === SCAN COMPLETE ===
        
        Total Scanned: {total}
        Total Hits: {hits}
        
        Top Detected Targets:
        {top_str}
        
        Check 'matches.txt' for details.
        """
        messagebox.showinfo("Scan Summary", summary)
        self.lbl_status.configure(text="FINISHED", text_color="#00E676")
        self.btn_start.configure(state="normal")
        self.btn_stop.configure(state="disabled")

    def start_session(self):
        self.stop_event.clear()
        self.stop_fetch_event.clear()
        self.work_queue = queue.Queue()
        self.stats = {k:0 for k in self.stats}
        self.seen_ips = set()
        self.memory_buffer = []
        self.session_matches = []
        self.active_workers = 0
        
        self.btn_start.configure(state="disabled")
        self.btn_stop.configure(state="normal")
        
        tab = self.tabs.get()
        
        if "Web Scraper" in tab:
            self.lbl_status.configure(text="FETCHING IPs...", text_color="#29B6F6")
            self.btn_proceed.configure(state="normal")
            
            source = self.site_select.get()
            mode = self.storage_mode.get()
            threading.Thread(target=self.process_fetch, args=(source, mode), daemon=True).start()
            
        elif "Custom List" in tab:
            if not self.custom_file_path:
                self.log("No file selected!", "ERR")
                self.force_stop()
                return
            self.lbl_status.configure(text="LOADING FILE...", text_color="#AB47BC")
            threading.Thread(target=self.process_load_file, args=(self.custom_file_path,), daemon=True).start()
            
        elif "IP Range" in tab:
            rng = self.ip_input.get().strip()
            if not rng:
                self.log("No IP Range entered!", "ERR")
                self.force_stop()
                return
            self.lbl_status.configure(text="GENERATING RANGE...", text_color="#AB47BC")
            threading.Thread(target=self.process_gen_range, args=(rng,), daemon=True).start()

    def proceed_to_scan(self):
        self.log("Stopping Fetch... Preparing Scan...", "SYS")
        self.stop_fetch_event.set()
        self.btn_proceed.configure(state="disabled")

    def force_stop(self):
        self.stop_event.set()
        self.stop_fetch_event.set()
        self.log("STOPPING...", "ERR")
        self.gui_queue.put(("DONE", None)) # Trigger summary

    def process_fetch(self, source, mode):
        self.log(f"Fetching from {source}...", "SYS")
        
        filename = f"ips_{source.replace('.', '_')}.txt"
        f_handle = None
        
        if "File" in mode:
            perm = "a"
            if self.chk_rewrite.get() or not os.path.exists(filename):
                perm = "w"
                self.log("Starting fresh file.", "SYS")
            f_handle = open(filename, perm)
        
        try:
            with requests.Session() as s:
                s.headers = {'User-Agent': 'Mozilla/5.0'}
                page = 1
                
                while not self.stop_event.is_set() and not self.stop_fetch_event.is_set():
                    url = self._get_url(source, page)
                    if not url: break
                    
                    try:
                        r = s.get(url, timeout=10)
                        txt = r.text
                        ips = self._extract_ips(txt)
                        
                        new_on_page = 0
                        for ip in ips:
                            if ip not in self.seen_ips:
                                self.seen_ips.add(ip)
                                new_on_page += 1
                                
                                if "File" in mode:
                                    f_handle.write(ip + "\n")
                                    f_handle.flush()
                                else:
                                    self.memory_buffer.append(ip)
                                    
                        self.update_stat("fetched", len(self.seen_ips))
                        self.lbl_prog_text.configure(text=f"Fetched: {len(self.seen_ips)}")
                        
                        if new_on_page > 0:
                            self.log(f"Page {page}: +{new_on_page} IPs", "INFO")
                        
                        page += 1
                        time.sleep(1)
                        if page > 100: break
                             
                    except Exception as e:
                        self.log(f"Fetch Error: {e}", "ERR")
                        time.sleep(2)
                        
        except Exception as e:
            self.log(f"Fatal Error: {e}", "ERR")
        finally:
            if f_handle: f_handle.close()
            
        if not self.stop_event.is_set():
            self.process_load_scan_queue(mode, filename)

    def _get_url(self, source, page):
        if source == "MinecraftServers.org": return f"https://minecraftservers.org/index/{page}"
        if source == "Minecraft-MP.com": return f"https://minecraft-mp.com/servers/list/{page}/"
        if source == "TopG.org": return "https://topg.org/minecraft-servers/" if page == 1 else f"https://topg.org/minecraft-servers/page/{page}"
        if source == "Minecraft-Server-List.com": return f"https://www.minecraft-server-list.com/sort/Popular/page/{page}/"
        return None

    def _extract_ips(self, txt):
        patterns = [
            r'<div class="url">(.*?)</div>',
            r'<strong>([a-zA-Z0-9\.\-]+\.[a-zA-Z]{2,}(?::\d+)?)</strong>',
            r'class="copyip" data-clipboard-text="(.*?)"',
            r'<div class="n2 copy" data-clipboard-text="(.*?)">',
            r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(?::\d{1,5})?'
        ]
        results = []
        for p in patterns:
            found = re.findall(p, txt)
            for ip in found:
                clean = ip.strip()
                if "." in clean and clean not in results:
                    results.append(clean)
        return results

    def process_gen_range(self, rng):
        try:
            ips = []
            if "/" in rng:
                ips = [str(ip) for ip in ipaddress.ip_network(rng, strict=False)]
            else:
                ips = [rng]
            self.process_finalize_queue(ips)
        except Exception as e:
            self.log(f"Range Error: {e}", "ERR")
            self.force_stop()

    def process_load_file(self, filepath):
        try:
            ips = []
            with open(filepath, "r") as f:
                ips = [l.strip() for l in f if l.strip()]
            self.process_finalize_queue(ips)
        except Exception as e:
            self.log(f"File Load Error: {e}", "ERR")
            self.force_stop()

    def process_load_scan_queue(self, mode, filename):
        ips = []
        if "File" in mode:
            if os.path.exists(filename):
                with open(filename, "r") as f:
                    ips = [l.strip() for l in f if l.strip()]
        else:
            ips = self.memory_buffer
        self.process_finalize_queue(ips)

    def process_finalize_queue(self, all_ips):
        if self.ignore_history.get():
            self.log("RESCAN MODE: Ignoring history.", "WARN")
            self.scanned_history = set()
        else:
            try:
                with open("scanned.txt", "r") as f:
                    self.scanned_history = set(l.strip() for l in f)
            except: pass
        
        valid_ips = []
        for ip in all_ips:
            if ip not in self.scanned_history:
                valid_ips.append(ip)
        
        for ip in valid_ips:
            self.work_queue.put(ip)
            
        self.total_targets = len(valid_ips) + (len(self.scanned_history) if not self.ignore_history.get() else 0)
        self.stats['checked'] = len(self.scanned_history) if not self.ignore_history.get() else 0
        self.update_stat("checked", self.stats['checked'])
        
        if not valid_ips:
            self.log("All IPs already scanned!", "WARN")
            self.gui_queue.put(("DONE", None))
        else:
            self.log(f"Queue Ready: {len(valid_ips)} IPs.", "SYS")
            self.launch_workers()

    def launch_workers(self):
        try:
            thread_count = int(self.threads_entry.get())
            kt = float(self.knock_timeout.get())
            qt = float(self.query_timeout.get())
            knock = bool(self.use_knock.get())
            strict = bool(self.strict_mode.get())
            targets = [x.strip().lower() for x in self.targets_box.get("0.0", "end").split(",") if x.strip()]
            
            self.lbl_status.configure(text="SCANNING...", text_color="#00E676")
            self.log(f"Launching {thread_count} workers...", "SYS")
            
            self.active_workers = 0
            
            for i in range(thread_count):
                self.active_workers += 1
                threading.Thread(target=self.worker_logic, args=(targets, kt, qt, knock, strict), daemon=True).start()
                
            threading.Thread(target=self.watchdog, daemon=True).start()
                
        except Exception as e:
            self.log(f"Launch Error: {e}", "ERR")

    def watchdog(self):
        while not self.stop_event.is_set():
            time.sleep(2)
            if self.work_queue.empty() and self.active_workers == 0:
                self.gui_queue.put(("DONE", None))
                break

    def worker_logic(self, targets, kt, qt, knock, strict):
        while not self.stop_event.is_set():
            try:
                try:
                    ip = self.work_queue.get(timeout=3)
                except queue.Empty:
                    break 
                
                try:
                    self._scan_single_ip(ip, targets, kt, qt, knock, strict)
                except Exception as e:
                    self.stats["errors"] += 1
                    self.update_stat("errors", self.stats["errors"])
                
                self.work_queue.task_done()
            except: pass
        
        self.active_workers -= 1

    def _scan_single_ip(self, ip, targets, kt, qt, knock, strict):
        def mark_scanned():
            try:
                with open("scanned.txt", "a") as f: f.write(ip + "\n")
            except: pass
            self.stats["checked"] += 1
            self.update_stat("checked", self.stats["checked"])

        if ":" in ip: host, port = ip.split(":"); port = int(port)
        else: host, port = ip, 25565
        
        if knock:
            s = None
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(kt)
                if s.connect_ex((host, port)) != 0:
                    s.close()
                    mark_scanned()
                    return
                s.close()
            except:
                if s: s.close()
                mark_scanned()
                return

        try:
            server = JavaServer(host, port, timeout=qt)
            status = server.query()
            
            raw = getattr(status.software, "plugins", [])
            p_list = [str(p).strip() for p in raw] if raw else []
            
            cleaned_plugins = [p for p in p_list if p.lower() not in IGNORED_DEFAULTS]
            
            is_hit = False
            found_targets = []
        
            if not cleaned_plugins:
                mark_scanned()
                return

            if not targets: 
                is_hit = True
                found_targets = cleaned_plugins
            else:
                found_targets = [p for p in cleaned_plugins if any(t in p.lower() for t in targets)]
                
                if strict:
                    if found_targets: is_hit = True
                else:
                    if cleaned_plugins: is_hit = True
            
            if is_hit:
                self.stats["hits"] += 1
                self.update_stat("hits", self.stats["hits"])
                display_str = ""
                if found_targets and strict:
                    display_str = ", ".join(found_targets)
                elif found_targets and not strict:
                     display_str = ", ".join(found_targets)
                else:
                    display_str = "Random/Other"

                self.log(f"[HIT] {ip} | {display_str}", "HIT")
                
                self.session_matches.append({'ip': ip, 'detected': found_targets if found_targets else ["Random/Other"]})
                
                with open("matches.txt", "a", encoding="utf-8") as f:
                    f.write(f"Server: {ip}\nAll Plugins: {', '.join(cleaned_plugins)}\nMatched: {display_str}\n\n")
        except: pass
        
        mark_scanned()

if __name__ == "__main__":
    app = DarkSearchUltraV5()
    app.mainloop()