#!/usr/bin/env python3
"""VulnScanner Desktop App"""
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading, json, webbrowser, sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from core.scanner import ScanOrchestrator
from core.config import Config
from modules import NmapScanner, WaybackScanner, GAUScanner, HTTPXScanner
from reports import JSONReporter, HTMLReporter

class VulnScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("🛡️ VulnScanner Pro")
        self.root.geometry("1200x800")
        
        # Ultra-modern color palette
        self.bg_dark = "#0A0E27"
        self.bg_dark2 = "#10162F"
        self.bg_dark3 = "#1A1F3A"
        self.bg_card = "#141937"
        self.primary = "#6366F1"  # Modern indigo
        self.primary_hover = "#818CF8"
        self.primary_light = "#A5B4FC"
        self.accent = "#EC4899"   # Modern pink
        self.accent2 = "#8B5CF6"  # Vibrant purple
        self.accent3 = "#14B8A6"  # Teal accent
        self.success = "#10B981"
        self.danger = "#EF4444"
        self.warning = "#F59E0B"
        self.text_light = "#F1F5F9"
        self.text_gray = "#94A3B8"
        self.text_dim = "#64748B"
        self.border = "#1E293B"
        self.border_light = "#334155"
        
        # Animation state
        self.gradient_offset = 0
        self.scanning_dots = 0
        
        self.root.configure(bg=self.bg_dark)
        self.config = Config()
        self.results = None
        self.setup_styles()
        self.setup_ui()
        
    def setup_styles(self):
        """Setup modern dark theme styles"""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure dark theme
        style.configure(".", background=self.bg_dark2, foreground=self.text_light,
                       fieldbackground=self.bg_dark3, borderwidth=0)
        
        # Notebook (tabs) style - ultra-modern design
        style.configure("TNotebook", background=self.bg_dark, borderwidth=0, tabmargins=[15, 15, 15, 0])
        style.configure("TNotebook.Tab", 
                       background=self.bg_dark3, 
                       foreground=self.text_gray,
                       padding=[28, 14], 
                       font=("Segoe UI", 11, "bold"),
                       borderwidth=0)
        style.map("TNotebook.Tab", 
                 background=[("selected", self.bg_card), ("active", self.bg_dark3)],
                 foreground=[("selected", self.primary_light), ("active", self.text_light)])
        
        # Entry style
        style.configure("Dark.TEntry", fieldbackground=self.bg_dark3, foreground=self.text_light,
                       borderwidth=2, relief="flat", padding=10)
        
        # Frame style
        style.configure("Dark.TFrame", background=self.bg_dark2)
        style.configure("Card.TFrame", background=self.bg_dark2, relief="flat", borderwidth=1)
        
        # Radiobutton style
        style.configure("Dark.TRadiobutton", background=self.bg_dark2, foreground=self.text_light,
                       font=("Segoe UI", 10))
        style.map("Dark.TRadiobutton", background=[("active", self.bg_dark3)])
        
    def setup_ui(self):
        # Ultra-modern gradient header
        header = tk.Frame(self.root, bg=self.bg_dark2, height=90)
        header.pack(fill=tk.X)
        header.pack_propagate(False)
        
        # Modern multi-color accent line
        self.accent_line = tk.Frame(header, bg=self.primary, height=4)
        self.accent_line.pack(fill=tk.X)
        
        # Create vibrant gradient effect with more segments
        self.gradient_segments = []
        for i in range(12):
            seg = tk.Frame(self.accent_line, bg=self.primary, width=100, height=4)
            seg.place(relx=i/12, rely=0, relwidth=1/12, relheight=1)
            self.gradient_segments.append(seg)
        
        # Main header content
        header_content = tk.Frame(header, bg=self.bg_dark2)
        header_content.pack(fill=tk.BOTH, expand=True, padx=40, pady=20)
        
        # Left side - modern logo design
        left_frame = tk.Frame(header_content, bg=self.bg_dark2)
        left_frame.pack(side=tk.LEFT)
        
        # Logo with icon
        logo_container = tk.Frame(left_frame, bg=self.bg_dark2)
        logo_container.pack(side=tk.LEFT)
        
        # Modern logo with gradient-style text
        tk.Label(logo_container, text="🛡️", bg=self.bg_dark2, 
                font=("Segoe UI Emoji", 28)).pack(side=tk.LEFT, padx=(0, 15))
        
        title_container = tk.Frame(logo_container, bg=self.bg_dark2)
        title_container.pack(side=tk.LEFT)
        
        # Modern title with gradient color effect
        title_label = tk.Label(title_container, text="VulnScanner", bg=self.bg_dark2, fg=self.primary_light, 
                font=("Segoe UI", 18, "bold"))
        title_label.pack(anchor="w")
        
        tk.Label(title_container, text="Enterprise Security Platform", bg=self.bg_dark2, fg=self.text_gray,
                font=("Segoe UI", 9)).pack(anchor="w", pady=(3,0))
        
        # Start animations
        self.animate_gradient()
        
        # Modern tab navigation with better spacing
        tabs_container = tk.Frame(self.root, bg=self.bg_dark)
        tabs_container.pack(fill=tk.BOTH, expand=True)
        
        tabs = ttk.Notebook(tabs_container)
        tabs.pack(fill=tk.BOTH, expand=True, padx=20, pady=(10, 20))
        
        # Tab 1: Scan - Modern design
        scan_tab = ttk.Frame(tabs, style="Dark.TFrame")
        tabs.add(scan_tab, text="  🎯 SCAN  ")
        scan_tab.configure(style="Dark.TFrame")
        
        # Content frame with modern card design
        content_wrapper = tk.Frame(scan_tab, bg=self.bg_dark2)
        content_wrapper.pack(fill=tk.BOTH, expand=True, padx=40, pady=30)
        
        # Card container
        content_frame = tk.Frame(content_wrapper, bg=self.bg_card, 
                                highlightbackground=self.border, highlightthickness=1)
        content_frame.pack(fill=tk.BOTH, expand=True)
        
        # Inner content with padding
        inner_content = tk.Frame(content_frame, bg=self.bg_card)
        inner_content.pack(fill=tk.BOTH, expand=True, padx=40, pady=40)
        
        # Target section - modern with better labels
        tk.Label(inner_content, text="Target Domain", bg=self.bg_card, fg=self.text_light,
                font=("Segoe UI", 11, "bold")).pack(anchor="w", pady=(0,8))
        
        tk.Label(inner_content, text="Enter the target domain or IP address to scan", 
                bg=self.bg_card, fg=self.text_gray,
                font=("Segoe UI", 9)).pack(anchor="w", pady=(0,10))
        
        target_frame = tk.Frame(inner_content, bg=self.bg_dark3, 
                               highlightbackground=self.border, highlightthickness=1)
        target_frame.pack(fill=tk.X, pady=(0,30))
        
        self.target = tk.Entry(target_frame, font=("Segoe UI", 12), bg=self.bg_dark3,
                              fg=self.text_light, insertbackground=self.primary,
                              relief=tk.FLAT, bd=0, highlightthickness=1,
                              highlightcolor=self.primary, highlightbackground=self.border)
        self.target.pack(fill=tk.X, padx=15, pady=12)
        
        # Add glow effect on focus
        self.target.bind("<FocusIn>", lambda e: self.on_entry_focus(target_frame, True))
        self.target.bind("<FocusOut>", lambda e: self.on_entry_focus(target_frame, False))
        
        self.target.insert(0, "example.com")
        
        # Profile section - modern card style
        tk.Label(inner_content, text="Scan Profile", bg=self.bg_card, fg=self.text_light,
                font=("Segoe UI", 11, "bold")).pack(anchor="w", pady=(0,8))
        
        tk.Label(inner_content, text="Choose the scanning intensity and depth", 
                bg=self.bg_card, fg=self.text_gray,
                font=("Segoe UI", 9)).pack(anchor="w", pady=(0,10))
        
        self.profile = tk.StringVar(value="standard")
        profile_frame = tk.Frame(inner_content, bg=self.bg_card)
        profile_frame.pack(fill=tk.X, pady=(0,30))
        
        profiles = [
            ("⚡ Quick Scan", "quick", "Fast reconnaissance"),
            ("🎯 Standard Scan", "standard", "Balanced approach"),
            ("🔥 Deep Scan", "comprehensive", "Comprehensive analysis")
        ]
        
        for i, (text, val, desc) in enumerate(profiles):
            rb_card = tk.Frame(profile_frame, bg=self.bg_dark3,
                              highlightbackground=self.border, highlightthickness=1)
            rb_card.pack(fill=tk.X, pady=4)
            
            rb_inner = tk.Frame(rb_card, bg=self.bg_dark3)
            rb_inner.pack(fill=tk.X, padx=15, pady=10)
            
            rb = tk.Radiobutton(rb_inner, text=text, variable=self.profile, value=val,
                               bg=self.bg_dark3, fg=self.text_light, selectcolor=self.bg_dark3,
                               font=("Segoe UI", 10, "bold"), activebackground=self.bg_dark3,
                               activeforeground=self.primary, cursor="hand2", bd=0,
                               highlightthickness=0, indicatoron=True)
            rb.pack(side=tk.LEFT)
            
            tk.Label(rb_inner, text=desc, bg=self.bg_dark3, fg=self.text_gray,
                    font=("Segoe UI", 8)).pack(side=tk.RIGHT)
            
            # Add hover effect to profile cards
            rb_card.bind("<Enter>", lambda e, card=rb_card: card.config(highlightbackground=self.primary))
            rb_card.bind("<Leave>", lambda e, card=rb_card: card.config(highlightbackground=self.border))
        
        # Buttons - modern with proper styling
        btn_frame = tk.Frame(inner_content, bg=self.bg_card)
        btn_frame.pack(pady=20)
        
        # Modern start button with gradient-like styling
        self.start_container = tk.Frame(btn_frame, bg=self.primary, highlightthickness=0)
        self.start_container.pack(side=tk.LEFT, padx=10)
        
        self.start_btn = tk.Button(self.start_container, text="▶  Start Scan", command=self.start_scan,
                                   bg=self.primary, fg="#ffffff", font=("Segoe UI", 12, "bold"),
                                   padx=45, pady=15, cursor="hand2", relief=tk.FLAT, bd=0,
                                   highlightthickness=0, activebackground=self.primary_hover,
                                   activeforeground="#ffffff")
        self.start_btn.pack()
        
        # Bind hover effects
        self.start_btn.bind("<Enter>", lambda e: self.on_button_hover(self.start_container, True))
        self.start_btn.bind("<Leave>", lambda e: self.on_button_hover(self.start_container, False))
        
        # Modern stop button
        self.stop_container = tk.Frame(btn_frame, bg=self.bg_dark3,
                                 highlightbackground=self.danger, highlightthickness=2)
        self.stop_container.pack(side=tk.LEFT, padx=10)
        
        self.stop_btn = tk.Button(self.stop_container, text="⏹  Stop Scan", command=self.stop_scan,
                                  bg=self.bg_dark3, fg=self.danger, font=("Segoe UI", 12, "bold"),
                                  padx=45, pady=14, state=tk.DISABLED, relief=tk.FLAT, bd=0,
                                  cursor="hand2", highlightthickness=0)
        self.stop_btn.pack()
        
        # Bind hover effects
        self.stop_btn.bind("<Enter>", lambda e: self.on_stop_button_hover(True))
        self.stop_btn.bind("<Leave>", lambda e: self.on_stop_button_hover(False))
        
        # Status display - modern
        status_frame = tk.Frame(inner_content, bg=self.bg_dark3,
                               highlightbackground=self.border, highlightthickness=1)
        status_frame.pack(fill=tk.X, pady=20)
        
        status_inner = tk.Frame(status_frame, bg=self.bg_dark3)
        status_inner.pack(fill=tk.X, padx=15, pady=10)
        
        tk.Label(status_inner, text="Status:", bg=self.bg_dark3, fg=self.text_gray,
                font=("Segoe UI", 9, "bold")).pack(side=tk.LEFT, padx=(0, 10))
        
        self.status = tk.StringVar(value="Ready to scan")
        self.status_label = tk.Label(status_inner, textvariable=self.status, bg=self.bg_dark3, 
                               fg=self.text_light, font=("Segoe UI", 9))
        self.status_label.pack(side=tk.LEFT)
        
        # Progress bar - modern with better visibility
        progress_frame = tk.Frame(inner_content, bg=self.bg_card)
        progress_frame.pack(fill=tk.X, pady=10)
        
        style = ttk.Style()
        style.configure("Modern.Horizontal.TProgressbar", 
                       background=self.primary,
                       troughcolor=self.bg_dark3,
                       borderwidth=0,
                       thickness=6)
        self.progress = ttk.Progressbar(progress_frame, mode="indeterminate", length=600,
                                       style="Modern.Horizontal.TProgressbar")
        self.progress.pack(fill=tk.X, pady=5)
        
        # Tab 2: Results - Modern design
        results_tab = ttk.Frame(tabs, style="Dark.TFrame")
        tabs.add(results_tab, text="  📊 RESULTS  ")
        results_tab.configure(style="Dark.TFrame")
        
        # Toolbar - modern with better buttons
        toolbar = tk.Frame(results_tab, bg=self.bg_dark2)
        toolbar.pack(fill=tk.X, padx=30, pady=15)
        
        # Modern export section
        export_label = tk.Label(toolbar, text="EXPORT", bg=self.bg_dark2, fg=self.text_dim,
                font=("Segoe UI", 8, "bold"))
        export_label.pack(side=tk.LEFT, padx=(0, 15))
        
        # Modern button style with hover effects
        button_configs = [
            ("📄  JSON", lambda: self.save("json"), self.accent2), 
            ("🌐  HTML", lambda: self.save("html"), self.accent3),
            ("👁  View", self.view_browser, self.primary)
        ]
        
        for text, cmd, color in button_configs:
            btn_container = tk.Frame(toolbar, bg=self.bg_card,
                                    highlightbackground=self.border_light, highlightthickness=2)
            btn_container.pack(side=tk.LEFT, padx=6)
            
            btn = tk.Button(btn_container, text=text, command=cmd,
                     bg=self.bg_card, fg=color, font=("Segoe UI", 10, "bold"),
                     padx=18, pady=8, relief=tk.FLAT, bd=0, cursor="hand2",
                     activebackground=self.bg_dark3, activeforeground=self.primary_light)
            btn.pack()
            
            # Add hover effects
            btn.bind("<Enter>", lambda e, c=btn_container, col=color: c.config(highlightbackground=col))
            btn.bind("<Leave>", lambda e, c=btn_container: c.config(highlightbackground=self.border_light))
        
        # Results display - modern card
        results_frame = tk.Frame(results_tab, bg=self.bg_card,
                                highlightbackground=self.border, highlightthickness=1)
        results_frame.pack(fill=tk.BOTH, expand=True, padx=30, pady=(0,20))
        
        self.results_text = scrolledtext.ScrolledText(results_frame, font=("Consolas", 9),
                                                     wrap=tk.WORD, bg=self.bg_card,
                                                     fg=self.text_light, insertbackground=self.primary,
                                                     relief=tk.FLAT, padx=20, pady=20, bd=0,
                                                     highlightthickness=0)
        self.results_text.pack(fill=tk.BOTH, expand=True)
        self.results_text.insert("1.0", "No scan results yet. Run a scan to see results here.")
        self.results_text.config(state=tk.DISABLED)
        
        
    
    
    def animate_gradient(self):
        """Animate the modern gradient accent line"""
        try:
            # Modern vibrant gradient colors
            colors = [self.primary, self.primary_light, self.accent2, self.accent, self.accent3, self.primary]
            for i, seg in enumerate(self.gradient_segments):
                # Create smooth wave effect
                color_idx = int((i + self.gradient_offset) % len(colors))
                seg.config(bg=colors[color_idx])
            
            self.gradient_offset = (self.gradient_offset + 0.15) % len(colors)
            self.root.after(80, self.animate_gradient)
        except:
            pass
    
    
    def on_entry_focus(self, frame, focused):
        """Animate entry field on focus"""
        if focused:
            frame.config(highlightbackground=self.primary)
            if self.target.get() == "example.com":
                self.target.delete(0, tk.END)
        else:
            frame.config(highlightbackground=self.border)
    
    def on_button_hover(self, container, hover):
        """Animate button on hover"""
        if hover:
            # Glow effect
            container.config(bg=self.primary_hover)
        else:
            container.config(bg=self.primary)
    
    def on_stop_button_hover(self, hover):
        """Animate stop button on hover"""
        if hover and self.stop_btn['state'] != tk.DISABLED:
            # Danger glow effect
            self.stop_container.config(bg=self.accent)
        else:
            self.stop_container.config(bg=self.bg_dark3)
    
    def animate_scanning_text(self):
        """Animate scanning status text with rotating messages"""
        try:
            if hasattr(self, 'scanning_active') and self.scanning_active:
                messages = [
                    "🔍 Scanning", 
                    "🔎 Analyzing", 
                    "⚡ Processing",
                    "🎯 Discovering"
                ]
                msg_idx = (self.scanning_dots // 4) % len(messages)
                dots = "." * (self.scanning_dots % 4)
                self.status.set(f"{messages[msg_idx]}{dots}")
                self.scanning_dots += 1
                self.root.after(400, self.animate_scanning_text)
        except:
            pass
    
    def flash_progress_bar(self):
        """Flash the progress bar with modern colors"""
        try:
            if hasattr(self, 'scanning_active') and self.scanning_active:
                # Modern vibrant color cycling
                colors = [self.primary, self.primary_light, self.accent2, self.accent, self.accent3]
                color_idx = (self.scanning_dots // 2) % len(colors)
                style = ttk.Style()
                style.configure("Modern.Horizontal.TProgressbar", 
                               background=colors[color_idx],
                               troughcolor=self.bg_dark3,
                               borderwidth=0,
                               thickness=6)
                self.root.after(180, self.flash_progress_bar)
        except:
            pass
        
    def log(self, msg, animate=True):
        """Disabled logging"""
        pass
    
    
        
    def start_scan(self):
        target = self.target.get().strip()
        if not target or target == "example.com":
            messagebox.showerror("error", "invalid target")
            return
        
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.progress.start(10)
        
        # Start scanning animations
        self.scanning_active = True
        self.scanning_dots = 0
        self.animate_scanning_text()
        self.flash_progress_bar()
        
        
        self.log(f"🎯 Target: {target}")
        self.log("🚀 Initializing scan modules...")
        
        threading.Thread(target=self.run_scan, args=(target,), daemon=True).start()
        
    def run_scan(self, target):
        try:
            scanner = ScanOrchestrator(self.config)
            scanner.register_module("nmap", NmapScanner())
            scanner.register_module("httpx", HTTPXScanner())
            scanner.register_module("wayback", WaybackScanner())
            scanner.register_module("gau", GAUScanner())
            
            results = scanner.run_scan(target, profile=self.profile.get())
            self.results = results
            
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            fname = f"scan_{target.replace('.', '_')}_{ts}"
            json_path = self.config.get_output_path(fname, "json")
            html_path = self.config.get_output_path(fname, "html")
            
            JSONReporter().generate(results, json_path)
            HTMLReporter().generate(results, html_path)
            
            self.root.after(0, self.scan_done, results, json_path)
        except Exception as e:
            self.root.after(0, self.scan_error, str(e))
            
    def scan_done(self, results, path):
        # Stop animations
        self.scanning_active = False
        
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.progress.stop()
        self.status.set("✅ Scan Complete!")
        
        
        findings = results.get("summary", {}).get("total_findings", 0)
        duration = results.get("scan_duration", 0)
        self.log(f"✅ Scan complete: {duration:.1f}s")
        self.log(f"📊 Findings: {findings}")
        self.log(f"💾 Saved to: {path.parent}")
        
        self.display_results(results)
        messagebox.showinfo("complete", f"scan finished\n\nfindings: {findings}\ntime: {duration:.1f}s")
        
    def scan_error(self, error):
        # Stop animations
        self.scanning_active = False
        
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.progress.stop()
        self.status.set("❌ Error occurred")
        
        
        self.log(f"❌ Error: {error}")
        messagebox.showerror("error", f"scan failed\n\n{error}")
        
    def stop_scan(self):
        # Stop animations
        self.scanning_active = False
        
        self.log("⏹ Scan stopped by user")
        self.status.set("⏹ Stopped")
        self.progress.stop()
        
        
    def display_results(self, results):
        self.results_text.config(state=tk.NORMAL)
        self.results_text.delete("1.0", tk.END)
        
        # Header
        output = f"{'='*80}\n"
        output += f"🔍 VULNERABILITY SCAN RESULTS\n"
        output += f"{'='*80}\n\n"
        output += f"🎯 Target:   {results.get('target')}\n"
        output += f"⚙️  Profile:  {results.get('profile')}\n"
        output += f"⏱️  Duration: {results.get('scan_duration', 0):.2f}s\n"
        output += f"📅 Date:     {results.get('scan_date')}\n\n"
        
        # Summary
        summary = results.get("summary", {})
        output += f"{'='*80}\n"
        output += f"📊 SUMMARY\n"
        output += f"{'='*80}\n"
        output += f"✅ Successful Modules: {summary.get('successful_modules', 0)}\n"
        output += f"❌ Failed Modules:     {summary.get('failed_modules', 0)}\n"
        output += f"⚡ Total Findings:     {summary.get('total_findings', 0)}\n"
        
        # Module-specific summaries
        if summary.get('wayback_urls'):
            output += f"🔗 Wayback URLs:       {summary.get('wayback_urls', 0)}\n"
        if summary.get('gau_urls'):
            output += f"🌐 GAU URLs:           {summary.get('gau_urls', 0)}\n"
        
        output += f"\n{'='*80}\n"
        output += f"📋 DETAILED MODULE RESULTS\n"
        output += f"{'='*80}\n\n"
        
        # Detailed results per module
        for module, data in results.get("results", {}).items():
            status_icon = "✅" if data.get("status") == "success" else "❌"
            output += f"\n{'-'*80}\n"
            output += f"{status_icon} {module.upper()}\n"
            output += f"{'-'*80}\n"
            
            if data.get("status") == "success":
                # Parameters (highlighted for vulnerability testing)
                if data.get("parameters"):
                    vuln_params = ['id', 'file', 'page', 'url', 'path', 'redirect', 'view', 'cat', 'debug', 'admin']
                    params = data["parameters"]
                    param_urls = data.get("parameter_urls", {})
                    output += f"\n🎯 DISCOVERED PARAMETERS ({len(params)}):\n"
                    
                    # Separate vulnerable-looking params
                    vuln_found = [p for p in params if p.lower() in vuln_params]
                    normal_params = [p for p in params if p.lower() not in vuln_params]
                    
                    if vuln_found:
                        output += f"\n  ⚠️  POTENTIALLY VULNERABLE PARAMETERS:\n"
                        for param in vuln_found:
                            output += f"     🔴 {param}\n"
                            
                            # Show URLs containing this parameter
                            if param in param_urls and param_urls[param]:
                                output += f"\n        💥 VULNERABLE URLs to test:\n"
                                for url in param_urls[param][:10]:  # Show first 10
                                    output += f"        → {url}\n"
                                if len(param_urls[param]) > 10:
                                    output += f"        ... and {len(param_urls[param]) - 10} more URLs\n"
                                output += "\n"
                    
                    if normal_params:
                        output += f"\n  📌 Other Parameters:\n"
                        for param in normal_params[:20]:  # Limit display
                            output += f"     • {param}\n"
                            
                            # Show URLs containing this parameter
                            if param in param_urls and param_urls[param]:
                                for url in param_urls[param][:3]:  # Show first 3
                                    output += f"       → {url}\n"
                        if len(normal_params) > 20:
                            output += f"     ... and {len(normal_params) - 20} more\n"
                
                # URLs
                if data.get("total_urls"):
                    output += f"\n📄 Total URLs Found: {data['total_urls']}\n"
                
                # Subdomains
                if data.get("subdomains"):
                    subs = data["subdomains"]
                    output += f"\n🌐 Subdomains ({len(subs)}):\n"
                    for sub in subs[:15]:
                        output += f"   • {sub}\n"
                    if len(subs) > 15:
                        output += f"   ... and {len(subs) - 15} more\n"
                
                # Endpoints
                if data.get("endpoints"):
                    endpoints = data["endpoints"]
                    output += f"\n🔗 Discovered Endpoints ({len(endpoints)}):\n"
                    for ep in endpoints[:20]:
                        output += f"   • {ep}\n"
                    if len(endpoints) > 20:
                        output += f"   ... and {len(endpoints) - 20} more\n"
                
                # File extensions
                if data.get("file_extensions"):
                    output += f"\n📁 File Types:\n"
                    for ext, count in list(data["file_extensions"].items())[:10]:
                        output += f"   .{ext}: {count}\n"
                
                # Nmap - open ports
                if module == "nmap" and data.get("open_ports"):
                    ports = data["open_ports"]
                    output += f"\n🚪 Open Ports: {', '.join(map(str, ports)) if ports else 'None'}\n"
                    
                    if data.get("services"):
                        output += f"\n⚙️  Services:\n"
                        for svc in data["services"]:
                            output += f"   Port {svc.get('port')}: {svc.get('service')} {svc.get('version', '')}\n"
                
                # HTTPX
                if module == "httpx":
                    if data.get("live_hosts"):
                        output += f"\n✅ Live Hosts: {len(data['live_hosts'])}\n"
                    if data.get("technologies"):
                        output += f"🔧 Technologies: {', '.join(data['technologies'])}\n"
                
                # Statistics
                if data.get("statistics"):
                    output += f"\n📈 Statistics:\n"
                    for key, val in data["statistics"].items():
                        label = key.replace('_', ' ').title()
                        output += f"   {label}: {val}\n"
                
                # Execution time
                if data.get("execution_time"):
                    output += f"\n⏱️  Execution Time: {data['execution_time']:.3f}s\n"
                    
            else:
                # Error
                output += f"\n❌ Error: {data.get('error', 'Unknown error')}\n"
                if data.get("execution_time"):
                    output += f"⏱️  Execution Time: {data['execution_time']:.3f}s\n"
        
        output += f"\n{'='*80}\n"
        output += f"✅ Scan Complete!\n"
        output += f"{'='*80}\n"
        
        self.results_text.insert("1.0", output)
        self.results_text.config(state=tk.DISABLED)
        
    def save(self, fmt):
        if not self.results:
            messagebox.showwarning("No Results", "No results to save")
            return
        
        ftypes = [("JSON", "*.json")] if fmt == "json" else [("HTML", "*.html")]
        fname = filedialog.asksaveasfilename(defaultextension=f".{fmt}", filetypes=ftypes)
        if fname:
            reporter = JSONReporter() if fmt == "json" else HTMLReporter()
            reporter.generate(self.results, Path(fname))
            messagebox.showinfo("Saved", f"Saved to:\n{fname}")
            self.log(f"💾 Saved {fmt.upper()} report: {fname}")
            
    def view_browser(self):
        if not self.results:
            messagebox.showwarning("No Results", "No results to view")
            return
        temp = self.config.REPORTS_DIR / "temp_view.html"
        HTMLReporter().generate(self.results, temp)
        webbrowser.open(str(temp))
        self.log("🌐 Opened report in browser")

if __name__ == "__main__":
    root = tk.Tk()
    app = VulnScannerApp(root)
    root.mainloop()
