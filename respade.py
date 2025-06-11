#!/usr/bin/env python3
"""
ReSpade (v1.09)

A Tkinter-based “Sam Spade” replacement with modern enhancements:

- Shared input field; single “About” menu item
- Whois (single/bulk)
- DNS lookup + Auth NS (ANY/A/AAAA/NS/MX/TXT/CNAME)
- Custom DNS server (auto-populated)
- Ping (IPv4/IPv6, 5 attempts)
- Traceroute (IPv4/IPv6, optional reverse lookups, skips private hops)
- IP Blocklist (DNSBL only)
- Reverse DNS
- Port Scan (common ports, IPv4/IPv6)
- Web Fetch (https→http fallback, raw/text, “No text…” message, blank-line collapse)
- robots.txt fetch
- SSL Info (certificate & cipher details)
- Co-hosted (reverse IP lookup via HackerTarget with API key or ThreatCrowd fallback, alphabetized)
- Save Output / Save as Evidence (with metadata)
- Download tab: non-HTML link discovery + checkbox / “Select All” / download
- Clear button to wipe the output pane

This code is dedicated to the public domain. No copyright is asserted.

Requires:
    pip install requests beautifulsoup4 python-whois
"""

import sys, platform, threading, subprocess, socket, re, datetime, ssl
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup
import whois

__version__ = "1.09"

# ─────────────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────────────
TLD_LIST     = ["com","net","org","io","co","us","uk","info","biz","xyz"]
COMMON_PORTS = [21,22,23,25,53,80,110,143,443,3306,8080]
DOWNLOAD_EXT = re.compile(
    r"\.(pdf|zip|jpg|jpeg|png|gif|docx?|xlsx?|pptx?|mp3|mp4|mov)(?:\?.*)?$",
    re.IGNORECASE
)

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────
def normalize_host(raw: str) -> str:
    p = urlparse(raw.strip())
    return p.netloc or p.path or ""

def get_default_dns() -> str:
    if platform.system()=="Windows":
        try:
            out=subprocess.check_output(["ipconfig","/all"], text=True, errors="ignore")
            for line in out.splitlines():
                if "DNS Servers" in line:
                    parts=line.split(":",1)
                    if len(parts)==2 and parts[1].strip():
                        return parts[1].strip()
        except: pass
    else:
        try:
            with open("/etc/resolv.conf") as f:
                for line in f:
                    if line.startswith("nameserver"):
                        return line.split()[1]
        except: pass
    return ""

def run_subprocess(cmd, append):
    try:
        p=subprocess.Popen(cmd, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, text=True)
    except Exception as e:
        append(f"Error running {cmd!r}: {e}\n"); return
    for line in p.stdout:
        append(line)
    p.wait()

def collapse_blank_lines(text: str) -> str:
    out, blank = [], 0
    for L in text.splitlines():
        if not L.strip():
            blank += 1
            if blank <= 2: out.append(L)
        else:
            blank = 0
            out.append(L)
    return "\n".join(out)

def local_ip() -> str:
    try:
        s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8",80))
        ip=s.getsockname()[0]
        s.close()
        return ip
    except:
        return socket.gethostbyname(socket.gethostname())

# ─────────────────────────────────────────────────────────────────────────────
# Core Functions
# ─────────────────────────────────────────────────────────────────────────────
def do_whois(dom, bulk, append):
    host=normalize_host(dom)
    if not host:
        append("⚠️ no domain provided\n"); return
    if bulk:
        append(f"Bulk WHOIS of “{host}” across {len(TLD_LIST)} TLDs\n\n")
        for tld in TLD_LIST:
            d=f"{host}.{tld}"
            append(f"=== WHOIS {d} ===\n")
            try:
                data=whois.whois(d)
                for k,v in data.items():
                    append(f"{k}: {v}\n")
            except Exception as e:
                append(f"Error: {e}\n")
            append("\n")
    else:
        append(f"WHOIS lookup for {host}\n")
        try:
            data=whois.whois(host)
            for k,v in data.items():
                append(f"{k}: {v}\n")
        except Exception as e:
            append(f"Error: {e}\n")

def do_dns_lookup(dom, server, record, append):
    host=normalize_host(dom)
    if not host:
        append("⚠️ no hostname\n"); return
    cmd=["nslookup",f"-type={record}",host]
    if server.strip(): cmd.append(server.strip())
    append(f"> {' '.join(cmd)}\n")
    run_subprocess(cmd, append)

def do_dns_ns(dom, server, append):
    append("\n")
    host=normalize_host(dom)
    if not host:
        append("⚠️ no hostname\n"); return
    cmd=["nslookup","-type=NS",host]
    if server.strip(): cmd.append(server.strip())
    append(f"> {' '.join(cmd)}\n")
    run_subprocess(cmd, append)

def do_ping(target, use_v6, append):
    host=normalize_host(target)
    if not host:
        append("⚠️ no target\n"); return
    cnt="5"; sys=platform.system()
    if use_v6:
        cmd=["ping","-6","-n",cnt,host] if sys=="Windows" else ["ping6","-c",cnt,host]
    else:
        cmd=["ping","-n",cnt,host] if sys=="Windows" else ["ping","-c",cnt,host]
    append(f"> {' '.join(cmd)}\n")
    run_subprocess(cmd, append)

_private=re.compile
_private_ranges=[
    _private(r"^10\."), _private(r"^127\."),
    _private(r"^192\.168\."), _private(r"^172\.(1[6-9]|2\d|3[0-1])\.")
]
def is_private(ip): return any(p.match(ip) for p in _private_ranges)

def do_traceroute(target, use_v6, rev_dns, append):
    host=normalize_host(target)
    if not host:
        append("⚠️ no target\n"); return
    sys=platform.system()
    if sys=="Windows":
        cmd=["tracert"]+(["-6"] if use_v6 else[])+(["-d"] if not rev_dns else[])+[host]
    else:
        cmd=["traceroute6",host] if use_v6 else ["traceroute","-n",host]
    append(f"> {' '.join(cmd)}\n")
    p=subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
    hops=[]
    for line in p.stdout:
        append(line)
        m=re.search(r"(\d+\.\d+\.\d+\.\d+)",line)
        if m: hops.append(m.group(1))
    p.wait()
    if rev_dns and sys!="Windows":
        append("\nReverse DNS on public hops:\n")
        for ip in hops:
            if not is_private(ip):
                try:
                    name=socket.gethostbyaddr(ip)[0]; append(f"{ip}: {name}\n")
                except:
                    append(f"{ip}: (no PTR)\n")

def do_ip_blocklist_check(raw, append):
    host=normalize_host(raw)
    if not host:
        append("⚠️ no target\n"); return
    try:
        ip=socket.gethostbyname(host)
        append(f"Resolved {host} → {ip}\n")
    except:
        append("Cannot resolve host\n"); return
    zones=["zen.spamhaus.org","bl.spamcop.net","dnsbl.sorbs.net"]
    append(f"Checking {ip} against DNSBLs:\n")
    for z in zones:
        q=".".join(reversed(ip.split(".")))+"."+z
        try: socket.gethostbyname(q); append(f" LISTED in {z}\n")
        except socket.gaierror: append(f" Not listed in {z}\n")

def do_reverse_dns(raw, append):
    host=normalize_host(raw)
    if not host:
        append("⚠️ no target\n"); return
    try:
        ip=socket.gethostbyname(host); append(f"Resolved {host} → {ip}\n")
        names=socket.gethostbyaddr(ip)
        append(f"{ip} → {names[0]}\n")
        for a in names[1]: append(f" alias: {a}\n")
    except Exception as e:
        append(f"Reverse DNS error: {e}\n")

def do_port_scan(raw, append):
    host=normalize_host(raw)
    if not host:
        append("⚠️ no target\n"); return
    try:
        ip=socket.gethostbyname(host); append(f"Resolved {host} → {ip}\n")
    except:
        append("Cannot resolve host\n"); return
    v6=":" in ip
    append(f"Port scanning {ip} on {len(COMMON_PORTS)} ports:\n")
    for p in COMMON_PORTS:
        try:
            fam=socket.AF_INET6 if v6 else socket.AF_INET
            s=socket.socket(fam,socket.SOCK_STREAM); s.settimeout(0.5)
            res=s.connect_ex((ip,p)); s.close()
            append(f" {p:>5}: {'OPEN' if res==0 else 'closed'}\n")
        except Exception as e:
            append(f" {p:>5}: error {e}\n")

def do_http_fetch(url, mode, append):
    if not url.strip():
        append("⚠️ no URL\n"); return
    if not url.startswith("http"):
        url="https://"+url
    append(f"GET {url}\n")
    try: r=requests.get(url,timeout=10)
    except:
        url=re.sub(r"^https://","http://",url)
        append(f"(https failed) GET {url}\n")
        try: r=requests.get(url,timeout=10)
        except Exception as e: append(f"Fetch failed: {e}\n"); return
    html=r.text
    if mode=="raw":
        append(html); return
    text=BeautifulSoup(html,"html.parser").get_text()
    if not text.strip():
        append("⚠️ No text found\n"); return
    append(collapse_blank_lines(text)+"\n")

def do_robots(raw, append):
    host=normalize_host(raw)
    if not host:
        append("⚠️ no host\n"); return
    base=host if host.startswith("http") else "https://"+host
    url=base.rstrip("/")+"/robots.txt"
    append(f"GET {url}\n")
    try: r=requests.get(url,timeout=10)
    except:
        url=re.sub(r"^https://","http://",url)
        append(f"(https failed) GET {url}\n")
        try: r=requests.get(url,timeout=10)
        except Exception as e: append(f"Fetch failed: {e}\n"); return
    if r.status_code==200:
        for L in r.text.splitlines(True): append(L)
    else:
        append(f"HTTP {r.status_code}\n")

def do_ssl_data(raw, append):
    host=normalize_host(raw)
    if not host:
        append("⚠️ no host\n"); return
    port=443
    append(f"Connecting to {host}:{port} for SSL info...\n")
    try:
        ctx=ssl.create_default_context()
        with socket.create_connection((host,port),timeout=5) as sock:
            with ctx.wrap_socket(sock,server_hostname=host) as ss:
                cert=ss.getpeercert()
                append("Certificate fields:\n")
                for k,v in cert.items():
                    append(f"  {k}: {v}\n")
                append(f"\nProtocol: {ss.version()}\nCipher: {ss.cipher()}\n")
    except Exception as e:
        append(f"SSL error: {e}\n")

def do_cohosted(raw, api_key, append):
    host=normalize_host(raw)
    if not host:
        append("⚠️ no host\n"); return
    try:
        ip=socket.gethostbyname(host)
        append(f"Resolved {host} → {ip}\n")
    except Exception as e:
        append(f"Resolution failed: {e}\n"); return
    # Try ThreatCrowd first (no key required)
    append("Using ThreatCrowd API (no key required)...\n")
    tc_url=f"https://www.threatcrowd.org/searchApi/v2/ip/report/?ip={ip}"
    try:
        r=requests.get(tc_url,timeout=10)
        data=r.json()
        res=data.get("resolutions") or []
        if not res:
            append("No hosts found via ThreatCrowd.\n")
        else:
            hosts=sorted({item["hostname"] for item in res})
            append("Co-hosted domains (ThreatCrowd):\n")
            for h in hosts:
                append(h+"\n")
    except Exception as e:
        append(f"ThreatCrowd error: {e}\n")

    # If API key provided, also try HackerTarget for more results
    if api_key.strip():
        append("\nUsing HackerTarget API for additional results...\n")
        url=f"https://api.hackertarget.com/reverseiplookup/?apikey={api_key.strip()}&q={ip}"
        append(f"Query: {url}\n")
        try:
            r=requests.get(url,timeout=10)
            text=r.text.strip()
            if text and "No records" not in text:
                hosts=text.splitlines()
                hosts=sorted(set(hosts))
                append("Additional co-hosted domains (HackerTarget):\n")
                for h in hosts:
                    append(h+"\n")
            else:
                append("No additional hosts via HackerTarget.\n")
        except Exception as e:
            append(f"HackerTarget error: {e}\n")

# ─────────────────────────────────────────────────────────────────────────────
# UI
# ─────────────────────────────────────────────────────────────────────────────
class ReSpade(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"ReSpade v{__version__}")
        self.geometry("920x660")

        menu=tk.Menu(self)
        menu.add_command(label="About",command=self.show_about)
        self.config(menu=menu)

        self.shared      = tk.StringVar()
        self.dns_srv     = tk.StringVar(value=get_default_dns())
        self.dns_record  = tk.StringVar(value="ANY")
        self.ipv6_var    = tk.BooleanVar(value=False)
        self.rev_dns_var = tk.BooleanVar(value=False)
        self.ht_api_key  = tk.StringVar()

        nb=ttk.Notebook(self)
        nb.pack(fill="both",expand=True)

        tabs=[
            ("Whois",        self.build_whois),
            ("DNS",          self.build_dns),
            ("Ping",         self.build_ping),
            ("Traceroute",   self.build_trace),
            ("IP Blocklist", self.build_blk),
            ("Reverse DNS",  self.build_rev_dns),
            ("Port Scan",    self.build_port_scan),
            ("Web Fetch",    self.build_web_fetch),
            ("Robots.txt",   self.build_robots),
            ("SSL Info",     self.build_ssl),
            ("Co-hosted",    self.build_cohosted),
            ("Downloads",    self.build_downloads),
        ]
        for name,builder in tabs:
            fr=ttk.Frame(nb); nb.add(fr,text=name); builder(fr)

    def show_about(self):
        messagebox.showinfo("About ReSpade",
            f"ReSpade v{__version__}\n"
            "This code is dedicated to the public domain.\n"
            "No copyright is asserted."
        )

    def _common_ui(self,parent):
        ttk.Entry(parent,textvariable=self.shared).pack(fill="x",padx=10,pady=5)
        btnf=ttk.Frame(parent); btnf.pack(fill="x",padx=10)
        run=ttk.Button(btnf,text="Run",width=10); run.pack(side="left")
        clear=ttk.Button(btnf,text="Clear",width=10); clear.pack(side="left",padx=5)
        copy=ttk.Button(btnf,text="Copy Output",width=15); copy.pack(side="left",padx=5)
        save=ttk.Button(btnf,text="Save Output",width=15); save.pack(side="left",padx=5)
        ev=ttk.Button(btnf,text="Save as Evidence",width=15); ev.pack(side="left",padx=5)

        txt=scrolledtext.ScrolledText(parent,wrap="word",font=("Consolas",10))
        txt.pack(fill="both",expand=True,padx=10,pady=5)

        clear.config(command=lambda: txt.delete("1.0","end"))
        copy.config(command=lambda: self._copy(txt.get("1.0","end")))
        save.config(command=lambda: self._save(txt.get("1.0","end")))
        ev.config(command=lambda: self._save_evidence(txt.get("1.0","end")))

        return txt,run

    def _copy(self,content):
        self.clipboard_clear(); self.clipboard_append(content)
        messagebox.showinfo("Copied","Output copied to clipboard")

    def _save(self,content):
        fn=filedialog.asksaveasfilename(defaultextension=".txt",
            filetypes=[("Text","*.txt"),("All","*.*")])
        if fn:
            with open(fn,"w",encoding="utf-8") as f: f.write(content)
            messagebox.showinfo("Saved",f"Output saved to {fn}")

    def _save_evidence(self,content):
        now=datetime.datetime.now()
        lines=[
            "=== ReSpade Evidence ===",
            f"Version: {__version__}",
            f"Local time: {now.isoformat()}",
            f"GMT time:   {datetime.datetime.utcnow().isoformat()}",
            f"Local IP:   {local_ip()}",
            f"Target/URL: {self.shared.get()}",
        ]
        try:
            ip=socket.gethostbyname(normalize_host(self.shared.get()))
            lines.append(f"Resolved IP: {ip}")
        except:
            lines.append("Resolved IP: (n/a)")
        lines.append("\n--- Output ---\n")
        body=content.strip() or "(no output)"
        lines.append(body)
        out="\n".join(lines)
        fn=filedialog.asksaveasfilename(defaultextension=".txt",
            filetypes=[("Text","*.txt"),("All","*.*")])
        if fn:
            with open(fn,"w",encoding="utf-8") as f: f.write(out)
            messagebox.showinfo("Saved","Evidence saved to "+fn)

    def build_whois(self,f):
        txt,run_btn=self._common_ui(f)
        run_btn.config(command=lambda:
            threading.Thread(target=lambda: do_whois(self.shared.get(),False,lambda l: txt.insert("end",l)),
                             daemon=True).start())
        ttk.Button(f,text="Bulk TLD Whois",command=lambda:
            threading.Thread(target=lambda:[
                txt.delete("1.0","end"),
                do_whois(self.shared.get(),True,lambda l:txt.insert("end",l))
            ],daemon=True).start()
        ).pack(anchor="w",padx=10,pady=(0,5))

    def build_dns(self,f):
        txt,run_btn=self._common_ui(f)
        run_btn.config(command=lambda:
            threading.Thread(target=lambda: do_dns_ns(self.shared.get(),
                                                      self.dns_srv.get(),
                                                      lambda l: txt.insert("end",l)),
                             daemon=True).start())
        frm=ttk.Frame(f); frm.pack(fill="x",padx=10)
        ttk.Label(frm,text="DNS Server:").pack(side="left")
        ttk.Entry(frm,textvariable=self.dns_srv,width=20).pack(side="left",padx=5)
        ttk.Label(frm,text="Record:").pack(side="left",padx=(10,0))
        opts=["ANY","A","AAAA","NS","MX","TXT","CNAME"]
        ttk.OptionMenu(frm,self.dns_record,*opts).pack(side="left",padx=5)
        btnf=ttk.Frame(f); btnf.pack(fill="x",padx=10,pady=(0,5))
        ttk.Button(btnf,text="Lookup",command=lambda:
            threading.Thread(target=lambda: do_dns_lookup(self.shared.get(),
                                                          self.dns_srv.get(),
                                                          self.dns_record.get(),
                                                          lambda l: txt.insert("end",l)),
                             daemon=True).start()
        ).pack(side="left")
        ttk.Button(btnf,text="Auth NS",command=lambda:
            threading.Thread(target=lambda: do_dns_ns(self.shared.get(),
                                                     self.dns_srv.get(),
                                                     lambda l: txt.insert("end",l)),
                             daemon=True).start()
        ).pack(side="left",padx=5)

    def build_ping(self,f):
        txt,run_btn=self._common_ui(f)
        ttk.Checkbutton(f,text="Use IPv6",variable=self.ipv6_var).pack(anchor="w",padx=10,pady=(0,5))
        run_btn.config(command=lambda:
            threading.Thread(target=lambda: do_ping(self.shared.get(),
                                                   self.ipv6_var.get(),
                                                   lambda l: txt.insert("end",l)),
                             daemon=True).start())

    def build_trace(self,f):
        txt,run_btn=self._common_ui(f)
        opts=ttk.Frame(f); opts.pack(fill="x",padx=10,pady=(0,5))
        ttk.Checkbutton(opts,text="Use IPv6",variable=self.ipv6_var).pack(side="left")
        ttk.Checkbutton(opts,text="Reverse DNS",variable=self.rev_dns_var).pack(side="left",padx=10)
        run_btn.config(command=lambda:
            threading.Thread(target=lambda: do_traceroute(self.shared.get(),
                                                         self.ipv6_var.get(),
                                                         self.rev_dns_var.get(),
                                                         lambda l: txt.insert("end",l)),
                             daemon=True).start())

    def build_blk(self,f):
        txt,run_btn=self._common_ui(f)
        run_btn.config(command=lambda:
            threading.Thread(target=lambda: do_ip_blocklist_check(self.shared.get(),
                                                                  lambda l: txt.insert("end",l)),
                             daemon=True).start())

    def build_rev_dns(self,f):
        txt,run_btn=self._common_ui(f)
        run_btn.config(command=lambda:
            threading.Thread(target=lambda: do_reverse_dns(self.shared.get(),
                                                          lambda l: txt.insert("end",l)),
                             daemon=True).start())

    def build_port_scan(self,f):
        txt,run_btn=self._common_ui(f)
        run_btn.config(command=lambda:
            threading.Thread(target=lambda: do_port_scan(self.shared.get(),
                                                        lambda l: txt.insert("end",l)),
                             daemon=True).start())

    def build_web_fetch(self,f):
        ttk.Entry(f,textvariable=self.shared).pack(fill="x",padx=10,pady=5)
        mode_var=tk.StringVar(value="text")
        rf=ttk.Frame(f); rf.pack(fill="x",padx=10)
        ttk.Radiobutton(rf,text="Text Only",variable=mode_var,value="text").pack(side="left")
        ttk.Radiobutton(rf,text="Raw HTML",variable=mode_var,value="raw").pack(side="left",padx=10)
        btnf=ttk.Frame(f); btnf.pack(fill="x",padx=10,pady=(5,0))
        run=ttk.Button(btnf,text="Run",width=10); ext=ttk.Button(btnf,text="Extract Links",width=15)
        copy=ttk.Button(btnf,text="Copy Output",width=15); save=ttk.Button(btnf,text="Save Output",width=15)
        ev=ttk.Button(btnf,text="Save as Evidence",width=15)
        run.pack(side="left"); ext.pack(side="left",padx=5)
        copy.pack(side="left",padx=5); save.pack(side="left",padx=5); ev.pack(side="left",padx=5)
        txt=scrolledtext.ScrolledText(f,wrap="word",font=("Consolas",10))
        txt.pack(fill="both",expand=True,padx=10,pady=5)

        def append(line):
            txt.insert("end",line); txt.see("end")

        def do_run():
            txt.delete("1.0","end")
            threading.Thread(target=lambda: do_http_fetch(self.shared.get(),
                                                         mode_var.get(),append),
                             daemon=True).start()

        def do_ext():
            txt.delete("1.0","end")
            def wk():
                do_http_fetch(self.shared.get(),"raw",lambda _:None)
                self._extract_links(self.shared.get(),append)
            threading.Thread(target=wk,daemon=True).start()

        run.config(command=do_run)
        ext.config(command=do_ext)
        copy.config(command=lambda:self._copy(txt.get("1.0","end")))
        save.config(command=lambda:self._save(txt.get("1.0","end")))
        ev.config(command=lambda:self._save_evidence(txt.get("1.0","end")))

    def build_robots(self,f):
        txt,run_btn=self._common_ui(f)
        run_btn.config(command=lambda:
            threading.Thread(target=lambda: do_robots(self.shared.get(),
                                                    lambda l: txt.insert("end",l)),
                             daemon=True).start())

    def build_ssl(self,f):
        txt,run_btn=self._common_ui(f)
        run_btn.config(command=lambda:
            threading.Thread(target=lambda: do_ssl_data(self.shared.get(),
                                                       lambda l: txt.insert("end",l)),
                             daemon=True).start())

    def build_cohosted(self,f):
        ttk.Label(f,text="HackerTarget API Key (optional; free endpoint no key up to ~50/day):"
        ).pack(anchor="w",padx=10,pady=(5,0))
        ttk.Entry(f,textvariable=self.ht_api_key).pack(fill="x",padx=10,pady=(0,5))
        txt,run_btn=self._common_ui(f)
        run_btn.config(command=lambda:
            threading.Thread(target=lambda: do_cohosted(self.shared.get(),
                                                       self.ht_api_key.get(),
                                                       lambda l: txt.insert("end",l)),
                             daemon=True).start())

    def _extract_links(self,url,append):
        u=url if url.startswith("http") else "https://"+url
        try: r=requests.get(u,timeout=10)
        except:
            u=re.sub(r"^https://","http://",u)
            r=requests.get(u,timeout=10)
        append("Links found:\n")
        for h in re.findall(r'href=["\'](.*?)["\']',r.text,flags=re.IGNORECASE):
            append(h+"\n")

    def build_downloads(self,f):
        txt,run_btn=self._common_ui(f)
        run_btn.pack_forget()
        ctl=ttk.Frame(f); ctl.pack(fill="x",padx=10,pady=5)
        fetch=ttk.Button(ctl,text="Fetch Files"); fetch.pack(side="left")
        allcb=tk.BooleanVar(value=False)
        sel=ttk.Checkbutton(ctl,text="Select All",variable=allcb); sel.pack(side="left",padx=10)
        lf=ttk.Frame(f); lf.pack(fill="both",expand=True,padx=10,pady=5)
        cvs=tk.Canvas(lf); cvs.pack(side="left",fill="both",expand=True)
        scr=ttk.Scrollbar(lf,orient="vertical",command=cvs.yview); scr.pack(side="right",fill="y")
        inner=ttk.Frame(cvs); inner.bind("<Configure>",lambda e:cvs.configure(scrollregion=cvs.bbox("all")))
        cvs.create_window((0,0),window=inner,anchor="nw"); cvs.configure(yscrollcommand=scr.set)
        link_vars=[]

        def fetch_files():
            for w in inner.winfo_children(): w.destroy()
            link_vars.clear()
            url=self.shared.get().strip()
            if not url:
                messagebox.showwarning("No URL","Please enter a URL."); return
            if not url.startswith("http"): url="https://"+url
            try: r=requests.get(url,timeout=10)
            except Exception as e:
                messagebox.showerror("Fetch error",str(e)); return
            hrefs=re.findall(r'href=["\'](.*?)["\']',r.text,flags=re.IGNORECASE)
            files=[h for h in hrefs if DOWNLOAD_EXT.search(h)]
            for link in files:
                var=tk.BooleanVar(); cb=ttk.Checkbutton(inner,text=link,variable=var)
                cb.pack(anchor="w"); link_vars.append((var,link))

        def toggle_all():
            s=allcb.get()
            for v,_ in link_vars: v.set(s)

        def download_sel():
            sel_links=[h for v,h in link_vars if v.get()]
            if not sel_links:
                messagebox.showinfo("None","No files selected."); return
            dst=filedialog.askdirectory()
            if not dst: return
            for h in sel_links:
                full=h if h.startswith("http") else requests.compat.urljoin(self.shared.get(),h)
                name=full.split("/")[-1].split("?")[0]
                fn=f"{dst}/{name}"
                try:
                    dl=requests.get(full,timeout=10)
                    with open(fn,"wb") as f: f.write(dl.content)
                except Exception as e:
                    messagebox.showwarning("Download failed",f"{full}: {e}")
            messagebox.showinfo("Done","Downloads complete.")

        fetch.config(command=lambda: threading.Thread(target=fetch_files,daemon=True).start())
        sel.config(command=toggle_all)
        ttk.Button(f,text="Download Selected",command=download_sel).pack(padx=10,pady=(0,5))

if __name__=="__main__":
    try:
        app=ReSpade()
        app.mainloop()
    except Exception as e:
        messagebox.showerror("Fatal Error",str(e))
        sys.exit(1)
