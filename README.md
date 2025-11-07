# 🛡️ VulnScanner Pro

Modern security vulnerability scanner with beautiful dark-themed web interface.

## 🚀 Quick Start

### **Web Interface (Recommended)**
```bash
python start_web.bat
# Open: http://localhost:5000
```

### **Desktop App**
```bash
python start_app.bat
```

### **Command Line**
```bash
python scanner.py example.com
```

---

## ✨ Features

- 🎨 Modern dark theme with sidebar navigation
- 🔍 Detailed scan results with vulnerable URLs
- 🔴 Automatic vulnerable parameter identification
- 📋 Click-to-copy vulnerable endpoints
- ⏰ Scheduled scans
- 📊 Real-time dashboard

### **Scanning Modules**
- Nmap - Port scanning
- HTTPX - HTTP probing
- Wayback - Historical URLs
- GAU - URL collection
- Shodan - IoT search (API key required)
- Censys - Internet scanning (API key required)

---

## 📦 Installation

```bash
# Install Python requirements
pip install -r requirements-web.txt

# Optional: Install external tools
# - Nmap: https://nmap.org/download.html
# - Go tools: httpx, gau, waybackurls
```

---

## 🔍 Understanding Results

When a scan completes, you'll see:

```
🔴 id parameter

   💥 VULNERABLE URLs to test:
   → http://example.com/page.php?id=1
   → http://example.com/page.php?id=2
```

**Red badges (🔴)** = potentially vulnerable parameters

---

## 📝 License

MIT License

---

**Happy Scanning! 🔍**
