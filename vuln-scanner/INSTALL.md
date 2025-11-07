# Installation Guide

Complete installation guide for the Vulnerability Scanner & Recon Framework.

## Table of Contents
- [System Requirements](#system-requirements)
- [Python Dependencies](#python-dependencies)
- [External Tools](#external-tools)
- [API Keys Setup](#api-keys-setup)
- [Verification](#verification)
- [Troubleshooting](#troubleshooting)

---

## System Requirements

### Minimum Requirements
- **OS:** Linux, macOS, or Windows 10/11
- **Python:** 3.8 or higher
- **RAM:** 2GB minimum, 4GB recommended
- **Disk Space:** 500MB for installation + space for reports
- **Network:** Internet connection for API calls and tool downloads

### Recommended Tools
- Git (for cloning repository)
- Go 1.16+ (for installing go-based tools)
- nmap (for port scanning)

---

## Python Dependencies

### Step 1: Clone Repository
```bash
git clone https://github.com/yourusername/vuln-scanner.git
cd vuln-scanner
```

### Step 2: Create Virtual Environment (Recommended)
```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Linux/macOS:
source venv/bin/activate

# On Windows:
venv\Scripts\activate
```

### Step 3: Install Python Packages
```bash
# Install from requirements.txt
pip install -r requirements.txt

# Or install with setup.py
pip install -e .
```

### Verify Python Installation
```bash
python --version  # Should be 3.8 or higher
pip list | grep -E "requests|shodan|censys|rich"
```

---

## External Tools

### 1. Nmap Installation

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install nmap -y
```

**macOS:**
```bash
brew install nmap
```

**Windows:**
1. Download from: https://nmap.org/download.html
2. Run the installer
3. Add to PATH: `C:\Program Files (x86)\Nmap`

**Verify:**
```bash
nmap --version
```

### 2. Go Installation (Required for waybackurls, gau, httpx)

**Ubuntu/Debian:**
```bash
wget https://go.dev/dl/go1.21.0.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin
```

**macOS:**
```bash
brew install go
```

**Windows:**
1. Download from: https://go.dev/dl/
2. Run installer
3. Verify: `go version`

**Add to shell profile:**
```bash
# Add to ~/.bashrc or ~/.zshrc
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin
```

### 3. Install waybackurls
```bash
go install github.com/tomnomnom/waybackurls@latest
```

### 4. Install gau (GetAllURLs)
```bash
go install github.com/lc/gau/v2/cmd/gau@latest
```

### 5. Install httpx
```bash
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
```

### Verify Go Tools
```bash
waybackurls --help
gau --help
httpx -version
```

**Troubleshooting Go Tools:**
If tools are not found:
```bash
# Check GOPATH
echo $GOPATH

# Verify binaries exist
ls $GOPATH/bin

# Ensure GOPATH/bin is in PATH
export PATH=$PATH:$(go env GOPATH)/bin
```

---

## API Keys Setup

### 1. Shodan API Key

**Sign Up:**
1. Visit: https://account.shodan.io/register
2. Free tier: 100 queries/month
3. Get API key: https://account.shodan.io/

**Configure:**
```bash
# Edit .env file
cp .env.example .env
nano .env
```

Add your key:
```env
SHODAN_API_KEY=your_actual_api_key_here
```

**Test:**
```bash
python -c "from modules.shodan_api import ShodanAPI; api = ShodanAPI('YOUR_KEY'); print(api.get_api_info())"
```

### 2. Censys API Credentials

**Sign Up:**
1. Visit: https://censys.io/register
2. Free tier: 250 queries/month
3. Get API credentials: https://censys.io/account/api

**Configure:**
```env
CENSYS_API_ID=your_api_id_here
CENSYS_API_SECRET=your_api_secret_here
```

**Test:**
```bash
python -c "from modules.censys_api import CensysAPI; api = CensysAPI('ID', 'SECRET'); print(api.get_account_info())"
```

### 3. Optional: Other APIs

The scanner works without these, but they enhance functionality:

- **VirusTotal:** https://www.virustotal.com/gui/my-apikey
- **AlienVault OTX:** https://otx.alienvault.com/
- **GitHub Token:** https://github.com/settings/tokens

---

## Verification

### Run Dependency Check
```bash
python scanner.py --check-deps
```

Expected output:
```
✓ nmap
✓ waybackurls
✓ gau
✓ httpx
✓ Shodan API configured
✓ Censys API configured
```

### Test Basic Scan
```bash
python scanner.py -t example.com -m httpx -v
```

### Test Full Scan
```bash
python scanner.py -t scanme.nmap.org --full -o html
```

---

## Troubleshooting

### Issue: "ModuleNotFoundError: No module named 'X'"
**Solution:**
```bash
pip install -r requirements.txt --force-reinstall
```

### Issue: "nmap not found"
**Solution:**
- Verify installation: `which nmap` or `where nmap`
- Add to PATH or reinstall nmap
- On Linux: `sudo apt install nmap`

### Issue: "waybackurls: command not found"
**Solution:**
```bash
# Verify Go installation
go version

# Reinstall tool
go install github.com/tomnomnom/waybackurls@latest

# Check PATH
export PATH=$PATH:$(go env GOPATH)/bin

# Add to shell profile permanently
echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.bashrc
source ~/.bashrc
```

### Issue: "Permission denied" on Linux
**Solution:**
```bash
# Some scans need elevated privileges
sudo python scanner.py -t target.com -m nmap

# Or make scanner executable
chmod +x scanner.py
```

### Issue: API rate limiting
**Solution:**
- Wait for quota reset (usually 24 hours)
- Upgrade to paid tier
- Use multiple API keys (configure in database)

### Issue: Slow scans
**Solution:**
```bash
# Increase threads
python scanner.py -t target.com --threads 10

# Use quick profile
python scanner.py -t target.com -p quick

# Run specific modules only
python scanner.py -t target.com -m httpx,wayback
```

### Issue: Timeout errors
**Solution:**
```bash
# Increase timeout
python scanner.py -t target.com --timeout 60

# Check network connection
ping target.com
```

---

## Platform-Specific Notes

### Windows
- Use PowerShell or CMD (not Git Bash for some commands)
- Add tools to system PATH via Environment Variables
- Some nmap scans require Administrator privileges

### macOS
- Install Homebrew first: https://brew.sh
- May need to allow nmap in Security & Privacy settings
- Use `sudo` for privileged port scans

### Linux
- Preferred platform for all tools
- Use `sudo` for scans below port 1024
- Ensure firewall allows outbound connections

---

## Next Steps

After successful installation:

1. **Read the README:** Understand all features and usage
2. **Configure API Keys:** Get free API keys for enhanced scanning
3. **Run Test Scan:** Try `python scanner.py -t scanme.nmap.org`
4. **Explore Profiles:** Test quick, standard, and comprehensive scans
5. **Generate Reports:** Try both JSON and HTML outputs

## Support

- **Issues:** https://github.com/yourusername/vuln-scanner/issues
- **Documentation:** See README.md
- **Community:** Join our Discord/Slack

---

**Installation complete! Happy scanning! 🚀**
