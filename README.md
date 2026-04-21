# 🗺️ MalwareMap

> A high-performance, real-time threat intelligence dashboard for security analysts. Unified threat data from multiple sources in one beautiful, interactive interface.

![Python](https://img.shields.io/badge/Python-3.9+-3776ab?logo=python&logoColor=white)
![Streamlit](https://img.shields.io/badge/Streamlit-1.28+-FF4B4B?logo=streamlit&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?logo=github)

---

## 🎯 Features

✨ **Multi-Source Threat Intelligence**
- 🔍 [MalwareBazaar](https://bazaar.abuse.ch/) - Latest malware hashes
- 🛡️ [AbuseIPDB](https://www.abuseipdb.com/) - Malicious IP addresses
- 🔗 [AlienVault OTX](https://otx.alienvault.com/) - Open Threat Exchange indicators

📊 **Advanced Analytics**
- Global threat heatmap with geolocation visualization
- Risk-based filtering (0-100 score)
- IOC distribution charts (types, sources)
- MITRE ATT&CK integration
- First/Last seen timestamps

🎨 **Modern UI/UX**
- Dark-mode with animated Vanta.js background
- Responsive design with compact buttons
- Smooth gradients and hover effects
- Real-time data synchronization

🔗 **One-Click Analysis**
- VirusTotal integration for hashes
- AbuseIPDB lookup for IPs
- URLhaus search for domains
- Direct external threat platform links

📋 **Data Management**
- SQLite database with WAL mode for performance
- CSV export functionality
- Advanced search & filtering
- Batch IOC operations

---

## 🚀 Quick Start

### Prerequisites
- Python 3.9+
- pip or conda

### Installation

```bash
# Clone the repository
git clone https://github.com/n4cr0t1c/malmap.git
cd malmap

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Configuration

Create a `.env` file in the root directory:

```env
ABUSEIPDB_API_KEY=your_api_key_here
ALIENVAULT_API_KEY=your_api_key_here
```

**Getting API Keys:**
- [AbuseIPDB](https://www.abuseipdb.com/register) - Free tier available
- [AlienVault OTX](https://otx.alienvault.com/) - Free with account
- MalwareBazaar - Public access (no key required initially)

### Running the App

```bash
streamlit run dashboard.py
```

The app will open at `http://localhost:8501`

---

## 📊 Dashboard Sections

### 1️⃣ **Threat Summary**
- Total IOCs in database
- High-risk threats (≥75 score)
- Active data sources
- Last sync timestamp

### 2️⃣ **Global Threat Map**
- Interactive world map with threat indicators
- Size/color represents risk level
- Hover for IOC details
- Up to 900 points for performance

### 3️⃣ **Threat Distribution**
- IOC type breakdown (pie chart)
- Source comparison (bar chart)
- Top threat categories

### 4️⃣ **IOC Repository**
- Searchable database of all indicators
- Risk-scored entries
- MITRE classification
- Associated tags
- Quick-link analysis buttons
- CSV export

### 5️⃣ **Filters** (Sidebar)
- Filter by IOC type (hash, IP, domain, URL)
- Filter by source (MalwareBazaar, AbuseIPDB, OTX)
- Risk score range slider
- API connection status
- Clear database option

---

## 🛠️ API Integration

### MalwareBazaar
```python
refresh_from_malwarebazaar(limit=100)
# Returns recent malware samples (SHA256 hashes)
```

### AbuseIPDB
```python
refresh_from_abuseipdb(limit=100)
# Returns confirmed malicious IP addresses
# Rate-limited: ~1000 requests/day (free tier)
```

### AlienVault OTX
```python
refresh_from_alienvault(limit=50)
# Returns threat pulses with indicators
# Requires API key but free tier available
```

---

## 📁 Project Structure

```
malmap/
├── dashboard.py         # Main Streamlit app
├── database.py          # SQLite operations & IOC storage
├── requirements.txt     # Python dependencies
├── .env                 # API keys (DO NOT COMMIT)
├── .gitignore          # Git ignore patterns
├── iocs.db             # Local threat database (auto-created)
└── README.md           # This file
```

---

## 🔒 Security Best Practices

**Never commit to GitHub:**
- ✋ `.env` file with API keys
- ✋ `iocs.db` database file
- ✋ `venv/` virtual environment
- ✋ `__pycache__/` compiled Python

**Use `.gitignore`** to automatically exclude sensitive files.

**Rotate API Keys** regularly and regenerate if accidentally exposed.

---

## 📊 Database Schema

The SQLite database stores threat indicators:

```sql
CREATE TABLE iocs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    value           TEXT UNIQUE NOT NULL,
    type            TEXT NOT NULL,              -- hash, ip, domain, url
    source          TEXT NOT NULL,              -- bazaar, abuseipdb, otx
    tags            TEXT,                       -- comma-separated
    mitre_id        TEXT,                       -- MITRE ATT&CK ID
    mitre_name      TEXT,                       -- MITRE name/category
    risk_score      INTEGER DEFAULT 50,        -- 0-100
    first_seen      DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen       DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

---

## 🎨 Customization

### Change Color Scheme
Edit the CSS variables in `dashboard.py`:
```python
:root{
  --bg: #060606;              # Dark background
  --red: #ff2a2a;             # Primary accent
  --text: #f2f2f2;            # Text color
}
```

### Add New Data Source
Add a new `refresh_from_source()` function following the pattern in `dashboard.py` and register it in the refresh button.

### Adjust Risk Scoring
Modify risk score calculations in the source integration functions.

---

## 🐛 Troubleshooting

### **API Rate Limiting (429 Error)**
- Good news: Built-in rate limit handling!
- Wait a few minutes and retry
- Consider upgrading API tier for higher limits

### **Authentication Error (401)**
- Verify API keys in `.env`
- Check key hasn't expired
- Regenerate key from provider dashboard

### **Database Locked**
WAL mode prevents this, but if it occurs:
```bash
rm iocs.db-wal iocs.db-shm
```

### **Slow Performance**
- Clear old IOCs: "Clear DB" button in sidebar
- Reduce filter scope
- Heatmap capped at 900 points for performance

---

## 📈 Performance Tips

1. **Filter by Risk Score** - Focus on dangerous threats first
2. **Use Source Filters** - Narrow to your trusted sources
3. **Regular Cleanup** - Clear database weekly to reduce bloat
4. **Limit API Calls** - Respect rate limits, cache results
5. **Export Data** - CSV export for offline analysis

---

## 🤝 Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Commit changes
4. Submit a pull request

---

## 📝 License

MIT License - See LICENSE file for details

---

## 👤 Author

**n4cr0t1c** - [GitHub](https://github.com/n4cr0t1c)

---

## ⚠️ Disclaimer

MalwareMap is for **authorized security use only**. The author is not responsible for misuse. Always respect terms of service for third-party APIs and data sources.

---

## 🔗 Links

- 📚 [Streamlit Docs](https://docs.streamlit.io/)
- 🛡️ [Threat Intelligence Best Practices](https://attack.mitre.org/)
- 📊 [CVSS Scoring](https://www.first.org/cvss/)

---

**Last Updated:** April 2026 | **Version:** 1.0.0
