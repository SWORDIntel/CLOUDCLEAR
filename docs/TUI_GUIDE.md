# CloudClear TUI - User Guide

## Overview

CloudClear TUI provides an interactive terminal user interface for advanced origin IP detection behind Cloudflare and other CDN services. The TUI offers real-time progress tracking, interactive results browsing, and comprehensive candidate analysis.

---

## 🎨 Features

### ✨ Real-Time Progress Display
- Live phase tracking with progress bars
- Current action display for each phase
- Items found counter
- Elapsed time tracking

### 🔍 Interactive Results Browser
- Keyboard navigation through candidates
- Color-coded confidence scores
- Ranked results by confidence
- Quick filtering and sorting

### 📊 Detailed Candidate View
- Complete IP information
- Confidence score breakdown
- Discovery method details
- Supporting evidence list
- ASN and network information

### 📈 Live Statistics
- Total IPs found
- Subdomains discovered
- Techniques attempted/successful
- Success rate percentage
- Scan duration

### 🎨 Beautiful Interface
- ASCII art logo
- Color-coded status indicators
- Progress bars with animations
- Clean, organized layout

---

## 🚀 Quick Start

### Installation

```bash
# Install dependencies
make deps

# Build TUI version
make tui

# Run
./cloudunflare-tui
```

### First Launch

1. **Welcome Screen** - Press any key to continue
2. **Input Screen** - Enter target domain (e.g., example.com)
3. **Scanning Screen** - Watch real-time progress
4. **Results Screen** - Browse and analyze results

---

## ⌨️ Keyboard Shortcuts

### Navigation
- `↑` / `k` - Move up
- `↓` / `j` - Move down
- `ENTER` - Select / View details
- `ESC` - Go back / Cancel

### Actions
- `Q` - Quit application
- `H` - Show help screen
- `SPACE` - Pause/Resume (scanning screen)

### Results Screen
- `↑/↓` - Navigate candidates
- `ENTER` - View candidate details
- `H` - Show help
- `Q` - Quit

### Candidate Detail Screen
- Any key - Return to results

---

## 🖥️ Screen Layouts

### Welcome Screen

```
   _____ _                 _  _____ _
  / ____| |               | |/ ____| |
 | |    | | ___  _   _  __| | |    | | ___  __ _ _ __
 | |    | |/ _ \| | | |/ _` | |    | |/ _ \/ _` | '__|
 | |____| | (_) | |_| | (_| | |____| |  __/ (_| | |
  \_____|_|\___/ \__,_|\__,_|\_____| _|\___|\ __,_|_|

        Advanced CDN Origin IP Detection v2.0

═══ Features ═══

✓ SSL Certificate Comparison
✓ Advanced MX Record Enumeration
✓ SRV Record Discovery (20+ services)
✓ Cloudflare Bypass Detection
✓ ASN Network Clustering
✓ Reverse DNS Intelligence
✓ Passive DNS Integration
✓ WHOIS Netblock Discovery

Press any key to continue...
```

### Scanning Screen

```
┌─────────────────────────────────────────────────────────────┐
│ CloudClear - Advanced IP Detection | example.com            │
└─────────────────────────────────────────────────────────────┘

┌─ Scan Progress ──────────────┐ ┌─ Statistics ──────────────┐
│                               │ │                            │
│ [1/8] DNS Reconnaissance      │ │ Scan Statistics            │
│   [DONE]                      │ │                            │
│   Found: 3 items              │ │ Target Domain: example.com │
│                               │ │                            │
│ [2/8] Certificate Transparency│ │ Scan Duration: 1m 23s      │
│   [RUNNING]                   │ │                            │
│   Progress [========>      ]  │ │ Origin IP Candidates: 0    │
│   -> Found subdomain #5       │ │ Total IPs Found: 3         │
│                               │ │ Subdomains Found: 25       │
│ [3/8] Subdomain Enumeration   │ │                            │
│   [PENDING]                   │ │ Techniques Attempted: 2    │
│                               │ │ Successful Techniques: 2   │
│ [4/8] OSINT Gathering         │ │ Success Rate: 100%         │
│   [PENDING]                   │ │                            │
│                               │ │                            │
│ ...                           │ │                            │
└───────────────────────────────┘ └────────────────────────────┘

┌───────────────────────────────────────────────────────────┐
│ Scanning in progress... Please wait                        │
└───────────────────────────────────────────────────────────┘
```

### Results Screen

```
┌─────────────────────────────────────────────────────────────┐
│ CloudClear - Scan Results | example.com | 5 candidates found│
└─────────────────────────────────────────────────────────────┘

┌─ Origin IP Candidates (Ranked by Confidence) ───────────────┐
│                                                              │
│>  1. 192.0.2.100       95% (VERIFIED)      MX Record + SSL  │
│   2. 192.0.2.101       85% (VERY LIKELY)   SRV Discovery    │
│   3. 192.0.2.102       75% (LIKELY)        Bypass Subdomain │
│   4. 192.0.2.103       70% (LIKELY)        PTR Match        │
│   5. 192.0.2.104       65% (POSSIBLE)      CT Logs          │
│                                                              │
│                                                              │
│                                                              │
│                                                              │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│ ↑/↓: Navigate  ENTER: Details  Q: Quit                       │
└──────────────────────────────────────────────────────────────┘
```

### Candidate Detail Screen

```
┌─────────────────────────────────────────────────────────────┐
│ Origin IP Candidate Details | Candidate #1 - 192.0.2.100    │
└─────────────────────────────────────────────────────────────┘

┌─ Detailed Information ───────────────────────────────────────┐
│                                                              │
│ IP Address:                                                  │
│   192.0.2.100                                               │
│                                                              │
│ Confidence Score:                                            │
│   95% (VERIFIED)                                            │
│                                                              │
│ Primary Discovery Method:                                    │
│   MX Record Analysis                                        │
│                                                              │
│ Network Information:                                         │
│   ASN: AS12345                                              │
│   AS Name: EXAMPLE-HOSTING Example Hosting Inc.            │
│   Hosting: Example Hosting Inc.                             │
│                                                              │
│ Supporting Evidence (5):                                     │
│   ✓ MX Record Analysis                                      │
│   ✓ MX Record PTR Match                                     │
│   ✓ Cloudflare Bypass Subdomain                             │
│   ✓ SSL Certificate Match (95%)                             │
│   ✓ PTR Record Match                                        │
│                                                              │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│ Press any key to return to results...                        │
└──────────────────────────────────────────────────────────────┘
```

---

## 🎯 Phase Descriptions

### Phase 1: DNS Reconnaissance
- Basic A/AAAA record lookups
- Initial IP discovery
- Domain resolution verification

### Phase 2: Certificate Transparency
- Mining CT logs (crt.sh)
- Subdomain discovery from certificates
- Certificate chain analysis

### Phase 3: Subdomain Enumeration
- Multi-threaded scanning (100+ subdomains)
- Wordlist-based discovery
- Pattern-based enumeration

### Phase 4: OSINT Gathering
- ViewDNS IP history
- CompleteDNS records
- Historical data collection

### Phase 5: MX Record Analysis
- Mail server enumeration
- Reverse DNS lookups
- Infrastructure correlation

### Phase 6: SRV Record Discovery
- 20+ service types queried
- Internal service discovery
- Direct IP identification

### Phase 7: SSL Certificate Testing
- Direct IP HTTPS connections
- Certificate comparison
- Origin server validation

### Phase 8: ASN Clustering
- Autonomous System Number lookup
- BGP prefix identification
- Network infrastructure mapping

---

## 📊 Color Legend

### Status Colors
- 🟢 **GREEN** - Completed successfully
- 🟡 **YELLOW** - In progress / Warning
- 🔵 **BLUE** - Information / Pending
- 🔴 **RED** - Failed / Error
- 🟦 **CYAN** - Headers / Highlights

### Confidence Colors
- 🟢 **GREEN** - 90-100% (VERIFIED)
- 🟡 **YELLOW** - 70-89% (LIKELY)
- 🔵 **BLUE** - 0-69% (POSSIBLE)

---

## 🔧 Advanced Usage

### Command Line Options

```bash
# Launch TUI mode (default)
./cloudunflare-tui

# Show help
./cloudunflare-tui --help

# CLI mode (if available)
./cloudunflare-tui --cli
```

### Environment Variables

```bash
# Adjust terminal colors
export TERM=xterm-256color

# Increase scrollback
export LINES=50
export COLUMNS=120
```

---

## 🐛 Troubleshooting

### Display Issues

**Problem**: Colors not showing
```bash
# Solution: Check terminal color support
echo $TERM
export TERM=xterm-256color
```

**Problem**: Characters not rendering correctly
```bash
# Solution: Use UTF-8 locale
export LANG=en_US.UTF-8
export LC_ALL=en_US.UTF-8
```

**Problem**: Screen size too small
```bash
# Solution: Resize terminal or use fullscreen
# Minimum recommended: 80x24
# Optimal: 120x40
```

### Performance Issues

**Problem**: TUI feels slow
```bash
# Solution: Close other terminal applications
# Run in a lightweight terminal emulator
# Check system resources
```

**Problem**: Scan hangs
```bash
# Solution: Press 'Q' to cancel
# Check network connectivity
# Verify target domain is accessible
```

### Input Issues

**Problem**: Keys not responding
```bash
# Solution: Click in terminal window to focus
# Check terminal input mode
# Try pressing ESC to reset
```

---

## 💡 Tips & Tricks

### Navigation
- Use `j`/`k` (Vim keys) or arrow keys for navigation
- Hold key to scroll faster
- Use ENTER to dig deeper into details

### Scanning
- Watch for phase status changes
- Monitor items found counter
- Check statistics panel for progress

### Results Analysis
- Candidates are ranked by confidence
- Green (90%+) = Very reliable
- Multiple evidence types = Higher confidence
- Check ASN clustering for infrastructure insights

### Keyboard Efficiency
- Learn keyboard shortcuts for faster navigation
- Use 'H' for quick help reference
- Press 'Q' from any screen to quit

---

## 📖 Example Session

### 1. Launch TUI
```bash
./cloudunflare-tui
```

### 2. Enter Target
- Type: `example.com`
- Press: `ENTER`

### 3. Watch Progress
- Observe real-time phase execution
- Monitor statistics panel
- Wait for completion message

### 4. Browse Results
- Navigate with ↑/↓ keys
- Review confidence scores
- Note discovery methods

### 5. View Details
- Press ENTER on a candidate
- Read all supporting evidence
- Check ASN information

### 6. Exit
- Press 'Q' to quit
- Or ESC to go back

---

## 🔒 Security Considerations

### OPSEC Features
- Randomized delays between requests
- User agent rotation
- DNS query distribution
- No aggressive scanning patterns

### Authorized Use Only
- Obtain explicit permission before testing
- Comply with legal requirements
- Follow responsible disclosure
- Document authorization

### Data Privacy
- Results stored in memory only
- No automatic logging to disk
- Secure cleanup on exit
- No sensitive data persistence

---

## 🚀 Performance Tips

### Optimal Settings
- Use wired network connection
- Run in dedicated terminal
- Close unnecessary applications
- Ensure stable DNS resolution

### Speed Optimization
- Phases run sequentially for safety
- Progress updates every 100ms
- Asynchronous scanning thread
- Non-blocking UI updates

---

## 📚 Additional Resources

- **Full Documentation**: `ADVANCED_IP_DETECTION.md`
- **Enhancement Summary**: `ENHANCEMENTS_SUMMARY.md`
- **Build Instructions**: `Makefile help`
- **Source Code**: GitHub repository

---

## 🆘 Getting Help

### In-Application
- Press `H` for help screen
- Check status bar for hints
- Read on-screen instructions

### External Resources
- GitHub Issues: Report bugs
- Documentation: Read guides
- Community: Ask questions

---

## 📝 Version Information

**Version**: 2.0-Enhanced TUI
**Release Date**: 2025-11-06
**Build Target**: `cloudunflare-tui`

### Features Summary
- ✅ 8 Advanced detection techniques
- ✅ Real-time progress tracking
- ✅ Interactive navigation
- ✅ Color-coded interface
- ✅ Keyboard shortcuts
- ✅ Detailed candidate views
- ✅ Live statistics
- ✅ Help screens

---

## 🎉 Enjoy CloudClear TUI!

The interactive terminal interface makes advanced IP detection intuitive and efficient. Happy hunting (with authorization)!

**For authorized security testing only.**

---

**CloudClear Development Team**
Version 2.0-Enhanced | 2025-11-06
