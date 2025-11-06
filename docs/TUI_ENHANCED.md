# CloudClear Enhanced TUI Guide

## Overview

The Enhanced TUI (Text User Interface) provides a modern, visually appealing terminal interface for CloudClear with improved colors, Unicode box-drawing characters, progress indicators, and better user experience.

## Visual Enhancements

### 1. Modern Color Scheme

The enhanced TUI uses an extended color palette with vibrant, semantic colors:

| Color Pair | Usage | Visual Impact |
|------------|-------|---------------|
| **Title** | Main headings, logo | Magenta, bold, eye-catching |
| **Subtitle** | Secondary text | Cyan, professional |
| **Success** | Completed items, high confidence | Green, positive feedback |
| **Warning** | In-progress, medium confidence | Yellow, attention |
| **Error** | Failed items, low confidence | Red, critical |
| **Info** | General information | Blue, neutral |
| **Accent** | Highlights, active elements | Yellow, emphasis |
| **Dim** | Secondary information | Gray, de-emphasized |

### 2. Unicode Box-Drawing Characters

The enhanced TUI uses Unicode box-drawing characters for a polished look:

```
╔═══════════════════════════════════════╗
║  CloudClear - Enhanced Interface      ║
╠═══════════════════════════════════════╣
║  Phase 1: DNS Reconnaissance          ║
║  ▕████████████████████████████████▏ 100% ✓ ║
║                                       ║
║  → Currently scanning subdomains...   ║
╚═══════════════════════════════════════╝
```

**Character Set:**
- `╔╗╚╝` - Box corners (double-line)
- `║═` - Box sides (double-line)
- `▕▏` - Progress bar brackets
- `█` - Filled progress
- `░` - Empty progress
- `✓✗` - Check/cross marks
- `→←↑↓` - Arrows
- `•★⚙` - Bullet points, status icons

### 3. Enhanced Progress Bars

Progress bars feature gradient colors based on progress:

```
Progress: ▕████████████████░░░░░░░░░░░░▏  55%
         ▕█████████████████████████████▏ 100% ✓
```

**Color Gradient:**
- 0-29%: Red (needs attention)
- 30-69%: Yellow (in progress)
- 70-100%: Green (good progress)

### 4. Status Icons

Visual icons for different states:

```
○ Pending     - Not started yet
⚙ Running     - Currently executing
✓ Completed   - Successfully finished
✗ Failed      - Encountered errors
★ Highlight   - Special emphasis
→ Action      - Current operation
```

### 5. Candidate Ranking with Medals

Top 3 candidates get special visual treatment:

```
🥇 1  203.0.113.10   █████ 95% (VERIFIED)      SSL Certificate
🥈 2  203.0.113.20   ████░ 88% (VERY LIKELY)   MX Record
🥉 3  203.0.113.30   ███░░ 72% (LIKELY)        SRV Discovery
•  4  203.0.113.40   ██░░░ 65% (POSSIBLE)      ASN Clustering
```

### 6. Confidence Score Visualization

Confidence levels shown with bars and descriptive text:

```
█████ 95% (VERIFIED)       - Highest confidence
████░ 85% (VERY LIKELY)    - Very high confidence
███░░ 72% (LIKELY)         - High confidence
██░░░ 65% (POSSIBLE)       - Medium confidence
█░░░░ 45% (WEAK)           - Low confidence
```

## Screen-by-Screen Guide

### Welcome Screen

```
   ██████╗██╗      ██████╗ ██╗   ██╗██████╗
  ██╔════╝██║     ██╔═══██╗██║   ██║██╔══██╗
  ██║     ██║     ██║   ██║██║   ██║██║  ██║
  ██║     ██║     ██║   ██║██║   ██║██║  ██║
  ╚██████╗███████╗╚██████╔╝╚██████╔╝██████╔╝
   ╚═════╝╚══════╝ ╚═════╝  ╚═════╝ ╚═════╝

   ██████╗██╗     ███████╗ █████╗ ██████╗
  ██╔════╝██║     ██╔════╝██╔══██╗██╔══██╗
  ██║     ██║     █████╗  ███████║██████╔╝
  ██║     ██║     ██╔══╝  ██╔══██║██╔══██╗
  ╚██████╗███████╗███████╗██║  ██║██║  ██║
   ╚═════╝╚══════╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝

═══════════════════════════════════════════════════════
  Advanced CDN Origin IP Detection Platform v2.0
  Penetrate CDN obfuscation • Discover true origin IPs

╔═══════════════════ FEATURES ═══════════════════╗

✓ SSL Certificate Transparency Analysis
✓ Advanced MX & SRV Record Enumeration
✓ Multi-Vector CDN Bypass Techniques
✓ ASN Network Clustering & BGP Analysis
✓ Reverse DNS & PTR Intelligence
✓ WAF Evasion & Origin Verification (NEW!)

╚═════════════════════════════════════════════════╝

▶ Press any key to continue...
```

**Features:**
- Large ASCII art logo with color
- Feature list with checkmarks
- Professional subtitle text
- Blinking continue prompt

### Scanning Screen

```
╔══════════════════════════════════════════════════════════╗
║ 🔍 Scan Progress                                         ║
╠══════════════════════════════════════════════════════════╣
║                                                          ║
║ ✓ [1/8] DNS Reconnaissance              [DONE]          ║
║   ★ Found: 12 items                                      ║
║                                                          ║
║ ⚙ [2/8] Certificate Transparency        [RUNNING]       ║
║   Progress: ▕██████████████████░░░░░░░░▏ 65%           ║
║   → Mining CT logs for subdomains...                     ║
║                                                          ║
║ ○ [3/8] Subdomain Enumeration          [PENDING]        ║
║                                                          ║
║ ○ [4/8] OSINT Gathering                [PENDING]        ║
║                                                          ║
╚══════════════════════════════════════════════════════════╝

╔══════════════════════════════════════════════════════════╗
║ 📊 Statistics                                            ║
╠══════════════════════════════════════════════════════════╣
║                                                          ║
║ 🎯 Target: example.com                                   ║
║                                                          ║
║ ⧗ Duration: 2m 34s                                       ║
║                                                          ║
║ ★ Origin Candidates: 5                                   ║
║ • Total IPs: 47                                          ║
║ • Subdomains: 128                                        ║
║                                                          ║
║ ⚡ Techniques:                                           ║
║   Attempted: 8                                           ║
║   Successful: 6                                          ║
║   Success Rate: 75%                                      ║
║                                                          ║
╚══════════════════════════════════════════════════════════╝
```

**Features:**
- Split-panel layout
- Live progress updates
- Animated progress bars
- Current action display
- Real-time statistics

### Results Screen

```
╔══════════════════════════════════════════════════════════════════════╗
║ ⚙ Origin IP Candidates (Ranked by Confidence)                       ║
╠══════════════════════════════════════════════════════════════════════╣
║                                                                      ║
║  Rank  IP Address       Confidence Score        Discovery Method    ║
║  ────  ─────────────────────────────────────────────────────────────║
║  🥇 1  203.0.113.10   █████ 95% (VERIFIED)      SSL Certificate     ║
║> 🥈 2  203.0.113.20   ████░ 88% (VERY LIKELY)   MX Record          ║
║  🥉 3  203.0.113.30   ███░░ 72% (LIKELY)        SRV Discovery      ║
║  •  4  203.0.113.40   ██░░░ 65% (POSSIBLE)      ASN Clustering     ║
║  •  5  203.0.113.50   █░░░░ 45% (WEAK)          PTR Analysis       ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝

╔══════════════════════════════════════════════════════════════════════╗
║  ↑↓ Navigate      ↵ View Details      Q Quit      H Help           ║
╚══════════════════════════════════════════════════════════════════════╝
```

**Features:**
- Medal icons for top 3
- Visual confidence bars
- Highlighted selection
- Clear navigation hints
- Column-aligned layout

### Help Screen

```
╔══════════════════════════════════════════════════════════════════════╗
║ ℹ HELP & KEYBOARD SHORTCUTS                                          ║
╠══════════════════════════════════════════════════════════════════════╣
║                                                                      ║
║  🚀 NAVIGATION                                                       ║
║                                                                      ║
║    ↑ / ↓     Navigate up/down in lists                             ║
║    ↵ ENTER    View detailed information                             ║
║    ← ESC       Go back / Cancel                                      ║
║                                                                      ║
║  ⚙ ACTIONS                                                           ║
║                                                                      ║
║    Q           Quit application                                      ║
║    H / ?       Show this help                                        ║
║    R           Refresh current view                                  ║
║    S           Start new scan                                        ║
║                                                                      ║
║  ⚡ TIPS                                                             ║
║                                                                      ║
║    • Candidates are ranked by confidence score                       ║
║    • Higher scores indicate more likely origin servers               ║
║    • Multiple discovery methods increase confidence                  ║
║    • Verify findings with additional tools                           ║
║                                                                      ║
║  ⚠ IMPORTANT                                                         ║
║                                                                      ║
║    This tool is for authorized security testing only.                ║
║    Always obtain proper authorization before testing.                ║
║                                                                      ║
║                                                                      ║
║                Press any key to close help...                        ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
```

## Keyboard Shortcuts

### Global Keys

| Key | Action | Description |
|-----|--------|-------------|
| `Q` | Quit | Exit CloudClear |
| `H` / `?` | Help | Show help screen |
| `ESC` | Back | Return to previous screen |

### Navigation Keys

| Key | Action | Description |
|-----|--------|-------------|
| `↑` | Up | Move selection up |
| `↓` | Down | Move selection down |
| `Enter` | Select | View details or confirm |
| `PgUp` | Page Up | Scroll up one page |
| `PgDn` | Page Down | Scroll down one page |
| `Home` | Top | Jump to first item |
| `End` | Bottom | Jump to last item |

### Results Screen Keys

| Key | Action | Description |
|-----|--------|-------------|
| `R` | Refresh | Refresh results display |
| `S` | Save | Save results to file |
| `E` | Export | Export in different formats |
| `F` | Filter | Filter candidates by confidence |

## Building and Running

### Standard TUI

```bash
# Build standard TUI
make tui

# Run
./cloudclear-tui
```

### Enhanced TUI (with Unicode support)

```bash
# Build enhanced TUI
make tui-enhanced

# Run
./cloudclear-tui-enhanced
```

### Docker with TUI

```bash
# Run interactive TUI in Docker
docker-compose --profile interactive up cloudclear-tui

# Or with enhanced UI
docker-compose --profile interactive-enhanced up cloudclear-tui-enhanced
```

## Terminal Requirements

### Minimum Requirements

- **Terminal Emulator**: xterm, GNOME Terminal, iTerm2, Windows Terminal, etc.
- **Color Support**: 256-color mode (8-bit)
- **Size**: Minimum 80x24 characters (recommended: 120x40)
- **Font**: Monospace font with Unicode support

### Recommended Terminals

1. **Linux**
   - GNOME Terminal
   - Konsole
   - Terminator
   - Alacritty

2. **macOS**
   - iTerm2 (highly recommended)
   - Terminal.app

3. **Windows**
   - Windows Terminal (Windows 10+)
   - WSL + any Linux terminal

### Font Recommendations

For best Unicode character display:

1. **Nerd Fonts** (https://www.nerdfonts.com/)
   - FiraCode Nerd Font
   - JetBrains Mono Nerd Font
   - Hack Nerd Font

2. **Standard Fonts with Good Unicode Coverage**
   - DejaVu Sans Mono
   - Source Code Pro
   - Menlo
   - Consolas

## Troubleshooting

### Issue: Box characters appear broken

**Cause**: Terminal doesn't support Unicode or wrong encoding

**Solution**:
```bash
# Set UTF-8 locale
export LC_ALL=en_US.UTF-8
export LANG=en_US.UTF-8

# Verify terminal supports UTF-8
locale charmap
# Should output: UTF-8
```

### Issue: Colors don't appear

**Cause**: Terminal doesn't support colors or TERM is misconfigured

**Solution**:
```bash
# Check color support
tput colors
# Should output: 256 or higher

# Set correct TERM
export TERM=xterm-256color
```

### Issue: Icons/emoji don't display

**Cause**: Font doesn't include those Unicode code points

**Solution**:
- Install a Nerd Font or font with emoji support
- Use standard TUI instead of enhanced version
- Fall back to ASCII mode (if available)

### Issue: Screen flickers or updates slowly

**Cause**: Terminal refresh rate or slow connection

**Solution**:
```bash
# Reduce update frequency (edit source)
timeout(500);  // Change from 100ms to 500ms

# Use SSH compression for remote connections
ssh -C user@host
```

## Performance Optimization

### For Slow Terminals

1. Disable animations:
   ```c
   // In source, set:
   #define ENABLE_ANIMATIONS 0
   ```

2. Reduce refresh rate:
   ```c
   timeout(500);  // 500ms instead of 100ms
   ```

3. Use standard TUI instead of enhanced

### For High-Performance Displays

1. Enable smooth animations
2. Increase refresh rate to 50ms
3. Use true-color mode if supported

## Customization

### Color Scheme

Edit `src/tui/cloudclear_tui_enhanced.c`:

```c
// Change color pairs
init_pair(COLOR_PAIR_SUCCESS, COLOR_GREEN, -1);
// Change to blue:
init_pair(COLOR_PAIR_SUCCESS, COLOR_BLUE, -1);
```

### Progress Bar Style

Customize progress bar characters:

```c
// Full block progress
waddch(win, '█');  // Filled
waddch(win, '░');  // Empty

// ASCII alternative
waddch(win, '=');  // Filled
waddch(win, '-');  // Empty
```

### Status Icons

Customize status indicators:

```c
// Unicode symbols
status_icon = "✓";  // Check
status_icon = "⚙";  // Gear

// ASCII alternatives
status_icon = "[OK]";
status_icon = "[>>]";
```

## Accessibility

### High Contrast Mode

For users who need high contrast:

```bash
# Build with high contrast colors
make tui-enhanced CFLAGS="-DHIGH_CONTRAST=1"
```

### ASCII-Only Mode

For terminals without Unicode support:

```bash
# Build ASCII-only version
make tui CFLAGS="-DASCII_ONLY=1"
```

### Screen Reader Support

While TUI is visual, you can use:

1. **tty output mode**: Prints progress to stdout
2. **Log file mode**: Writes all updates to log file
3. **JSON output**: Machine-readable progress

```bash
# Log file mode
./cloudclear-tui --log-file=/tmp/cloudclear.log

# Follow progress in another terminal
tail -f /tmp/cloudclear.log
```

## Tips for Best Experience

1. **Use a modern terminal** with full Unicode support
2. **Install a Nerd Font** for best icon display
3. **Set terminal size** to at least 120x40 for comfortable viewing
4. **Enable 256-color mode** for best color rendering
5. **Use SSH compression** (-C flag) for remote sessions
6. **Maximize terminal window** during scans for best overview

## Comparison: Standard vs Enhanced TUI

| Feature | Standard TUI | Enhanced TUI |
|---------|-------------|-------------|
| Box Characters | ASCII (`+---+`) | Unicode (`╔══╗`) |
| Progress Bars | Simple (`[====>  ]`) | Gradient (`▕████░░▏`) |
| Status Icons | Text (`[OK]`) | Unicode (`✓`) |
| Color Scheme | 8 colors | Extended palette |
| Ranking Display | Numbers only | Medals + numbers |
| Confidence Viz | Text only | Bars + text |
| Overall Look | Functional | Polished |

## Support

For TUI-specific issues:
- Check terminal requirements
- Verify UTF-8 encoding
- Test with recommended terminals
- Fall back to standard TUI if needed

General support:
- **Documentation**: [docs/](../docs/)
- **Issues**: [GitHub Issues](https://github.com/SWORDIntel/CLOUDCLEAR/issues)

---

**CloudClear Enhanced TUI** - Professional reconnaissance with style.
