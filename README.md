# LG TV Remote CLI

## Command-line interface for controlling LG webOS TVs over your local network.

Communicates via WebSocket using the SSAP (Simple Service Access Protocol) on port 3001. Supports TV discovery, PIN-based pairing, remote control, app launching, input switching, Wake-on-LAN, and more.

## Installation

Only Python 3.9+ is required (ships with macOS and most Linux distros).

```bash
# Install from PyPI (recommended)
pip install lgtvremote-cli

# Or with pipx (isolated environment, great for CLI tools)
pipx install lgtvremote-cli
```

### Install from source

```bash
git clone https://github.com/griches/lgtvremote-cli.git
cd lgtvremote-cli
pip install .
```

### Upgrading from older versions

Run `lgtv pair` after upgrading to 1.3.1 — the registration manifest changed, and existing client keys are frozen to their original (more limited) permission set. Re-pairing issues a fresh key under the new manifest.

If you don't have Python 3 installed:

| Platform | Install |
|----------|---------|
| macOS | `brew install python3` |
| Ubuntu/Debian | `sudo apt install python3` |
| Fedora/RHEL | `sudo dnf install python3` |
| Windows | `winget install Python.Python.3` or [python.org](https://www.python.org/downloads/) |

## Quick Start

```bash
# 1. Scan, add, and pair — all in one step
lgtv scan
# Finds TVs, adds them, asks to pair, fetches MAC addresses for Wake-on-LAN

# 2. Control your TV
lgtv off                    # Turn off
lgtv on                     # Wake via Wake-on-LAN
lgtv launch Netflix         # Launch apps by name
lgtv volume set 20          # Set volume
lgtv input 1                # Switch to HDMI 1
```

Or if you know the IP:

```bash
lgtv add 192.168.1.100      # Adds, pairs, and fetches MACs automatically
```

## Configuration

Device data is stored in `~/.config/lgtvremote/devices.json`. This includes IP addresses, names, MAC addresses, and pairing keys.

## Command Reference

### Device Management

| Command | Description |
|---------|-------------|
| `lgtv scan` | Discover TVs, auto-add, pair, and fetch MAC addresses |
| `lgtv add <ip>` | Add a TV by IP — auto-enriches, pairs, and fetches MACs |
| `lgtv add <ip> --name "Living Room"` | Add with a custom name |
| `lgtv remove <ip>` | Remove a saved TV |
| `lgtv list` | List all saved TVs |
| `lgtv set-default <ip>` | Set the default TV for commands |
| `lgtv pair` | Re-pair with a TV (if needed) |
| `lgtv enrich` | Re-fetch model name and MAC addresses from TV |

### Power

| Command | Description |
|---------|-------------|
| `lgtv on` | Turn on TV via Wake-on-LAN (requires stored MAC address) |
| `lgtv off` | Turn off TV |
| `lgtv power` | Toggle power (off via WebSocket, on via WOL if unreachable) |
| `lgtv power-status` | Check if TV is on or off (JSON output, exit code 1 if off/unreachable) |

### Volume

| Command | Description |
|---------|-------------|
| `lgtv volume up` | Volume up |
| `lgtv volume down` | Volume down |
| `lgtv volume set <0-100>` | Set volume to specific level |
| `lgtv volume get` | Get current volume and mute status |
| `lgtv volume mute` | Mute |
| `lgtv volume unmute` | Unmute |

### Navigation

| Command | Description |
|---------|-------------|
| `lgtv nav up` | Navigate up |
| `lgtv nav down` | Navigate down |
| `lgtv nav left` | Navigate left |
| `lgtv nav right` | Navigate right |
| `lgtv nav ok` | Select / OK / Enter |
| `lgtv nav back` | Go back |
| `lgtv nav home` | Go to home screen |
| `lgtv nav menu` | Open menu |

### Live TV & Channels

| Command | Description |
|---------|-------------|
| `lgtv livetv` | Switch to Live TV tuner |
| `lgtv channel up` | Next channel |
| `lgtv channel down` | Previous channel |

### Media Controls

| Command | Description |
|---------|-------------|
| `lgtv play` | Play |
| `lgtv pause` | Pause |
| `lgtv stop` | Stop playback |
| `lgtv rewind` | Rewind |
| `lgtv ff` | Fast forward |
| `lgtv skip-forward` | Skip forward / next track |
| `lgtv skip-back` | Skip backward / previous track |

### Input / HDMI

| Command | Description |
|---------|-------------|
| `lgtv input 1` | Switch to HDMI 1 |
| `lgtv input 2` | Switch to HDMI 2 |
| `lgtv input HDMI_3` | Switch to HDMI 3 (full ID) |
| `lgtv input PS5` | Switch by label (case-insensitive) |
| `lgtv inputs` | List all available inputs (also caches labels) |
| `lgtv input-alias HDMI_1 PS5` | Set a custom alias for an input |
| `lgtv input-alias HDMI_1` | Remove the alias for an input |

Input labels are automatically cached per TV when you run `lgtv inputs` or `lgtv pair`, so you can switch by label name (e.g., `lgtv input ps5`) without an extra network round-trip. Custom aliases set with `input-alias` take precedence over TV-reported labels.

### Apps

Launch any app by its display name — matches against what's installed on your TV:

| Command | Description |
|---------|-------------|
| `lgtv launch Netflix` | Launch Netflix |
| `lgtv launch YouTube` | Launch YouTube |
| `lgtv launch "Disney+"` | Launch Disney+ |
| `lgtv launch "Prime Video"` | Launch Prime Video |
| `lgtv launch Plex` | Launch Plex |
| `lgtv launch browser` | Launch web browser (shortcut) |
| `lgtv launch settings` | Open TV settings (shortcut) |
| `lgtv launch <app-id>` | Launch by webOS app ID |
| `lgtv apps` | List all installed apps with their IDs |
| `lgtv app` | Show currently running foreground app |

#### Supported App Shortcuts

| Shortcut | App ID |
|----------|--------|
| `netflix` | `netflix` |
| `youtube` | `youtube.leanback.v4` |
| `amazon` / `prime` / `primevideo` | `amazon` |
| `disney` / `disney+` / `disneyplus` | `com.disney.disneyplus-prod` |
| `hulu` | `hulu` |
| `hbo` / `hbomax` | `hbo-go-2` |
| `apple` / `appletv` | `com.apple.tv` |
| `spotify` | `spotify-beehive` |
| `plex` | `plex` |
| `crunchyroll` | `crunchyroll` |
| `twitch` | `twitch` |
| `vudu` | `vudu` |
| `livetv` / `tv` | `com.webos.app.livetv` |
| `settings` | `com.webos.app.settings` |
| `browser` | `com.webos.app.browser` |

### Open URL

Send a URL to the TV to open in the built-in webOS browser.

| Command | Description |
|---------|-------------|
| `lgtv open-url https://example.com` | Open URL in TV browser |
| `lgtv open-url example.com` | Scheme is added automatically if omitted |

### Number Keys

| Command | Description |
|---------|-------------|
| `lgtv number <0-9>` | Send a number key press |

### Display & Settings (newer TVs only)

These commands use `setSystemSettings` which may not be available on older webOS versions.

| Command | Description |
|---------|-------------|
| `lgtv screen-off` | Turn off screen (audio continues) |
| `lgtv screen-on` | Turn screen back on |
| `lgtv picture-mode <mode>` | Set picture mode (e.g., standard, vivid, cinema, game) |
| `lgtv sound-mode <mode>` | Set sound mode (e.g., standard, cinema, game) |
| `lgtv subtitles` | Toggle subtitles |
| `lgtv audio-track` | Cycle audio track |

### Service Menus (Advanced)

These menus require a password. The default is usually **0413**. Other common codes: **0000**, **7777**.

| Command | Description |
|---------|-------------|
| `lgtv service instart` | Open In-Start service menu |
| `lgtv service ezadjust` | Open Ez-Adjust menu |
| `lgtv service hotel` | Open Hotel/Installation mode |
| `lgtv service hidden` | Open hidden menu |
| `lgtv service freesync` | Show Freesync info |

### Raw Commands

| Command | Description |
|---------|-------------|
| `lgtv raw <ssap-uri>` | Send any SSAP command |
| `lgtv raw <ssap-uri> --payload '{"key":"value"}'` | Send with JSON payload |

#### Examples

```bash
# Get system info
lgtv raw ssap://system/getSystemInfo

# Get software info
lgtv raw ssap://com.webos.service.update/getCurrentSWInformation

# Set a specific setting
lgtv raw ssap://com.webos.service.settings/setSystemSettings \
  --payload '{"category":"picture","settings":{"backlight":80}}'
```

## Using with Multiple TVs

```bash
# Add multiple TVs
lgtv add 192.168.1.100 --name "Living Room"
lgtv add 192.168.1.101 --name "Bedroom"

# Set default
lgtv set-default 192.168.1.100

# Commands use default TV
lgtv off

# Override with --tv flag (IP or name)
lgtv --tv 192.168.1.101 off
lgtv --tv "Bedroom" launch netflix
```

## Using with AI Assistants

This CLI is designed to be easily used by AI assistants and automation tools. Run `lgtv -h` for the full command list, or `lgtv <command> -h` for detailed help on any command.

Key patterns:
- All commands return human-readable output to stdout
- Errors go to stderr with non-zero exit codes
- `lgtv apps` and `lgtv inputs` list available options with IDs
- `lgtv raw` allows sending any SSAP command for capabilities not covered by named commands

## Network Requirements

- Your computer and TV must be on the same local network
- Port 3001 (WSS) must be accessible for TV control
- Port 3000 (HTTP) is used for device discovery enrichment
- Port 1900 (UDP) is used for SSDP discovery
- Ports 7 and 9 (UDP broadcast) are used for Wake-on-LAN

## License

MIT
