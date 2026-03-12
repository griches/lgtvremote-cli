# lgtvremote-cli

Command-line interface for controlling LG webOS TVs over your local network.

Communicates via WebSocket using the SSAP (Simple Service Access Protocol) on port 3001. Supports TV discovery, PIN-based pairing, remote control, app launching, input switching, Wake-on-LAN, and more.

## Installation

```bash
pip install .
```

Or run directly:

```bash
python lgtvremote_cli.py <command>
```

### Requirements

- Python 3.9+
- `websockets` >= 12.0 (`pip install websockets`)

## Quick Start

```bash
# 1. Find TVs on your network
lgtv scan

# 2. Add your TV
lgtv add 192.168.1.100

# 3. Pair (enter PIN shown on TV screen)
lgtv pair

# 4. Control your TV
lgtv off
lgtv on
lgtv launch netflix
lgtv volume set 20
```

## Configuration

Device data is stored in `~/.config/lgtvremote/devices.json`. This includes IP addresses, names, MAC addresses, and pairing keys.

## Command Reference

### Device Management

| Command | Description |
|---------|-------------|
| `lgtv scan` | Discover LG webOS TVs on the local network via SSDP |
| `lgtv add <ip>` | Add a TV by IP address |
| `lgtv add <ip> --name "Living Room" --mac AA:BB:CC:DD:EE:FF` | Add with name and MAC |
| `lgtv remove <ip>` | Remove a saved TV |
| `lgtv list` | List all saved TVs |
| `lgtv set-default <ip>` | Set the default TV for commands |
| `lgtv pair` | Pair with TV using PIN displayed on screen |
| `lgtv enrich` | Fetch/update model name and MAC addresses from TV |

### Power

| Command | Description |
|---------|-------------|
| `lgtv on` | Turn on TV via Wake-on-LAN (requires stored MAC address) |
| `lgtv off` | Turn off TV |
| `lgtv power` | Toggle power (off via WebSocket, on via WOL if unreachable) |

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

### Channels

| Command | Description |
|---------|-------------|
| `lgtv channel up` | Next channel |
| `lgtv channel down` | Previous channel |
| `lgtv channel set <number>` | Switch to specific channel |

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
| `lgtv inputs` | List all available inputs |

### Apps

| Command | Description |
|---------|-------------|
| `lgtv launch netflix` | Launch Netflix |
| `lgtv launch youtube` | Launch YouTube |
| `lgtv launch disney+` | Launch Disney+ |
| `lgtv launch amazon` | Launch Prime Video |
| `lgtv launch hbo` | Launch HBO Max |
| `lgtv launch spotify` | Launch Spotify |
| `lgtv launch appletv` | Launch Apple TV+ |
| `lgtv launch plex` | Launch Plex |
| `lgtv launch browser` | Launch web browser |
| `lgtv launch settings` | Open TV settings |
| `lgtv launch <app-id>` | Launch any app by its webOS app ID |
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

### Display & Settings

| Command | Description |
|---------|-------------|
| `lgtv screen-off` | Turn off screen (audio continues) |
| `lgtv picture-mode <mode>` | Set picture mode (standard, vivid, cinema, game, etc.) |
| `lgtv sound-mode <mode>` | Set sound mode (standard, cinema, game, etc.) |
| `lgtv sleep <minutes>` | Set sleep timer (0 to cancel) |
| `lgtv subtitles` | Toggle subtitles |
| `lgtv audio-track` | Cycle through audio tracks |
| `lgtv info` | Show channel/media info on screen |

### Number Keys

| Command | Description |
|---------|-------------|
| `lgtv number <0-9>` | Send a number key press |

### Service Menus (Advanced)

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

# Override with --tv flag
lgtv --tv 192.168.1.101 off
lgtv --tv 192.168.1.101 launch netflix
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
