# EpixNet

**EpixNet** is a decentralized peer-to-peer web platform that enables users to create, host, and access websites without relying on traditional centralized servers. Built on BitTorrent technology and cryptographic principles, EpixNet creates a censorship-resistant internet where content is distributed across a network of peers.

## What is EpixNet?

EpixNet is a Python-based implementation of a decentralized web platform where:

- **Websites are distributed**: Each site is stored across multiple peers in the network
- **No central servers**: Sites remain online as long as at least one peer hosts them
- **Cryptographically secured**: All content is signed and verified using public-key cryptography
- **BitTorrent-powered**: Uses BitTorrent protocol for peer discovery and content distribution
- **Real-time updates**: Site owners can update content and changes propagate across the network
- **Privacy-focused**: Supports Tor integration for anonymous browsing and hosting

## Core Features

- **Decentralized hosting**: Sites are served by visitors, eliminating hosting costs
- **Cryptographic authentication**: Password-less authorization using private/public key pairs
- **Real-time synchronization**: Live updates across all peers when content changes
- **Built-in database**: P2P synchronized SQLite database for dynamic content
- **Tor integration**: Full support for .onion hidden services (including onion-v3)
- **Offline capability**: Access cached sites even without internet connection
- **Clone protection**: One-click site cloning and forking
- **Multi-platform**: Works on Windows, macOS, Linux, and Android (via Termux)

## How It Works

1. **Start EpixNet**: Run `python3 epixnet.py` to start the local server
2. **Access sites**: Visit `http://127.0.0.1:42222/{site_address}` in your browser
3. **Peer discovery**: When you visit a site, EpixNet finds peers using BitTorrent trackers
4. **Content verification**: All files are verified against cryptographic signatures
5. **Automatic serving**: Sites you visit are automatically shared with other peers
6. **Content updates**: Site owners sign and publish updates, which propagate through the network

## Quick Start

### Prerequisites

- Python 3.8 or higher
- Git (for cloning the repository)
- Basic development tools (compiler, etc.)

### Installation

1. **Clone the repository**:

   ```bash
   git clone https://github.com/EpixZone/EpixNet.git
   cd EpixNet
   ```

2. **Create a virtual environment**:

   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**:

   ```bash
   python3 -m pip install -r requirements.txt
   ```

4. **Run EpixNet**:

   ```bash
   python3 epixnet.py
   ```

5. **Access the dashboard**:
   Open your browser and navigate to: `http://127.0.0.1:42222/`

### Creating Your First Site

1. Visit the EpixNet dashboard at `http://127.0.0.1:42222/`
2. Click **⋮** > **"Create new, empty site"**
3. You'll be redirected to your new site that only you can modify
4. Find your site files in the `data/[your_site_address]` directory
5. Edit your content, then drag the "0" button left and click **"Sign and publish"**

### System Dependencies for Source Installation

#### Ubuntu/Debian

```bash
sudo apt update
sudo apt install git pkg-config libffi-dev python3-pip python3-venv python3-dev build-essential libtool
```

#### Fedora/CentOS/RHEL

```bash
# Fedora
sudo dnf install git python3-pip python3-wheel python3-devel gcc

# CentOS/RHEL
sudo yum install epel-release
sudo yum install git python3 python3-wheel python3-devel gcc
```

#### openSUSE

```bash
sudo zypper install python3-pip python3-setuptools python3-wheel python3-devel gcc
```

#### Arch Linux

```bash
sudo pacman -S git python-pip base-devel
```

#### macOS

```bash
# Install Xcode command line tools
xcode-select --install

# Install Python 3 via Homebrew (recommended)
brew install python3
```

#### Android (Termux)

```bash
# Install Termux from F-Droid or Google Play
pkg update
pkg install python automake git binutils libtool

# For older Android versions, you may also need:
pkg install openssl-tool libcrypt clang

# Optional: Install Tor for enhanced privacy
pkg install tor
```

### Docker Installation

#### Using Docker Compose (Recommended)

```bash
# Clone the repository
git clone https://github.com/EpixZone/EpixNet.git
cd EpixNet

# Run with separate Tor container
docker compose up -d epixnet

# Or run with integrated Tor
docker compose up -d epixnet-tor
```

#### Manual Docker Build

```bash
# Build standard image
docker build -t epixnet:latest . -f docker/Dockerfile

# Build with integrated Tor
docker build -t epixnet:latest . -f docker/tor.Dockerfile

# Run the container
docker run --rm -it \
  -v /path/to/data:/app/data \
  -p 42222:42222 \
  -p 42223:42223 \
  -p 10042:10042 \
  epixnet:latest
```

**Note**: Replace `/path/to/data` with your desired data directory. This directory will contain your sites and private keys.

### Convenience Scripts

#### Automated Setup Script

```bash
# Use the provided setup script
./start-venv.sh
```

This script automatically:

- Creates a Python virtual environment
- Installs all dependencies
- Starts EpixNet

### Windows Installation

#### Prerequisites

1. **Install Python 3.8+** from [python.org](https://www.python.org/downloads/)
2. **Install Git** from [git-scm.com](https://git-scm.com/downloads)
3. **Install Visual Studio Build Tools** (for compiling dependencies)

#### Installation Steps

```cmd
# Clone the repository
git clone https://github.com/EpixZone/EpixNet.git
cd EpixNet

# Create virtual environment
python -m venv venv
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run EpixNet
python epixnet.py
```

#### With Tor Support

```cmd
# Install Tor Browser or standalone Tor
# Run EpixNet with Tor proxy
python epixnet.py --tor_proxy 127.0.0.1:9150 --tor_controller 127.0.0.1:9151

# For full Tor anonymity
python epixnet.py --tor_proxy 127.0.0.1:9150 --tor_controller 127.0.0.1:9151 --tor always
```

## Configuration

### Command Line Options

```bash
# Basic usage
python3 epixnet.py

# Custom port
python3 epixnet.py --ui_port 42222

# Enable Tor
python3 epixnet.py --tor always

# Offline mode
python3 epixnet.py --offline

# Custom data directory
python3 epixnet.py --data_dir /path/to/data

# Debug mode
python3 epixnet.py --debug
```

### Configuration File

EpixNet creates a `epixnet.conf` file in your data directory where you can set persistent configuration options.

## Usage

### Accessing Sites

- **Local dashboard**: `http://127.0.0.1:42222/`
- **Specific site**: `http://127.0.0.1:42222/{site_address}/`
- **Dashboard site**: `http://127.0.0.1:42222/epix1dashuu6pvsut7aw9dx44f543mv7xt9zlydsj9t/`

### Site Management

- **Create new site**: Dashboard → ⋮ → "Create new, empty site"
- **Clone existing site**: Visit site → Clone button
- **Manage sites**: Dashboard shows all your sites and visited sites
- **Site files**: Located in `data/{site_address}/` directory

## Development

### Architecture

EpixNet is built with a modular plugin architecture:

- **Core**: Site management, peer discovery, content verification
- **File Server**: Handles file serving and peer connections
- **UI Server**: Web interface for site management
- **Plugins**: Extensible functionality (Tor, BitTorrent, etc.)

### Key Technologies

- **Python 3.8+**: Core runtime
- **gevent**: Asynchronous networking
- **SQLite**: Local database storage
- **BitTorrent**: Peer discovery protocol
- **Cryptography**: Content signing and verification
- **Tor**: Anonymous networking (optional)

### Contributing

We welcome contributions! Here's how you can help:

1. **Report bugs**: Use GitHub issues to report problems
2. **Submit patches**: Fork the repo and submit pull requests
3. **Improve documentation**: Help make the docs clearer
4. **Test on different platforms**: Help ensure compatibility
5. **Create packages**: Help package EpixNet for more distributions

### Current Limitations

- No DHT support (relies on BitTorrent trackers)
- No I2P integration
- Limited spam protection mechanisms
- No built-in encryption for local storage
- Requires local installation (no browser-only access)

## Security Considerations

- **Private keys**: Stored locally in `data/users.json` - keep this file secure
- **Site verification**: All content is cryptographically verified
- **Tor integration**: Use `--tor always` for maximum anonymity
- **Network exposure**: EpixNet opens network ports for peer connections
- **Content responsibility**: You become a host for sites you visit

## Community and Support

- **GitHub Issues**: [Report bugs and request features](https://github.com/EpixZone/EpixNet/issues)

## License

EpixNet is free and open-source software licensed under the GNU General Public License v3.0. See the [LICENSE](LICENSE) file for details.
