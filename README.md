# ⚡ VPS Control Panel v2.0

A cyberpunk-themed web-based VPS management panel built with Node.js. Manage your entire server from a single, beautiful dashboard.

![Version](https://img.shields.io/badge/version-2.0.0-brightgreen)
![License](https://img.shields.io/badge/license-MIT-blue)
![Node](https://img.shields.io/badge/node-16%2B-green)

---

## 📸 Screenshots

<p align="center">
  <img src="https://via.placeholder.com/800x400/0a0a0f/00ff41?text=VPS+Control+Panel+Dashboard" alt="Dashboard">
</p>

---

## ✨ Features

### 🖥️ System Management
- Real-time CPU, RAM, Disk, and Network monitoring
- Live process manager with kill, filter, and sort
- System information (OS, kernel, uptime, load average)
- Temperature monitoring
- Memory and disk usage details

### 💻 Web Terminal
- Full PTY-based bash terminal
- Command blocking for dangerous operations
- Resize support
- Multi-session support via WebSocket
- Ctrl+C interrupt handling

### 📦 Process Management (PM2)
- List all PM2 applications
- Start, stop, restart, reload, delete apps
- View application logs
- Save PM2 process list
- Monitor CPU/Memory per app

### 🐳 Docker Management
- List containers (running and stopped)
- Start, stop, restart, pause, kill, remove containers
- View container logs with timestamps
- Inspect container details
- List Docker images
- Docker network overview

### 🌐 Nginx Management
- Start, stop, restart, reload Nginx
- View access and error logs
- Check configuration syntax
- List available and enabled sites
- Monitor Nginx status

### 📁 File Manager
- Browse server filesystem
- Read and edit files (with syntax highlighting ready)
- Create, delete, rename files and folders
- Upload files (multi-file support)
- Download files
- Copy, move operations
- Change file permissions (chmod)
- Automatic backup before file edits
- Path traversal protection

### 🔥 Firewall (UFW)
- Enable/disable firewall
- Add allow/deny/reject rules
- Delete rules by number
- Port and protocol specification
- Source IP filtering
- Rule comments

### 🌍 Network Tools
- View listening ports (ss/netstat)
- Active connections monitor
- Ping test
- Traceroute
- DNS lookup (nslookup/dig)
- Network interfaces information

### 🔒 Security Center
- SSH login history (last command)
- Fail2ban status and jail monitoring
- SSH configuration viewer
- System users list
- Available updates check (apt/yum)
- Audit logging

### 💾 Backup System
- Create compressed backups (tar.gz)
- Custom backup paths
- Exclude patterns
- List all backups with sizes
- Download backups
- Delete old backups

### 👥 User Management
- Create users with roles (admin/user)
- Update user passwords
- Delete users
- Role-based access control
- Password hashing with bcrypt

### 📋 Log Viewer
- System logs (journalctl)
- Authentication logs
- Audit logs
- Custom log file viewer
- Nginx access and error logs
- Configurable line limits

### ⚡ Power Controls
- Reboot server
- Shutdown server
- Double confirmation for safety

---

## 🚀 Quick Start

### Prerequisites
- **Node.js** 16 or higher
- **Linux** server (Ubuntu/Debian recommended)
- **npm** (comes with Node.js)
- **sudo** access for service management

### Installation

```bash
# Clone the repository
git clone https://github.com/x6455/vps-control-panel.git

# Navigate to directory
cd vps-control-panel

# Install dependencies
npm install

# Start the server
npm start
