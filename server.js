// server.js - Complete VPS Management Panel
// Production-ready with all features implemented

const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const { spawn, exec, execSync } = require('child_process');
const fs = require('fs').promises;
const fsSync = require('fs');
const path = require('path');
const crypto = require('crypto');
const os = require('os');
const pty = require('node-pty');
const si = require('systeminformation');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const FileStore = require('session-file-store')(session);
const multer = require('multer');
const Docker = require('dockerode');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');

// ============================================================
// CONFIGURATION
// ============================================================
const CONFIG = {
    port: process.env.PORT || 3010,
    sessionSecret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
    usersFile: './data/users.json',
    sessionsDir: './data/sessions',
    auditFile: './data/audit.log',
    backupsDir: './data/backups',
    uploadsDir: './data/uploads',
    blockedCommands: [
        /rm\s+-rf\s+\//i,
        /mkfs/i,
        /shutdown\s+-/i,
        /reboot\s+-/i,
        /dd\s+if=/i,
        /:\{\s*:\|:&\s*\};:/i,
        />\s*\/dev\/sd[a-z]/i,
        /chmod\s+-R\s+777\s+\//i,
        /wget.*\|.*sh/i,
        /curl.*\|.*sh/i
    ],
    maxFileSize: '50mb',
    maxLogLines: 500,
    wsClients: new Set(),
    terminalSessions: new Map()
};

// Ensure data directories exist
['./data', CONFIG.sessionsDir, CONFIG.backupsDir, CONFIG.uploadsDir].forEach(dir => {
    if (!fsSync.existsSync(dir)) {
        fsSync.mkdirSync(dir, { recursive: true });
    }
});

// ============================================================
// EXPRESS SETUP
// ============================================================
const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

// Security middleware
app.use(helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false,
    crossOriginResourcePolicy: { policy: "cross-origin" }
}));

// Add security headers
app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    next();
});

app.use(express.json({ limit: CONFIG.maxFileSize }));
app.use(express.urlencoded({ extended: true, limit: CONFIG.maxFileSize }));

// Rate limiting
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 200,
    message: { error: 'Too many requests, please try again later.' },
    standardHeaders: true,
    legacyHeaders: false
});
app.use('/api/', apiLimiter);

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    message: { error: 'Too many login attempts, please try again later.' },
    standardHeaders: true,
    legacyHeaders: false
});
app.use('/api/auth/login', authLimiter);

// Session configuration
const sessionMiddleware = session({
    store: new FileStore({
        path: CONFIG.sessionsDir,
        ttl: 86400,
        retries: 0
    }),
    secret: CONFIG.sessionSecret,
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: false,
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000,
        sameSite: 'lax'
    }
});
app.use(sessionMiddleware);

// ============================================================
// AUTHENTICATION MIDDLEWARE
// ============================================================
function requireAuth(req, res, next) {
    if (req.session && req.session.authenticated) {
        req.session.lastActivity = Date.now();
        next();
    } else {
        res.status(401).json({ error: 'Unauthorized' });
    }
}

function requireAdmin(req, res, next) {
    if (req.session && req.session.authenticated && req.session.role === 'admin') {
        req.session.lastActivity = Date.now();
        next();
    } else {
        res.status(403).json({ error: 'Admin access required' });
    }
}

// ============================================================
// UTILITY FUNCTIONS
// ============================================================
async function getUsers() {
    try {
        const data = await fs.readFile(CONFIG.usersFile, 'utf8');
        return JSON.parse(data);
    } catch {
        const defaultUser = {
            admin: {
                password: await bcrypt.hash('admin', 12),
                role: 'admin',
                created: new Date().toISOString()
            }
        };
        await fs.writeFile(CONFIG.usersFile, JSON.stringify(defaultUser, null, 2));
        return defaultUser;
    }
}

async function saveUsers(users) {
    await fs.writeFile(CONFIG.usersFile, JSON.stringify(users, null, 2));
}

function auditLog(action, user = 'system', ip = 'unknown') {
    const timestamp = new Date().toISOString();
    const logEntry = `[${timestamp}] [${user}] [${ip}] ${action}\n`;
    fsSync.appendFileSync(CONFIG.auditFile, logEntry);
}

function sanitizePath(userPath) {
    if (!userPath || typeof userPath !== 'string') {
        throw new Error('Invalid path');
    }
    const normalized = path.normalize(userPath);
    if (normalized.includes('..')) {
        throw new Error('Path traversal detected');
    }
    return normalized;
}

function validateCommand(command) {
    for (const pattern of CONFIG.blockedCommands) {
        if (pattern.test(command)) {
            throw new Error(`Blocked command detected`);
        }
    }
    return true;
}

function execPromise(command, options = {}) {
    return new Promise((resolve, reject) => {
        exec(command, { timeout: 30000, ...options }, (error, stdout, stderr) => {
            if (error) {
                reject(new Error(stderr || error.message));
            } else {
                resolve({ stdout: stdout || '', stderr: stderr || '' });
            }
        });
    });
}

async function getPublicIP() {
    try {
        const { stdout } = await execPromise('curl -s --max-time 5 ifconfig.me 2>/dev/null || curl -s --max-time 5 icanhazip.com 2>/dev/null || curl -s --max-time 5 ipinfo.io/ip 2>/dev/null');
        return stdout.trim() || 'Unknown';
    } catch {
        try {
            const { stdout } = await execPromise('curl -s --max-time 5 ipinfo.io/ip');
            return stdout.trim();
        } catch {
            return 'Unknown';
        }
    }
}

function getPrivateIP() {
    const interfaces = os.networkInterfaces();
    for (const name of Object.keys(interfaces)) {
        for (const iface of interfaces[name]) {
            if (iface.family === 'IPv4' && !iface.internal) {
                return iface.address;
            }
        }
    }
    return 'Unknown';
}

// ============================================================
// AUTH ROUTES
// ============================================================
app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password required' });
        }

        const users = await getUsers();
        const user = users[username];

        if (!user || !(await bcrypt.compare(password, user.password))) {
            auditLog(`Failed login attempt for ${username}`, username, req.ip);
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        req.session.authenticated = true;
        req.session.username = username;
        req.session.role = user.role;
        req.session.lastActivity = Date.now();
        
        auditLog('Successful login', username, req.ip);
        res.json({ success: true, username, role: user.role });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Login failed' });
    }
});

app.post('/api/auth/logout', (req, res) => {
    const username = req.session.username;
    auditLog('Logout', username, req.ip);
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).json({ error: 'Logout failed' });
        }
        res.clearCookie('connect.sid');
        res.json({ success: true });
    });
});

app.get('/api/auth/status', (req, res) => {
    res.json({
        authenticated: !!req.session.authenticated,
        username: req.session.username || null,
        role: req.session.role || null
    });
});

app.get('/api/auth/users', requireAdmin, async (req, res) => {
    try {
        const users = await getUsers();
        const safeUsers = {};
        for (const [username, data] of Object.entries(users)) {
            safeUsers[username] = {
                role: data.role,
                created: data.created || 'Unknown'
            };
        }
        res.json(safeUsers);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/auth/users', requireAdmin, async (req, res) => {
    try {
        const { username, password, role } = req.body;
        
        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password required' });
        }

        if (username.length < 3 || username.length > 32) {
            return res.status(400).json({ error: 'Username must be 3-32 characters' });
        }

        if (password.length < 4) {
            return res.status(400).json({ error: 'Password must be at least 4 characters' });
        }

        if (!/^[a-zA-Z0-9_]+$/.test(username)) {
            return res.status(400).json({ error: 'Username can only contain letters, numbers, and underscores' });
        }

        const users = await getUsers();
        if (users[username]) {
            return res.status(400).json({ error: 'User already exists' });
        }

        users[username] = {
            password: await bcrypt.hash(password, 12),
            role: role === 'admin' ? 'admin' : 'user',
            created: new Date().toISOString()
        };

        await saveUsers(users);
        auditLog(`User created: ${username} (${role})`, req.session.username, req.ip);
        res.json({ success: true, username });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.put('/api/auth/users/:username', requireAdmin, async (req, res) => {
    try {
        const { username } = req.params;
        const { password, role } = req.body;
        
        if (username === 'admin' && role !== 'admin') {
            return res.status(400).json({ error: 'Cannot change admin role' });
        }

        const users = await getUsers();
        if (!users[username]) {
            return res.status(404).json({ error: 'User not found' });
        }

        if (password) {
            users[username].password = await bcrypt.hash(password, 12);
        }
        if (role && ['admin', 'user'].includes(role)) {
            users[username].role = role;
        }

        await saveUsers(users);
        auditLog(`User updated: ${username}`, req.session.username, req.ip);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.delete('/api/auth/users/:username', requireAdmin, async (req, res) => {
    try {
        const { username } = req.params;
        if (username === 'admin') {
            return res.status(400).json({ error: 'Cannot delete admin user' });
        }

        const users = await getUsers();
        if (!users[username]) {
            return res.status(404).json({ error: 'User not found' });
        }

        delete users[username];
        await saveUsers(users);
        auditLog(`User deleted: ${username}`, req.session.username, req.ip);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ============================================================
// DASHBOARD ROUTES
// ============================================================
app.get('/api/dashboard', requireAuth, async (req, res) => {
    try {
        const [cpu, mem, fsSize, time, currentLoad, networkStats] = await Promise.all([
            si.cpu(),
            si.mem(),
            si.fsSize(),
            si.time(),
            si.currentLoad(),
            si.networkStats()
        ]);

        const mainDisk = fsSize[0] || { used: 0, size: 1, use: 0 };
        
        res.json({
            hostname: os.hostname(),
            publicIp: await getPublicIP(),
            privateIp: getPrivateIP(),
            os: `${os.type()} ${os.release()}`,
            osType: os.type(),
            osRelease: os.release(),
            kernel: os.version(),
            arch: os.arch(),
            cpu: `${cpu.manufacturer} ${cpu.brand}`,
            cpuManufacturer: cpu.manufacturer,
            cpuBrand: cpu.brand,
            cores: cpu.cores,
            physicalCores: cpu.physicalCores,
            cpuUsage: currentLoad.currentLoad.toFixed(1),
            ramUsed: (mem.used / 1024 / 1024 / 1024).toFixed(1),
            ramTotal: (mem.total / 1024 / 1024 / 1024).toFixed(1),
            ramPercent: ((mem.used / mem.total) * 100).toFixed(1),
            ramFree: (mem.free / 1024 / 1024 / 1024).toFixed(1),
            swapUsed: (mem.swapused / 1024 / 1024 / 1024).toFixed(1),
            swapTotal: (mem.swaptotal / 1024 / 1024 / 1024).toFixed(1),
            swapPercent: mem.swaptotal > 0 ? ((mem.swapused / mem.swaptotal) * 100).toFixed(1) : '0',
            diskUsed: (mainDisk.used / 1024 / 1024 / 1024).toFixed(1),
            diskTotal: (mainDisk.size / 1024 / 1024 / 1024).toFixed(1),
            diskPercent: mainDisk.use.toFixed(1),
            diskMount: mainDisk.mount || '/',
            uptime: time.uptime,
            loadAvg: os.loadavg(),
            processes: (await si.processes()).all,
            network: networkStats[0] ? {
                interface: networkStats[0].iface,
                rx: (networkStats[0].rx_sec / 1024).toFixed(1),
                tx: (networkStats[0].tx_sec / 1024).toFixed(1),
                rxTotal: (networkStats[0].rx_bytes / 1024 / 1024 / 1024).toFixed(2),
                txTotal: (networkStats[0].tx_bytes / 1024 / 1024 / 1024).toFixed(2)
            } : null
        });
    } catch (error) {
        console.error('Dashboard error:', error);
        res.status(500).json({ error: error.message });
    }
});

// ============================================================
// SYSTEM ROUTES
// ============================================================
app.get('/api/system/info', requireAuth, async (req, res) => {
    try {
        const [system, bios, baseboard, chassis, osInfo, versions] = await Promise.all([
            si.system(),
            si.bios(),
            si.baseboard(),
            si.chassis(),
            si.osInfo(),
            si.versions()
        ]);
        res.json({ system, bios, baseboard, chassis, osInfo, versions });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/system/processes', requireAuth, async (req, res) => {
    try {
        const sortBy = req.query.sort || 'cpu';
        const filter = req.query.filter || '';
        const processes = await si.processes();
        
        let list = processes.list;
        if (filter) {
            const lowerFilter = filter.toLowerCase();
            list = list.filter(p => 
                p.name.toLowerCase().includes(lowerFilter) || 
                (p.pid && p.pid.toString().includes(lowerFilter))
            );
        }
        
        const sorted = list.sort((a, b) => {
            if (sortBy === 'mem') return b.mem - a.mem;
            if (sortBy === 'name') return a.name.localeCompare(b.name);
            if (sortBy === 'pid') return a.pid - b.pid;
            return b.cpu - a.cpu;
        }).slice(0, 50).map(p => ({
            pid: p.pid,
            name: p.name,
            cpu: p.cpu.toFixed(1),
            mem: (p.mem / 1024 / 1024).toFixed(1),
            memPercent: p.mem.toFixed(1),
            state: p.state,
            user: p.user || 'unknown',
            command: p.command || p.name
        }));
        
        res.json(sorted);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/system/kill-process/:pid', requireAuth, async (req, res) => {
    try {
        const pid = parseInt(req.params.pid);
        if (!pid || pid <= 0 || pid === 1) {
            return res.status(400).json({ error: 'Invalid PID' });
        }
        
        try {
            process.kill(pid, 0);
        } catch {
            return res.status(404).json({ error: 'Process not found' });
        }
        
        process.kill(pid, 'SIGKILL');
        auditLog(`Killed process ${pid}`, req.session.username, req.ip);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/system/disk', requireAuth, async (req, res) => {
    try {
        const disks = await si.fsSize();
        const blockDevices = await si.blockDevices();
        res.json({
            mounts: disks.map(d => ({
                fs: d.fs,
                type: d.type,
                size: (d.size / 1024 / 1024 / 1024).toFixed(1),
                used: (d.used / 1024 / 1024 / 1024).toFixed(1),
                available: ((d.size - d.used) / 1024 / 1024 / 1024).toFixed(1),
                use: d.use.toFixed(1),
                mount: d.mount
            })),
            devices: blockDevices.map(d => ({
                name: d.name,
                type: d.type,
                size: d.size ? (d.size / 1024 / 1024 / 1024).toFixed(1) : 0,
                mountpoint: d.mountpoint || 'Not mounted'
            }))
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/system/memory', requireAuth, async (req, res) => {
    try {
        const mem = await si.mem();
        res.json({
            total: (mem.total / 1024 / 1024 / 1024).toFixed(1),
            free: (mem.free / 1024 / 1024 / 1024).toFixed(1),
            used: (mem.used / 1024 / 1024 / 1024).toFixed(1),
            active: (mem.active / 1024 / 1024 / 1024).toFixed(1),
            available: (mem.available / 1024 / 1024 / 1024).toFixed(1),
            swapTotal: (mem.swaptotal / 1024 / 1024 / 1024).toFixed(1),
            swapUsed: (mem.swapused / 1024 / 1024 / 1024).toFixed(1),
            swapFree: (mem.swapfree / 1024 / 1024 / 1024).toFixed(1)
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ============================================================
// PM2/APP MANAGER ROUTES
// ============================================================
app.get('/api/apps/list', requireAuth, async (req, res) => {
    try {
        const { stdout } = await execPromise('pm2 jlist 2>/dev/null || echo "[]"');
        const apps = JSON.parse(stdout || '[]').map(app => ({
            name: app.name,
            status: app.pm2_env?.status || 'stopped',
            pid: app.pid || 0,
            cpu: app.monit?.cpu || 0,
            memory: app.monit?.memory || 0,
            uptime: app.pm2_env?.pm_uptime || 0,
            restarts: app.pm2_env?.restart_time || 0,
            instances: app.pm2_env?.instances || 1,
            execMode: app.pm2_env?.exec_mode || 'fork',
            script: app.pm2_env?.pm_exec_path || '',
            cwd: app.pm2_env?.pm_cwd || ''
        }));
        res.json(apps);
    } catch {
        res.json([]);
    }
});

app.post('/api/apps/:action/:name', requireAuth, async (req, res) => {
    const { action, name } = req.params;
    const allowedActions = ['start', 'stop', 'restart', 'reload', 'delete', 'gracefulReload'];
    
    if (!allowedActions.includes(action)) {
        return res.status(400).json({ error: 'Invalid action' });
    }
    
    if (!name || name.length > 128) {
        return res.status(400).json({ error: 'Invalid app name' });
    }
    
    try {
        const pm2Action = action === 'gracefulReload' ? 'reload' : action;
        const { stdout, stderr } = await execPromise(`pm2 ${pm2Action} ${name} 2>&1`);
        auditLog(`PM2 ${action}: ${name}`, req.session.username, req.ip);
        res.json({ success: true, output: stdout || stderr });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/apps/logs/:name', requireAuth, async (req, res) => {
    const { name } = req.params;
    const lines = Math.min(parseInt(req.query.lines) || 100, CONFIG.maxLogLines);
    
    if (!name || name.length > 128) {
        return res.status(400).json({ error: 'Invalid app name' });
    }
    
    try {
        const { stdout } = await execPromise(`pm2 logs ${name} --nostream --lines ${lines} 2>&1`);
        res.json({ logs: stdout });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/apps/info/:name', requireAuth, async (req, res) => {
    const { name } = req.params;
    
    if (!name || name.length > 128) {
        return res.status(400).json({ error: 'Invalid app name' });
    }
    
    try {
        const { stdout } = await execPromise(`pm2 show ${name} 2>&1`);
        res.json({ info: stdout });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/apps/save', requireAuth, async (req, res) => {
    try {
        const { stdout } = await execPromise('pm2 save 2>&1');
        auditLog('PM2 process list saved', req.session.username, req.ip);
        res.json({ success: true, output: stdout });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ============================================================
// DOCKER ROUTES
// ============================================================
const docker = (() => {
    try {
        return new Docker({ socketPath: '/var/run/docker.sock' });
    } catch {
        return null;
    }
})();

app.get('/api/docker/containers', requireAuth, async (req, res) => {
    if (!docker) return res.status(503).json({ error: 'Docker not available' });
    
    try {
        const containers = await docker.listContainers({ all: true });
        res.json(containers.map(c => ({
            id: c.Id.substring(0, 12),
            names: c.Names.map(n => n.replace('/', '')),
            name: c.Names[0].replace('/', ''),
            image: c.Image,
            status: c.Status,
            state: c.State,
            ports: c.Ports.map(p => ({
                ip: p.IP || '0.0.0.0',
                privatePort: p.PrivatePort,
                publicPort: p.PublicPort,
                type: p.Type
            })),
            created: new Date(c.Created * 1000).toISOString(),
            mounts: c.Mounts?.map(m => ({
                source: m.Source,
                destination: m.Destination,
                mode: m.Mode
            })) || []
        })));
    } catch (error) {
        res.status(500).json({ error: 'Failed to list containers' });
    }
});

app.post('/api/docker/:action/:id', requireAuth, async (req, res) => {
    if (!docker) return res.status(503).json({ error: 'Docker not available' });
    
    const { action, id } = req.params;
    
    if (!id || id.length > 64) {
        return res.status(400).json({ error: 'Invalid container ID' });
    }
    
    try {
        const container = docker.getContainer(id);
        switch(action) {
            case 'start': await container.start(); break;
            case 'stop': await container.stop(); break;
            case 'restart': await container.restart(); break;
            case 'pause': await container.pause(); break;
            case 'unpause': await container.unpause(); break;
            case 'remove': await container.remove({ force: true }); break;
            case 'kill': await container.kill(); break;
            default: return res.status(400).json({ error: 'Invalid action' });
        }
        auditLog(`Docker ${action}: ${id}`, req.session.username, req.ip);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/docker/images', requireAuth, async (req, res) => {
    if (!docker) return res.status(503).json({ error: 'Docker not available' });
    
    try {
        const images = await docker.listImages();
        res.json(images.map(i => ({
            id: i.Id.substring(7, 19),
            tags: i.RepoTags?.filter(t => t !== '<none>:<none>') || [],
            size: (i.Size / 1024 / 1024).toFixed(1),
            created: new Date(i.Created * 1000).toISOString(),
            containers: i.Containers
        })));
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/docker/logs/:id', requireAuth, async (req, res) => {
    if (!docker) return res.status(503).json({ error: 'Docker not available' });
    
    try {
        const container = docker.getContainer(req.params.id);
        const logs = await container.logs({
            stdout: true,
            stderr: true,
            tail: Math.min(parseInt(req.query.lines) || 100, 500),
            timestamps: req.query.timestamps === 'true'
        });
        res.json({ logs: logs.toString('utf8') });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/docker/inspect/:id', requireAuth, async (req, res) => {
    if (!docker) return res.status(503).json({ error: 'Docker not available' });
    
    try {
        const container = docker.getContainer(req.params.id);
        const info = await container.inspect();
        res.json({
            id: info.Id.substring(0, 12),
            name: info.Name.replace('/', ''),
            image: info.Config.Image,
            state: info.State,
            created: info.Created,
            platform: info.Platform || info.Config?.Platform || 'linux',
            env: info.Config?.Env || [],
            cmd: info.Config?.Cmd || [],
            ports: info.NetworkSettings?.Ports || {},
            mounts: info.Mounts || []
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/docker/networks', requireAuth, async (req, res) => {
    if (!docker) return res.status(503).json({ error: 'Docker not available' });
    
    try {
        const networks = await docker.listNetworks();
        res.json(networks.map(n => ({
            id: n.Id.substring(0, 12),
            name: n.Name,
            driver: n.Driver,
            scope: n.Scope,
            containers: Object.keys(n.Containers || {}).length
        })));
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ============================================================
// SERVICE MANAGEMENT ROUTES
// ============================================================
app.get('/api/services/list', requireAuth, async (req, res) => {
    try {
        const { stdout } = await execPromise('systemctl list-units --type=service --all --no-pager --no-legend 2>/dev/null');
        const services = stdout.split('\n')
            .filter(line => line.trim())
            .map(line => {
                const parts = line.trim().split(/\s+/);
                return {
                    name: parts[0]?.replace('.service', '') || '',
                    load: parts[1] || 'unknown',
                    active: parts[2] || 'unknown',
                    sub: parts[3] || 'unknown',
                    description: parts.slice(4).join(' ') || ''
                };
            });
        res.json(services);
    } catch (error) {
        try {
            const { stdout } = await execPromise('service --status-all 2>/dev/null');
            res.json([{ name: 'raw', load: 'loaded', active: 'active', sub: 'running', description: stdout }]);
        } catch {
            res.status(500).json({ error: 'Cannot list services' });
        }
    }
});

app.post('/api/services/:action/:name', requireAuth, async (req, res) => {
    const { action, name } = req.params;
    const allowedActions = ['start', 'stop', 'restart', 'enable', 'disable', 'status'];
    const allowedServices = [
        'nginx', 'apache2', 'httpd', 'docker', 'ssh', 'sshd',
        'postgresql', 'mysql', 'mariadb', 'redis', 'redis-server',
        'fail2ban', 'ufw', 'mongod', 'mongodb', 'pm2'
    ];

    if (!allowedActions.includes(action)) {
        return res.status(400).json({ error: 'Invalid action' });
    }

    if (!name || name.length > 64) {
        return res.status(400).json({ error: 'Invalid service name' });
    }

    if (!allowedServices.some(s => name.toLowerCase().includes(s))) {
        return res.status(400).json({ error: 'Service not in allowed list for security' });
    }

    try {
        const command = action === 'status' 
            ? `systemctl status ${name} --no-pager 2>&1`
            : `sudo systemctl ${action} ${name} 2>&1`;
        const { stdout, stderr } = await execPromise(command);
        auditLog(`Service ${action}: ${name}`, req.session.username, req.ip);
        res.json({ success: true, output: stdout || stderr });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ============================================================
// NGINX MANAGEMENT ROUTES
// ============================================================
app.get('/api/nginx/status', requireAuth, async (req, res) => {
    try {
        const { stdout: activeStatus } = await execPromise('systemctl is-active nginx 2>/dev/null || echo "inactive"');
        const { stdout: enabledStatus } = await execPromise('systemctl is-enabled nginx 2>/dev/null || echo "disabled"');
        
        let configTest = '';
        try {
            const { stdout } = await execPromise('nginx -t 2>&1');
            configTest = stdout;
        } catch (e) {
            configTest = e.message;
        }
        
        res.json({
            active: activeStatus.trim() === 'active',
            enabled: enabledStatus.trim() === 'enabled',
            status: activeStatus.trim(),
            configTest
        });
    } catch {
        res.json({ active: false, enabled: false, status: 'inactive', configTest: 'Nginx not found' });
    }
});

app.post('/api/nginx/:action', requireAuth, async (req, res) => {
    const { action } = req.params;
    const allowedActions = ['start', 'stop', 'restart', 'reload', 'status'];
    
    if (!allowedActions.includes(action)) {
        return res.status(400).json({ error: 'Invalid action' });
    }

    try {
        const command = action === 'status'
            ? 'systemctl status nginx --no-pager 2>&1'
            : `sudo systemctl ${action} nginx 2>&1`;
        const { stdout, stderr } = await execPromise(command);
        auditLog(`Nginx ${action}`, req.session.username, req.ip);
        res.json({ success: true, output: stdout || stderr });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/nginx/logs/:type', requireAuth, async (req, res) => {
    const { type } = req.params;
    const lines = Math.min(parseInt(req.query.lines) || 100, CONFIG.maxLogLines);
    
    if (!['access', 'error'].includes(type)) {
        return res.status(400).json({ error: 'Invalid log type' });
    }
    
    const logFile = `/var/log/nginx/${type}.log`;
    
    try {
        const { stdout } = await execPromise(`tail -n ${lines} ${logFile} 2>/dev/null || echo "Log file not found"`);
        res.json({ logs: stdout });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/nginx/sites', requireAuth, async (req, res) => {
    try {
        const sitesAvailable = await fs.readdir('/etc/nginx/sites-available').catch(() => []);
        const sitesEnabled = await fs.readdir('/etc/nginx/sites-enabled').catch(() => []);
        
        res.json({
            available: sitesAvailable.filter(f => f !== 'default'),
            enabled: sitesEnabled.filter(f => f !== 'default'),
            configPath: '/etc/nginx/sites-available'
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ============================================================
// FILE MANAGER ROUTES
// ============================================================
app.get('/api/files/list', requireAuth, async (req, res) => {
    try {
        const dir = req.query.path || '/';
        const safePath = sanitizePath(dir);
        
        const stat = await fs.stat(safePath);
        if (!stat.isDirectory()) {
            return res.status(400).json({ error: 'Not a directory' });
        }
        
        const files = await fs.readdir(safePath, { withFileTypes: true });
        const fileList = await Promise.all(files.map(async (file) => {
            const fullPath = path.join(safePath, file.name);
            try {
                const stats = await fs.stat(fullPath);
                const ext = path.extname(file.name).toLowerCase();
                return {
                    name: file.name,
                    isDirectory: file.isDirectory(),
                    isFile: file.isFile(),
                    isSymlink: file.isSymbolicLink(),
                    size: stats.size,
                    modified: stats.mtime,
                    accessed: stats.atime,
                    permissions: (stats.mode & parseInt('777', 8)).toString(8).slice(-3),
                    owner: stats.uid,
                    group: stats.gid,
                    extension: ext,
                    hidden: file.name.startsWith('.')
                };
            } catch {
                return {
                    name: file.name,
                    isDirectory: file.isDirectory(),
                    isFile: file.isFile(),
                    isSymlink: file.isSymbolicLink(),
                    size: 0,
                    modified: new Date(),
                    accessed: new Date(),
                    permissions: '000',
                    owner: 0,
                    group: 0,
                    extension: '',
                    hidden: file.name.startsWith('.'),
                    error: true
                };
            }
        }));
        
        fileList.sort((a, b) => {
            if (a.isDirectory !== b.isDirectory) return a.isDirectory ? -1 : 1;
            return a.name.localeCompare(b.name, undefined, { sensitivity: 'base' });
        });
        
        res.json({ path: safePath, files: fileList });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/files/read', requireAuth, async (req, res) => {
    try {
        const filePath = sanitizePath(req.query.path);
        const stats = await fs.stat(filePath);
        
        if (stats.isDirectory()) {
            return res.status(400).json({ error: 'Cannot read directory' });
        }
        
        if (stats.size > 10 * 1024 * 1024) {
            return res.status(400).json({ error: 'File too large to read (>10MB)' });
        }
        
        if (req.query.download === 'true') {
            res.download(filePath);
            return;
        }
        
        const content = await fs.readFile(filePath, 'utf8');
        res.json({
            path: filePath,
            content,
            size: stats.size,
            modified: stats.mtime,
            permissions: (stats.mode & parseInt('777', 8)).toString(8).slice(-3)
        });
    } catch (error) {
        if (error.code === 'ENOENT') {
            return res.status(404).json({ error: 'File not found' });
        }
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/files/write', requireAuth, async (req, res) => {
    try {
        const { path: filePath, content } = req.body;
        
        if (!filePath || content === undefined) {
            return res.status(400).json({ error: 'Path and content required' });
        }
        
        const safePath = sanitizePath(filePath);
        
        if (fsSync.existsSync(safePath)) {
            const dir = path.dirname(safePath);
            const ext = path.extname(safePath);
            const base = path.basename(safePath, ext);
            const backup = path.join(dir, `.${base}.backup.${Date.now()}${ext}`);
            await fs.copyFile(safePath, backup);
        }
        
        await fs.writeFile(safePath, content, 'utf8');
        auditLog(`File written: ${safePath}`, req.session.username, req.ip);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/files/delete', requireAuth, async (req, res) => {
    try {
        const safePath = sanitizePath(req.body.path);
        
        if (['/', '/etc', '/bin', '/sbin', '/usr', '/var', '/boot', '/root'].includes(safePath)) {
            return res.status(400).json({ error: 'Cannot delete system directory' });
        }
        
        const stats = await fs.stat(safePath);
        
        if (stats.isDirectory()) {
            const files = await fs.readdir(safePath);
            if (files.length > 0) {
                const confirm = req.body.recursive;
                if (!confirm) {
                    return res.status(400).json({ error: 'Directory not empty. Use recursive=true to confirm.' });
                }
            }
            await fs.rm(safePath, { recursive: true, force: true });
        } else {
            await fs.unlink(safePath);
        }
        
        auditLog(`Deleted: ${safePath}`, req.session.username, req.ip);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/files/mkdir', requireAuth, async (req, res) => {
    try {
        const safePath = sanitizePath(req.body.path);
        await fs.mkdir(safePath, { recursive: true });
        auditLog(`Directory created: ${safePath}`, req.session.username, req.ip);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/files/move', requireAuth, async (req, res) => {
    try {
        const { source, destination } = req.body;
        
        if (!source || !destination) {
            return res.status(400).json({ error: 'Source and destination required' });
        }
        
        const safeSource = sanitizePath(source);
        const safeDest = sanitizePath(destination);
        
        await fs.rename(safeSource, safeDest);
        auditLog(`Moved: ${safeSource} -> ${safeDest}`, req.session.username, req.ip);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/files/copy', requireAuth, async (req, res) => {
    try {
        const { source, destination } = req.body;
        
        if (!source || !destination) {
            return res.status(400).json({ error: 'Source and destination required' });
        }
        
        const safeSource = sanitizePath(source);
        const safeDest = sanitizePath(destination);
        
        const sourceStats = await fs.stat(safeSource);
        if (sourceStats.isDirectory()) {
            await execPromise(`cp -r "${safeSource}" "${safeDest}"`);
        } else {
            await fs.copyFile(safeSource, safeDest);
        }
        
        auditLog(`Copied: ${safeSource} -> ${safeDest}`, req.session.username, req.ip);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/files/chmod', requireAuth, async (req, res) => {
    try {
        const { path: filePath, mode } = req.body;
        
        if (!filePath || !mode) {
            return res.status(400).json({ error: 'Path and mode required' });
        }
        
        const safePath = sanitizePath(filePath);
        const modeNum = parseInt(mode, 8);
        
        if (isNaN(modeNum) || modeNum < 0 || modeNum > 0o777) {
            return res.status(400).json({ error: 'Invalid mode. Use octal (e.g., 755)' });
        }
        
        await fs.chmod(safePath, modeNum);
        auditLog(`chmod ${mode} ${safePath}`, req.session.username, req.ip);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// File upload
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, CONFIG.uploadsDir);
    },
    filename: (req, file, cb) => {
        const uniqueName = `${Date.now()}-${crypto.randomBytes(8).toString('hex')}-${file.originalname}`;
        cb(null, uniqueName);
    }
});

const upload = multer({
    storage,
    limits: { fileSize: 50 * 1024 * 1024 }
});

app.post('/api/files/upload', requireAuth, upload.single('file'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }
        
        const destPath = req.body.path || '/';
        const safeDest = sanitizePath(path.join(destPath, req.file.originalname));
        
        await fs.copyFile(req.file.path, safeDest);
        await fs.unlink(req.file.path);
        
        auditLog(`Uploaded: ${safeDest} (${(req.file.size / 1024).toFixed(1)} KB)`, req.session.username, req.ip);
        res.json({ success: true, filename: req.file.originalname, size: req.file.size });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ============================================================
// FIREWALL (UFW) ROUTES
// ============================================================
app.get('/api/firewall/status', requireAuth, async (req, res) => {
    try {
        const { stdout } = await execPromise('sudo ufw status verbose 2>&1 || echo "UFW not installed"');
        res.json({
            output: stdout,
            active: stdout.includes('Status: active'),
            installed: !stdout.includes('not installed')
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/firewall/:action', requireAuth, async (req, res) => {
    const { action } = req.params;
    if (!['enable', 'disable'].includes(action)) {
        return res.status(400).json({ error: 'Invalid action' });
    }
    
    try {
        const { stdout } = await execPromise(`sudo ufw --force ${action} 2>&1`);
        auditLog(`Firewall ${action}d`, req.session.username, req.ip);
        res.json({ success: true, output: stdout });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/firewall/rule', requireAuth, async (req, res) => {
    const { port, protocol, action, from, comment } = req.body;
    
    if (!port || !['tcp', 'udp', 'any'].includes(protocol) || !['allow', 'deny', 'reject', 'delete'].includes(action)) {
        return res.status(400).json({ error: 'Invalid parameters' });
    }
    
    const portNum = parseInt(port);
    if (isNaN(portNum) || portNum < 1 || portNum > 65535) {
        return res.status(400).json({ error: 'Invalid port number (1-65535)' });
    }
    
    try {
        let command = `sudo ufw ${action} ${portNum}/${protocol}`;
        if (from && from.trim()) {
            const sanitizedFrom = from.replace(/[^0-9./\-]/g, '');
            command += ` from ${sanitizedFrom}`;
        }
        if (comment && comment.trim()) {
            command += ` comment '${comment.replace(/'/g, "\\'")}'`;
        }
        
        const { stdout } = await execPromise(command + ' 2>&1');
        auditLog(`Firewall rule ${action}: ${portNum}/${protocol}`, req.session.username, req.ip);
        res.json({ success: true, output: stdout });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.delete('/api/firewall/rule/:number', requireAuth, async (req, res) => {
    try {
        const ruleNumber = parseInt(req.params.number);
        if (isNaN(ruleNumber) || ruleNumber < 1) {
            return res.status(400).json({ error: 'Invalid rule number' });
        }
        
        const { stdout } = await execPromise(`sudo ufw --force delete ${ruleNumber} 2>&1`);
        auditLog(`Firewall rule deleted: #${ruleNumber}`, req.session.username, req.ip);
        res.json({ success: true, output: stdout });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ============================================================
// NETWORK TOOLS
// ============================================================
app.get('/api/network/ports', requireAuth, async (req, res) => {
    try {
        const { stdout } = await execPromise('ss -tulnp 2>/dev/null || netstat -tulnp 2>/dev/null || ss -tuln');
        res.json({ output: stdout });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/network/connections', requireAuth, async (req, res) => {
    try {
        const { stdout } = await execPromise('ss -tan state established 2>/dev/null | head -30 || netstat -tan | grep ESTABLISHED | head -30');
        res.json({ output: stdout });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/network/ping', requireAuth, async (req, res) => {
    const { host } = req.body;
    if (!host || host.length > 255) {
        return res.status(400).json({ error: 'Invalid host' });
    }
    
    const sanitizedHost = host.replace(/[^a-zA-Z0-9.\-_]/g, '');
    
    if (!sanitizedHost) {
        return res.status(400).json({ error: 'Invalid host after sanitization' });
    }
    
    try {
        const { stdout } = await execPromise(`ping -c 4 -W 5 ${sanitizedHost} 2>&1`);
        res.json({ output: stdout, success: true });
    } catch (error) {
        res.json({ output: error.message, success: false });
    }
});

app.post('/api/network/traceroute', requireAuth, async (req, res) => {
    const { host } = req.body;
    if (!host || host.length > 255) {
        return res.status(400).json({ error: 'Invalid host' });
    }
    
    const sanitizedHost = host.replace(/[^a-zA-Z0-9.\-_]/g, '');
    
    if (!sanitizedHost) {
        return res.status(400).json({ error: 'Invalid host after sanitization' });
    }
    
    try {
        const { stdout } = await execPromise(`traceroute -m 15 -w 3 ${sanitizedHost} 2>&1 || traceroute -m 15 ${sanitizedHost} 2>&1`);
        res.json({ output: stdout, success: true });
    } catch (error) {
        res.json({ output: error.message, success: false });
    }
});

app.post('/api/network/nslookup', requireAuth, async (req, res) => {
    const { host } = req.body;
    if (!host || host.length > 255) {
        return res.status(400).json({ error: 'Invalid host' });
    }
    
    const sanitizedHost = host.replace(/[^a-zA-Z0-9.\-_]/g, '');
    
    try {
        const { stdout } = await execPromise(`nslookup ${sanitizedHost} 2>&1 || host ${sanitizedHost} 2>&1 || dig ${sanitizedHost} 2>&1`);
        res.json({ output: stdout, success: true });
    } catch (error) {
        res.json({ output: error.message, success: false });
    }
});

app.get('/api/network/interfaces', requireAuth, async (req, res) => {
    try {
        const interfaces = await si.networkInterfaces();
        res.json(interfaces);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ============================================================
// LOG VIEWER ROUTES
// ============================================================
app.get('/api/logs/system', requireAuth, async (req, res) => {
    try {
        const lines = Math.min(parseInt(req.query.lines) || 100, CONFIG.maxLogLines);
        const { stdout } = await execPromise(`journalctl -n ${lines} --no-pager 2>&1 || dmesg | tail -${lines}`);
        res.json({ logs: stdout });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/logs/auth', requireAuth, async (req, res) => {
    try {
        const lines = Math.min(parseInt(req.query.lines) || 100, CONFIG.maxLogLines);
        const authFiles = ['/var/log/auth.log', '/var/log/secure', '/var/log/messages'];
        let logs = '';
        
        for (const file of authFiles) {
            try {
                const { stdout } = await execPromise(`tail -n ${lines} ${file} 2>/dev/null`);
                if (stdout) {
                    logs += `--- ${file} ---\n${stdout}\n`;
                    break;
                }
            } catch {}
        }
        
        res.json({ logs: logs || 'No auth logs found' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/logs/audit', requireAuth, async (req, res) => {
    try {
        const lines = Math.min(parseInt(req.query.lines) || 100, CONFIG.maxLogLines);
        const { stdout } = await execPromise(`tail -n ${lines} ${CONFIG.auditFile} 2>/dev/null || echo "No audit logs yet"`);
        res.json({ logs: stdout });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/logs/custom', requireAuth, async (req, res) => {
    try {
        const logPath = sanitizePath(req.query.path || '/var/log/syslog');
        const lines = Math.min(parseInt(req.query.lines) || 100, CONFIG.maxLogLines);
        const { stdout } = await execPromise(`tail -n ${lines} ${logPath} 2>/dev/null || echo "Cannot read log file"`);
        res.json({ logs: stdout, path: logPath });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ============================================================
// SECURITY CENTER ROUTES
// ============================================================
app.get('/api/security/ssh-logins', requireAuth, async (req, res) => {
    try {
        const { stdout } = await execPromise('last -30 2>/dev/null || lastlog 2>/dev/null');
        res.json({ output: stdout || 'No login history available' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/security/fail2ban', requireAuth, async (req, res) => {
    try {
        const { stdout: status } = await execPromise('sudo fail2ban-client status 2>&1');
        let jails = '';
        try {
            const { stdout } = await execPromise('sudo fail2ban-client status sshd 2>&1');
            jails = stdout;
        } catch {}
        
        res.json({
            output: status + '\n' + jails,
            active: true,
            installed: true
        });
    } catch {
        res.json({
            output: 'Fail2ban not installed or not running',
            active: false,
            installed: false
        });
    }
});

app.get('/api/security/ssh-config', requireAuth, async (req, res) => {
    try {
        const content = await fs.readFile('/etc/ssh/sshd_config', 'utf8');
        const lines = content.split('\n').filter(line => 
            line.trim() && !line.trim().startsWith('#')
        );
        res.json({ config: content, activeSettings: lines });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/security/users', requireAuth, async (req, res) => {
    try {
        const { stdout } = await execPromise('cat /etc/passwd 2>/dev/null | grep -E ":/bin/(bash|sh|zsh)" | cut -d: -f1');
        const users = stdout.split('\n').filter(u => u.trim());
        res.json({ users });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/security/updates', requireAuth, async (req, res) => {
    try {
        const osType = os.type();
        let command;
        
        if (osType === 'Linux') {
            try {
                await execPromise('which apt 2>/dev/null');
                command = 'apt list --upgradable 2>/dev/null | tail -n +2';
            } catch {
                try {
                    await execPromise('which yum 2>/dev/null');
                    command = 'yum check-update 2>/dev/null';
                } catch {
                    return res.json({ output: 'Package manager not detected', updates: [] });
                }
            }
        } else {
            return res.json({ output: 'Update check only available on Linux', updates: [] });
        }
        
        const { stdout } = await execPromise(command);
        const updates = stdout.split('\n').filter(line => line.trim());
        res.json({ output: stdout, updateCount: updates.length, updates });
    } catch (error) {
        res.json({ output: 'No updates available or check failed', updateCount: 0, updates: [] });
    }
});

// ============================================================
// BACKUP ROUTES
// ============================================================
app.post('/api/backup/create', requireAuth, async (req, res) => {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const backupName = req.body.name || `backup-${timestamp}`;
    const backupFile = path.join(CONFIG.backupsDir, `${backupName}.tar.gz`);
    const includePaths = req.body.paths || '/etc /home /var/www /opt';
    
    try {
        const pathsArray = includePaths.split(' ').filter(p => p && fsSync.existsSync(p));
        if (pathsArray.length === 0) {
            return res.status(400).json({ error: 'No valid paths to backup' });
        }
        
        const excludeArgs = (req.body.exclude || 'node_modules,.cache,.npm').split(',')
            .map(e => `--exclude=${e.trim()}`).join(' ');
        
        const { stdout } = await execPromise(`tar ${excludeArgs} -czf "${backupFile}" ${pathsArray.join(' ')} 2>&1`);
        
        const stats = await fs.stat(backupFile);
        auditLog(`Backup created: ${backupName} (${(stats.size / 1024 / 1024).toFixed(1)} MB)`, req.session.username, req.ip);
        res.json({
            success: true,
            file: `${backupName}.tar.gz`,
            size: stats.size,
            path: backupFile
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/backup/list', requireAuth, async (req, res) => {
    try {
        const files = await fs.readdir(CONFIG.backupsDir);
        const backups = await Promise.all(
            files.filter(f => f.endsWith('.tar.gz') || f.endsWith('.tgz') || f.endsWith('.zip'))
                .map(async (file) => {
                    const filePath = path.join(CONFIG.backupsDir, file);
                    const stats = await fs.stat(filePath);
                    return {
                        name: file,
                        size: stats.size,
                        date: stats.mtime,
                        path: filePath,
                        sizeFormatted: stats.size > 1024 * 1024 * 1024
                            ? (stats.size / 1024 / 1024 / 1024).toFixed(2) + ' GB'
                            : (stats.size / 1024 / 1024).toFixed(1) + ' MB'
                    };
                })
        );
        backups.sort((a, b) => b.date - a.date);
        res.json(backups);
    } catch {
        res.json([]);
    }
});

app.get('/api/backup/download/:filename', requireAuth, (req, res) => {
    const filename = path.basename(req.params.filename);
    const filePath = path.join(CONFIG.backupsDir, filename);
    
    if (!fsSync.existsSync(filePath)) {
        return res.status(404).json({ error: 'Backup not found' });
    }
    
    res.download(filePath, filename);
});

app.delete('/api/backup/:filename', requireAuth, async (req, res) => {
    try {
        const filename = path.basename(req.params.filename);
        const filePath = path.join(CONFIG.backupsDir, filename);
        
        if (!fsSync.existsSync(filePath)) {
            return res.status(404).json({ error: 'Backup not found' });
        }
        
        await fs.unlink(filePath);
        auditLog(`Backup deleted: ${filename}`, req.session.username, req.ip);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ============================================================
// MONITORING ROUTES
// ============================================================
app.get('/api/monitoring/history', requireAuth, async (req, res) => {
    try {
        const [currentLoad, mem, fsSize, netStats] = await Promise.all([
            si.currentLoad(),
            si.mem(),
            si.fsSize(),
            si.networkStats()
        ]);
        
        const mainDisk = fsSize[0] || { used: 0, size: 1, use: 0 };
        
        res.json({
            timestamp: Date.now(),
            cpu: currentLoad.currentLoad,
            cpuCores: currentLoad.cpus.map((c, i) => ({
                core: i,
                load: c.load,
                speed: c.speed
            })),
            ram: {
                used: (mem.used / 1024 / 1024 / 1024).toFixed(2),
                total: (mem.total / 1024 / 1024 / 1024).toFixed(2),
                percent: ((mem.used / mem.total) * 100).toFixed(1),
                free: (mem.free / 1024 / 1024 / 1024).toFixed(2)
            },
            disk: {
                used: (mainDisk.used / 1024 / 1024 / 1024).toFixed(2),
                total: (mainDisk.size / 1024 / 1024 / 1024).toFixed(2),
                percent: mainDisk.use.toFixed(1)
            },
            network: netStats[0] ? {
                rx: (netStats[0].rx_sec / 1024).toFixed(2),
                tx: (netStats[0].tx_sec / 1024).toFixed(2)
            } : null
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/monitoring/cpu-details', requireAuth, async (req, res) => {
    try {
        const cpuLoad = await si.currentLoad();
        const cpuInfo = await si.cpu();
        
        res.json({
            cores: cpuLoad.cpus.map((c, i) => ({
                core: i,
                load: c.load.toFixed(1),
                speed: c.speed
            })),
            average: cpuLoad.currentLoad.toFixed(1),
            model: cpuInfo.brand,
            physicalCores: cpuInfo.physicalCores,
            speed: cpuInfo.speed
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/monitoring/temperature', requireAuth, async (req, res) => {
    try {
        const temp = await si.cpuTemperature();
        res.json({
            main: temp.main,
            cores: temp.cores || [],
            max: temp.max
        });
    } catch (error) {
        res.json({ main: 0, cores: [], max: 0, error: 'Temperature sensors not available' });
    }
});

// ============================================================
// POWER CONTROLS
// ============================================================
app.post('/api/power/:action', requireAuth, async (req, res) => {
    const { action } = req.params;
    
    if (!['reboot', 'shutdown'].includes(action)) {
        return res.status(400).json({ error: 'Invalid action' });
    }

    auditLog(`Server ${action} initiated by ${req.session.username}`, req.session.username, req.ip);
    
    if (action === 'reboot') {
        res.json({ success: true, message: 'Server is rebooting. You will be disconnected.' });
        setTimeout(() => {
            exec('sudo reboot');
        }, 1000);
    } else {
        res.json({ success: true, message: 'Server is shutting down. Goodbye!' });
        setTimeout(() => {
            exec('sudo shutdown -h now');
        }, 1000);
    }
});

// ============================================================
// WEBSOCKET HANDLER
// ============================================================
wss.on('connection', (ws, req) => {
    CONFIG.wsClients.add(ws);
    const wsTerminalSessions = new Map();

    ws.on('message', async (message) => {
        try {
            const data = JSON.parse(message);

            if (data.type === 'terminal' && data.action === 'init') {
                const sessionId = data.sessionId || Date.now().toString();
                
                if (wsTerminalSessions.has(sessionId)) {
                    wsTerminalSessions.get(sessionId).kill();
                }

                const term = pty.spawn('bash', [], {
                    name: 'xterm-color',
                    cols: data.cols || 80,
                    rows: data.rows || 24,
                    cwd: process.env.HOME || '/root',
                    env: process.env
                });

                wsTerminalSessions.set(sessionId, term);
                CONFIG.terminalSessions.set(sessionId, term);

                term.on('data', (chunk) => {
                    if (ws.readyState === WebSocket.OPEN) {
                        ws.send(JSON.stringify({
                            type: 'terminal',
                            sessionId,
                            data: chunk
                        }));
                    }
                });

                term.on('exit', () => {
                    wsTerminalSessions.delete(sessionId);
                    CONFIG.terminalSessions.delete(sessionId);
                    if (ws.readyState === WebSocket.OPEN) {
                        ws.send(JSON.stringify({
                            type: 'terminal',
                            sessionId,
                            action: 'closed'
                        }));
                    }
                });

                ws.send(JSON.stringify({
                    type: 'terminal',
                    sessionId,
                    action: 'ready'
                }));

            } else if (data.type === 'terminal' && data.action === 'resize') {
                const term = wsTerminalSessions.get(data.sessionId);
                if (term && data.cols && data.rows) {
                    term.resize(data.cols, data.rows);
                }

            } else if (data.type === 'terminal' && data.action === 'kill') {
                const term = wsTerminalSessions.get(data.sessionId);
                if (term) {
                    term.kill();
                    wsTerminalSessions.delete(data.sessionId);
                    CONFIG.terminalSessions.delete(data.sessionId);
                }

            } else if (data.type === 'terminal' && data.sessionId && data.data !== undefined) {
                const term = wsTerminalSessions.get(data.sessionId);
                if (term) {
                    if (data.data === '\x03') {
                        term.kill('SIGINT');
                        const newTerm = pty.spawn('bash', [], {
                            name: 'xterm-color',
                            cols: 80,
                            rows: 24,
                            cwd: process.env.HOME || '/root',
                            env: process.env
                        });
                        wsTerminalSessions.set(data.sessionId, newTerm);
                        CONFIG.terminalSessions.set(data.sessionId, newTerm);
                        newTerm.on('data', (chunk) => {
                            if (ws.readyState === WebSocket.OPEN) {
                                ws.send(JSON.stringify({
                                    type: 'terminal',
                                    sessionId: data.sessionId,
                                    data: chunk
                                }));
                            }
                        });
                    } else {
                        try {
                            validateCommand(data.data);
                            term.write(data.data);
                        } catch {
                            ws.send(JSON.stringify({
                                type: 'terminal',
                                sessionId: data.sessionId,
                                data: '\r\n[BLOCKED] Command not allowed for security reasons\r\n'
                            }));
                        }
                    }
                }
            }
        } catch (error) {
            console.error('WebSocket message error:', error.message);
        }
    });

    ws.on('close', () => {
        CONFIG.wsClients.delete(ws);
        for (const [id, term] of wsTerminalSessions) {
            term.kill();
            CONFIG.terminalSessions.delete(id);
        }
        wsTerminalSessions.clear();
    });

    ws.on('error', (error) => {
        console.error('WebSocket error:', error.message);
    });
});

// Metrics broadcast
let metricsInterval;

function broadcastMetrics() {
    if (CONFIG.wsClients.size === 0) return;

    Promise.all([
        si.currentLoad(),
        si.mem(),
        si.fsSize(),
        si.networkStats()
    ]).then(([cpu, mem, disks, netStats]) => {
        const metrics = {
            type: 'metrics',
            timestamp: Date.now(),
            cpu: cpu.currentLoad.toFixed(1),
            cpuCores: cpu.cpus.map(c => ({
                load: c.load.toFixed(1),
                speed: c.speed
            })),
            ram: {
                used: (mem.used / 1024 / 1024 / 1024).toFixed(1),
                total: (mem.total / 1024 / 1024 / 1024).toFixed(1),
                percent: ((mem.used / mem.total) * 100).toFixed(1),
                free: (mem.free / 1024 / 1024 / 1024).toFixed(1)
            },
            swap: {
                used: (mem.swapused / 1024 / 1024 / 1024).toFixed(1),
                total: (mem.swaptotal / 1024 / 1024 / 1024).toFixed(1),
                percent: mem.swaptotal > 0 ? ((mem.swapused / mem.swaptotal) * 100).toFixed(1) : '0'
            },
            disk: disks[0] ? {
                used: (disks[0].used / 1024 / 1024 / 1024).toFixed(1),
                total: (disks[0].size / 1024 / 1024 / 1024).toFixed(1),
                percent: disks[0].use.toFixed(1),
                mount: disks[0].mount
            } : null,
            network: netStats[0] ? {
                rx: (netStats[0].rx_sec / 1024).toFixed(2),
                tx: (netStats[0].tx_sec / 1024).toFixed(2),
                iface: netStats[0].iface
            } : null,
            uptime: os.uptime(),
            loadAvg: os.loadavg()
        };

        const message = JSON.stringify(metrics);
        CONFIG.wsClients.forEach(client => {
            if (client.readyState === WebSocket.OPEN) {
                try {
                    client.send(message);
                } catch {}
            }
        });
    }).catch(() => {});
}

metricsInterval = setInterval(broadcastMetrics, 3000);

// ============================================================
// SERVE FRONTEND
// ============================================================
app.use(express.static(path.join(__dirname, 'public'), {
    maxAge: '1h',
    etag: true
}));

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// 404 handler
app.use((req, res) => {
    if (req.path.startsWith('/api/')) {
        res.status(404).json({ error: 'API endpoint not found' });
    } else {
        res.status(404).send('Not found');
    }
});

// Error handler
app.use((err, req, res, next) => {
    console.error('Unhandled error:', err.message);
    res.status(500).json({ error: 'Internal server error' });
});

// ============================================================
// START SERVER
// ============================================================
server.listen(CONFIG.port, '0.0.0.0', () => {
    console.log('\n' + '='.repeat(50));
    console.log('  \x1b[32m⚡ VPS Control Panel v2.0\x1b[0m');
    console.log('='.repeat(50));
    console.log(`  \x1b[36m➜\x1b[0m URL:    http://0.0.0.0:${CONFIG.port}`);
    console.log(`  \x1b[36m➜\x1b[0m Login:  admin / admin`);
    console.log(`  \x1b[33m⚠\x1b[0m  Change default password immediately!`);
    console.log('='.repeat(50) + '\n');

    auditLog('VPS Panel started successfully');
});

// Graceful shutdown
function gracefulShutdown(signal) {
    console.log(`\n\x1b[33m${signal} received. Shutting down gracefully...\x1b[0m`);
    
    clearInterval(metricsInterval);
    
    CONFIG.terminalSessions.forEach(term => {
        try { term.kill(); } catch {}
    });
    CONFIG.terminalSessions.clear();
    
    CONFIG.wsClients.forEach(client => {
        try { client.close(); } catch {}
    });
    CONFIG.wsClients.clear();
    
    auditLog('VPS Panel stopped');
    
    server.close(() => {
        console.log('\x1b[32mServer closed successfully\x1b[0m');
        process.exit(0);
    });
    
    setTimeout(() => {
        console.log('\x1b[31mForced shutdown\x1b[0m');
        process.exit(1);
    }, 10000);
}

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));
process.on('SIGHUP', () => gracefulShutdown('SIGHUP'));

module.exports = { app, server };
