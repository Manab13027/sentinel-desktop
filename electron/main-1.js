// Sentinel - Electron main process.
// Spawns the bundled Python scanning engine on 127.0.0.1 with a random token,
// hosts the dark UI, raises native notifications and keeps monitoring from the tray.
const { app, BrowserWindow, ipcMain, Notification, Tray, Menu, dialog, nativeImage, shell } = require('electron');
const { spawn, execFile } = require('child_process');
const path = require('path');
const fs = require('fs');
const net = require('net');
const crypto = require('crypto');

const isMac = process.platform === 'darwin';
const isWin = process.platform === 'win32';
let win = null;
let tray = null;
let backend = null;
let quitting = false;
const cfg = { port: null, token: crypto.randomBytes(24).toString('hex'), elevated: false };

const PROJECT_ROOT = path.join(__dirname, '..');

// Same location the Python engine uses (store.data_dir), shared by normal and elevated engines.
function dataDir() {
  const d = isWin ? path.join(process.env.APPDATA || app.getPath('home'), 'Sentinel')
    : isMac ? path.join(app.getPath('home'), 'Library', 'Application Support', 'Sentinel')
    : path.join(app.getPath('home'), '.sentinel');
  fs.mkdirSync(d, { recursive: true });
  return d;
}

// Absolute path to an executable: elevated shells run from '/' with root's PATH,
// so relative paths (.venv/bin/python) and bare names (python3) would resolve differently.
function absoluteExe(cmd) {
  if (path.isAbsolute(cmd)) return cmd;
  if (cmd.includes('/') || cmd.includes('\\')) {
    const fromCwd = path.resolve(process.cwd(), cmd);
    return fs.existsSync(fromCwd) ? fromCwd : path.resolve(PROJECT_ROOT, cmd);
  }
  try {
    const { execFileSync } = require('child_process');
    const out = execFileSync(isWin ? 'where' : '/usr/bin/which', [cmd], { encoding: 'utf8' }).split(/\r?\n/)[0].trim();
    if (out) return out;
  } catch (_) { /* fall through */ }
  return cmd;
}

function backendCommand() {
  const exe = isWin ? 'sentinel-backend.exe' : 'sentinel-backend';
  const packaged = path.join(process.resourcesPath || '', 'backend', exe);
  if (app.isPackaged && fs.existsSync(packaged)) return { cmd: packaged, args: [] };
  // development: run the Python source directly (prefer the project's .venv if present)
  const venvPy = path.join(PROJECT_ROOT, '.venv', isWin ? 'Scripts/python.exe' : 'bin/python');
  const py = process.env.SENTINEL_PYTHON || (fs.existsSync(venvPy) ? venvPy : (isWin ? 'python' : 'python3'));
  return { cmd: absoluteExe(py), args: [path.join(PROJECT_ROOT, 'backend', 'server.py')] };
}

function freePort() {
  return new Promise((resolve, reject) => {
    const s = net.createServer();
    s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => resolve(p)); });
    s.on('error', reject);
  });
}

async function waitHealthy(port, ms = 20000) {
  const until = Date.now() + ms;
  while (Date.now() < until) {
    try {
      const r = await fetch(`http://127.0.0.1:${port}/api/health`, { headers: { 'X-Sentinel-Token': cfg.token } });
      if (r.ok) return true;
    } catch (_) { /* not up yet */ }
    await new Promise(r => setTimeout(r, 300));
  }
  return false;
}

async function startBackend() {
  const { cmd, args } = backendCommand();
  const port = await freePort();
  backend = spawn(cmd, [...args, '--port', String(port), '--token', cfg.token, '--parent-pid', String(process.pid)], {
    windowsHide: true, env: { ...process.env, PYTHONUNBUFFERED: '1', SENTINEL_DATA: dataDir() },
  });
  backend.stderr.on('data', d => console.error('[backend]', d.toString().trim()));
  backend.on('exit', code => {
    console.log('[backend] exited', code);
    if (!quitting && !cfg.elevated && win) win.webContents.send('backend-down');
  });
  if (!(await waitHealthy(port))) throw new Error('Scanning engine failed to start: ' + cmd);
  cfg.port = port;
  cfg.elevated = false;
}

// macOS privacy protection (TCC) stops root processes started from a password prompt reading
// ~/Documents, ~/Desktop and ~/Downloads. In development the engine and its .venv live in the project
// folder, so copy the engine + psutil to Application Support and run the base Python interpreter.
// (The installed app keeps its engine inside Sentinel.app, which is not protected, so it is used as-is.)
function adminEngineCommand() {
  const base = backendCommand();
  if (app.isPackaged && path.isAbsolute(base.cmd) && base.cmd.startsWith(process.resourcesPath)) return base;
  const { execFileSync } = require('child_process');
  const info = JSON.parse(execFileSync(base.cmd, ['-c',
    'import sys, os, json, psutil; print(json.dumps({"py": os.path.realpath(getattr(sys, "_base_executable", sys.executable)), "psutil": os.path.dirname(psutil.__file__)}))'],
    { encoding: 'utf8' }).trim().split('\n').pop());
  const dest = path.join(dataDir(), 'admin-engine');
  fs.rmSync(dest, { recursive: true, force: true });
  fs.cpSync(path.join(PROJECT_ROOT, 'backend'), path.join(dest, 'backend'), {
    recursive: true, filter: src => !src.includes('__pycache__') && !src.includes(path.sep + 'tests'),
  });
  fs.cpSync(info.psutil, path.join(dest, 'lib', 'psutil'), { recursive: true });
  return { cmd: info.py, args: ['-s', path.join(dest, 'backend', 'server.py')], pyPath: path.join(dest, 'lib') };
}

// macOS/Linux: restart the engine with administrator rights (system-wide socket visibility).
// Windows builds request admin via the app manifest instead.
async function elevateBackend() {
  if (isWin) return { ok: false, error: 'On Windows, right-click Sentinel and choose "Run as administrator".' };
  let cmd, args, pyPath = '';
  try { ({ cmd, args, pyPath } = adminEngineCommand()); }
  catch (e) { return { ok: false, error: 'Could not prepare admin engine: ' + (e.message || e) }; }
  const port = await freePort();
  const q = s => `'${String(s).replace(/'/g, `'\\''`)}'`;
  const log = path.join(dataDir(), 'engine-admin.log');
  // No nohup: macOS 'do shell script' has no console, so nohup refuses to run. There is no tty to
  // send SIGHUP either; detaching stdin/stdout is enough for the engine to outlive the prompt.
  const line = `SENTINEL_DATA=${q(dataDir())} PYTHONUNBUFFERED=1 ${pyPath ? 'PYTHONPATH=' + q(pyPath) + ' ' : ''}` +
    [cmd, ...args, '--port', port, '--token', cfg.token, '--parent-pid', process.pid].map(q).join(' ') +
    ` </dev/null >${q(log)} 2>&1 &`;
  return new Promise(resolve => {
    const runner = isMac
      ? ['osascript', ['-e', `do shell script "${line.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}" with administrator privileges`]]
      : ['pkexec', ['/bin/sh', '-c', line]];
    execFile(runner[0], runner[1], async (err, _out, stderr) => {
      if (err) {
        const cancelled = /-128|cancel/i.test(String(stderr || err.message));
        return resolve({ ok: false, error: cancelled ? 'Administrator permission was not granted.' : `Could not start admin engine: ${String(stderr || err.message).trim()}` });
      }
      if (!(await waitHealthy(port))) {
        let tail = '';
        try { tail = fs.readFileSync(log, 'utf8').trim().split('\n').slice(-3).join('\n'); } catch (_) {}
        return resolve({ ok: false, error: `Admin engine did not start. ${tail || 'See ' + log}` });
      }
      const old = backend; cfg.elevated = true; cfg.port = port; backend = null;
      try { old && old.kill(); } catch (_) {}
      resolve({ ok: true, port });
    });
  });
}

function stopBackend() {
  quitting = true;
  try { backend && backend.kill(); } catch (_) {}
  if (cfg.elevated && cfg.port) {
    // the elevated engine runs as root and cannot be killed by us: ask it to exit (it also watches our PID)
    fetch(`http://127.0.0.1:${cfg.port}/api/shutdown`, { method: 'POST', headers: { 'X-Sentinel-Token': cfg.token } }).catch(() => {});
  }
}

function createWindow() {
  win = new BrowserWindow({
    width: 1480, height: 940, minWidth: 1100, minHeight: 700,
    backgroundColor: '#0d0f12',
    title: 'Sentinel',
    titleBarStyle: isMac ? 'hiddenInset' : 'default',
    autoHideMenuBar: true,
    icon: path.join(__dirname, '..', 'build', 'icon.png'),
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true, nodeIntegration: false, sandbox: true,
    },
  });
  win.loadFile(path.join(__dirname, '..', 'renderer', 'index.html'));
  // no external navigation: the app is fully offline
  win.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  win.webContents.on('will-navigate', e => e.preventDefault());
  win.on('close', e => {
    if (!quitting && tray) { e.preventDefault(); win.hide(); }
  });
}

function createTray() {
  try {
    const img = isMac
      ? nativeImage.createFromPath(path.join(__dirname, '..', 'build', 'trayTemplate.png'))   // auto-tinted menu-bar template
      : nativeImage.createFromPath(path.join(__dirname, '..', 'build', 'icon.png')).resize({ width: 16, height: 16 });
    tray = new Tray(img);
    tray.setToolTip('Sentinel - monitoring connections');
    tray.setContextMenu(Menu.buildFromTemplate([
      { label: 'Open Sentinel', click: () => { win.show(); win.focus(); } },
      { type: 'separator' },
      { label: 'Quit (stop monitoring)', click: () => { quitting = true; app.quit(); } },
    ]));
    tray.on('click', () => { win.show(); win.focus(); });
  } catch (e) { tray = null; }
}

ipcMain.handle('config', () => ({ port: cfg.port, token: cfg.token, platform: process.platform, elevated: cfg.elevated, version: app.getVersion() }));
ipcMain.handle('notify', (_e, { title, body }) => {
  if (Notification.isSupported()) {
    const n = new Notification({ title, body, silent: false });
    n.on('click', () => { win.show(); win.focus(); win.webContents.send('navigate', 'network'); });
    n.show();
  }
});
ipcMain.handle('elevate', () => elevateBackend());
ipcMain.handle('open-file', async (_e, filters) => {
  const r = await dialog.showOpenDialog(win, { properties: ['openFile'], filters: filters || [{ name: 'Text/JSON', extensions: ['txt', 'json', 'csv', 'list', 'hosts'] }] });
  if (r.canceled || !r.filePaths[0]) return null;
  const p = r.filePaths[0];
  const stat = fs.statSync(p);
  if (stat.size > 20 * 1024 * 1024) throw new Error('File too large (max 20 MB)');
  return { name: path.basename(p), text: fs.readFileSync(p, 'utf8') };
});
ipcMain.handle('save-file', async (_e, { name, text }) => {
  const r = await dialog.showSaveDialog(win, { defaultPath: name });
  if (r.canceled || !r.filePath) return false;
  fs.writeFileSync(r.filePath, text, 'utf8');
  return true;
});
ipcMain.handle('show-item', (_e, p) => { if (p && fs.existsSync(p)) shell.showItemInFolder(p); });

const single = app.requestSingleInstanceLock();
if (!single) app.quit();
app.on('second-instance', () => { if (win) { win.show(); win.focus(); } });

app.whenReady().then(async () => {
  try {
    await startBackend();
  } catch (e) {
    dialog.showErrorBox('Sentinel', String(e.message || e));
    app.quit();
    return;
  }
  createWindow();
  createTray();
  app.on('activate', () => { if (win) win.show(); });
});

app.on('before-quit', () => { quitting = true; stopBackend(); });
app.on('window-all-closed', () => { if (!tray) app.quit(); });
