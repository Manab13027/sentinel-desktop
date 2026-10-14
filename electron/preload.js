const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('sentinel', {
  config: () => ipcRenderer.invoke('config'),
  notify: (title, body) => ipcRenderer.invoke('notify', { title, body }),
  elevate: () => ipcRenderer.invoke('elevate'),
  openFile: filters => ipcRenderer.invoke('open-file', filters),
  saveFile: (name, text) => ipcRenderer.invoke('save-file', { name, text }),
  showItem: p => ipcRenderer.invoke('show-item', p),
  openUrl: u => ipcRenderer.invoke('open-url', u),
  onNavigate: cb => ipcRenderer.on('navigate', (_e, v) => cb(v)),
  onBackendDown: cb => ipcRenderer.on('backend-down', () => cb()),
});
