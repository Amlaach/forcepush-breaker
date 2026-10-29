"use strict";

const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("unforceDesktop", {
  isElectron: true,
  platform: process.platform,
  getBackendUrl: () => ipcRenderer.invoke("unforce:get-backend-url"),
  readClipboard: () => ipcRenderer.invoke("unforce:read-clipboard"),
  writeClipboard: (text) => ipcRenderer.invoke("unforce:write-clipboard", text),
  selectDirectoryDialog: () => ipcRenderer.invoke("unforce:select-directory"),
  saveFileDialog: (options) => ipcRenderer.invoke("unforce:save-file", options),
  openExternal: (url) => ipcRenderer.invoke("unforce:open-external", url),
  getAppInfo: () => ipcRenderer.invoke("unforce:app-info"),
  minimize: () => ipcRenderer.send("unforce:win-minimize"),
  maximize: () => ipcRenderer.send("unforce:win-maximize"),
  close: () => ipcRenderer.send("unforce:win-close"),
});
