const { app, BrowserWindow, ipcMain, powerSaveBlocker } = require('electron')
const path = require('path')
const crypto = require('crypto')
const { spawn } = require('child_process')
const { resolvePackagedBackendPath } = require('./backend_runtime')

let powerSaveId = null;
let backendProcess = null;

const isDev = !app.isPackaged;
const sessionApiToken =
  process.env.KOVIL_API_TOKEN || (isDev ? '' : crypto.randomBytes(32).toString('hex'));

if (sessionApiToken) {
  process.env.KOVIL_API_TOKEN = sessionApiToken;
}

function startBackend() {
  if (isDev) {
    console.log('Running in Dev mode. Backend should be started manually.');
    return;
  }

  let backendPath;
  try {
    backendPath = resolvePackagedBackendPath(process.resourcesPath, process.platform);
  } catch (err) {
    console.error(`Failed to resolve packaged backend: ${err.message}`);
    return;
  }

  console.log(`Starting backend from: ${backendPath}`);

  backendProcess = spawn(backendPath, [], {
    cwd: path.dirname(backendPath), // Define o diretório de trabalho para onde o exe está
    env: {
      ...process.env,
      KOVIL_API_TOKEN: sessionApiToken
    }
  });

  backendProcess.stdout.on('data', (data) => {
    console.log(`Backend: ${data}`);
  });

  backendProcess.stderr.on('data', (data) => {
    console.error(`Backend Error: ${data}`);
  });

  backendProcess.on('error', (error) => {
    console.error(`Backend process failed to start: ${error.message}`);
    backendProcess = null;
  });

  backendProcess.on('close', (code) => {
    console.log(`Backend process exited with code ${code}`);
    backendProcess = null;
  });
}

function killBackend() {
  if (backendProcess) {
    console.log('Killing backend process...');
    // Tenta matar o processo de forma graciosa primeiro
    backendProcess.kill(); 
    
    // No Windows, às vezes o processo filho (spawn) não morre completamente se tiver subprocessos
    // Podemos forçar um taskkill se necessário, mas geralmente .kill() funciona para spawn direto.
    // Se o backend spawnar outros processos (como hashcat), eles podem ficar órfãos se o backend não tratá-los.
    // O backend Python deve lidar com seus próprios subprocessos no shutdown.
    
    backendProcess = null;
  }
}

function createWindow () {
  const win = new BrowserWindow({
    width: 1200,
    height: 800,
    title: 'KOVIL MAP',
    frame: false, // Remove a moldura padrão do Windows
    autoHideMenuBar: true, // Esconde a barra de menu (File, Edit, etc.)
    backgroundColor: '#050505', // Cor de fundo para evitar flash branco
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      nodeIntegration: false,
      contextIsolation: true,
      sandbox: true
    }
  })

  win.webContents.setWindowOpenHandler(() => ({ action: 'deny' }))
  win.webContents.on('will-navigate', (event, targetUrl) => {
    const currentUrl = win.webContents.getURL()
    if (currentUrl && targetUrl !== currentUrl) {
      event.preventDefault()
    }
  })

  // Configurar permissões automaticamente (especialmente Geolocalização)
  win.webContents.session.setPermissionRequestHandler((webContents, permission, callback) => {
    if (permission === 'geolocation') {
      callback(true)
    } else {
      callback(false)
    }
  })

  win.loadFile('src/index.html')
  // win.webContents.openDevTools()

  // IPC Listeners para controle da janela
  ipcMain.on('minimize-window', () => {
    win.minimize()
  })

  ipcMain.on('close-window', () => {
    win.close()
  })
  
  ipcMain.on('maximize-window', () => {
    if (win.isMaximized()) {
      win.unmaximize()
    } else {
      win.maximize()
    }
  })

  // --- NOVOS RECURSOS ---

  // Controle da Barra de Progresso na Taskbar
  // value: 0 a 1 (progresso), -1 (remove barra)
  // mode: 'normal', 'error', 'paused', 'indeterminate'
  ipcMain.on('set-progress-bar', (event, { value, mode }) => {
    win.setProgressBar(value, { mode: mode || 'normal' })
  })

  // Bloqueador de Suspensão (Power Save Blocker)
  ipcMain.on('toggle-power-save', (event, enable) => {
    if (enable) {
      if (powerSaveId === null) {
        powerSaveId = powerSaveBlocker.start('prevent-app-suspension')
        console.log('Power Save Blocker: ENABLED')
      }
    } else {
      if (powerSaveId !== null) {
        powerSaveBlocker.stop(powerSaveId)
        powerSaveId = null
        console.log('Power Save Blocker: DISABLED')
      }
    }
  })
}

app.whenReady().then(() => {
  startBackend();
  createWindow()

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow()
    }
  })
})

app.on('window-all-closed', () => {
  killBackend();
  if (process.platform !== 'darwin') {
    app.quit()
  }
})

app.on('will-quit', () => {
  killBackend();
});

// Garante que o backend morra mesmo em caso de crash do processo principal
process.on('exit', () => {
    killBackend();
});

process.on('uncaughtException', (err) => {
    console.error('Uncaught Exception:', err);
    killBackend();
    app.quit(); // Opcional: forçar saída após erro não tratado
});

process.on('SIGINT', () => {
    killBackend();
    app.quit();
});

process.on('SIGTERM', () => {
    killBackend();
    app.quit();
});
