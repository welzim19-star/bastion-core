/**
 * Bastion Audit v2.0 Enterprise - UI Controller, Smart Categorization, Tactical Dossier & Cyber CFTV HUD
 */
document.addEventListener('DOMContentLoaded', () => {
  const CATEGORY_DEFINITIONS = [
    { id: 'all',          label: 'Todos',              icon: '🌐' },
    { id: 'cameras',      label: 'Câmeras',            icon: '📹' },
    { id: 'mobile',       label: 'Celulares',          icon: '📱' },
    { id: 'network',      label: 'Roteadores & Rede',  icon: '🛜' },
    { id: 'computers',    label: 'Computadores',       icon: '💻' },
    { id: 'iot',          label: 'Smart TV & Casa',    icon: '📺' },
    { id: 'unclassified', label: 'Outros',             icon: '❓' },
  ];

  const App = {
    radar: null,
    devices: [],
    currentFilter: 'all',
    currentCategory: 'all',
    overviewCategory: 'all',
    viewMode: 'grouped', // 'grouped' | 'flat'
    searchQuery: '',
    pollInterval: null,

    // Estado de Aparência, Layout & Escala de Fonte (Persistido no navegador)
    theme: localStorage.getItem('bastion_theme') || 'light', // 'light' | 'dark'
    layoutDensity: localStorage.getItem('bastion_density') || 'minimal', // 'minimal' | 'full'
    fontScale: localStorage.getItem('bastion_font_scale') || 'large', // 'normal' | 'large' | 'xlarge'
    localServerIp: '192.168.1.12',

    // Estado do Modal de Dossiê
    activeDossierMac: null,

    // Estado do Modal de Câmera CFTV HUD
    activeCamIp: null,
    activeCamMac: null,
    camStreamTimer: null,
    camClockTimer: null,
    camFilterMode: null,

    init() {
      this.applyThemeAndLayout();
      this.radar = new CyberRadar('radarCanvas');
      this.bindEvents();
      this.fetchInitialData();
      this.startPolling();

      window.addEventListener('languageChanged', () => {
        this.renderOverviewTable();
        this.renderInventoryTable();
        this.applyThemeAndLayout();
        if (window.I18N) {
          this.showToast(window.I18N.t('toast_lang_changed'), 'info');
        }
      });
    },

    applyThemeAndLayout() {
      document.body.classList.toggle('theme-light', this.theme === 'light');
      document.body.classList.toggle('layout-minimal', this.layoutDensity === 'minimal');

      const btnQuick = document.getElementById('btnQuickThemeToggle');
      if (btnQuick) {
        const isEn = window.I18N && window.I18N.getLang() === 'en';
        btnQuick.innerHTML = this.theme === 'light' 
          ? (isEn ? '🌙 Dark Mode' : '🌙 Modo Escuro') 
          : (isEn ? '☀️ Light Mode' : '☀️ Modo Claro');
      }

      const cardLight = document.getElementById('cardThemeLight');
      const cardDark = document.getElementById('cardThemeDark');
      if (cardLight && cardDark) {
        cardLight.classList.toggle('selected', this.theme === 'light');
        cardDark.classList.toggle('selected', this.theme === 'dark');
      }

      const cardMin = document.getElementById('cardLayoutMinimal');
      const cardFull = document.getElementById('cardLayoutFull');
      if (cardMin && cardFull) {
        cardMin.classList.toggle('selected', this.layoutDensity === 'minimal');
        cardFull.classList.toggle('selected', this.layoutDensity === 'full');
      }
    },

    setTheme(mode) {
      this.theme = mode === 'light' ? 'light' : 'dark';
      localStorage.setItem('bastion_theme', this.theme);
      this.applyThemeAndLayout();
      this.showToast(
        this.theme === 'light'
          ? '☀️ Visual Claro & Minimalista ativado!'
          : '🌙 Visual Cyber Dark ativado!',
        'info'
      );
    },

    setLayoutDensity(density) {
      this.layoutDensity = density === 'minimal' ? 'minimal' : 'full';
      localStorage.setItem('bastion_density', this.layoutDensity);
      this.applyThemeAndLayout();
      this.renderOverviewTable();
      this.renderInventoryTable();
      this.showToast(
        this.layoutDensity === 'minimal'
          ? '✨ Modo Minimalista (Fácil Leitura) aplicado!'
          : '🔧 Modo Técnico Completo aplicado!',
        'info'
      );
    },

    openSettingsModal() {
      this.applyThemeAndLayout();
      const modal = document.getElementById('settingsModal');
      if (modal) modal.style.display = 'flex';
    },

    closeSettingsModal() {
      const modal = document.getElementById('settingsModal');
      if (modal) modal.style.display = 'none';
    },

    bindEvents() {
      // ─── Navegação de Abas ─────────────────────────────────────────────────
      document.querySelectorAll('.tab-btn').forEach((btn) => {
        btn.addEventListener('click', () => {
          const tabName = btn.dataset.tab;
          document.querySelectorAll('.tab-btn').forEach((b) => b.classList.remove('active'));
          document.querySelectorAll('.tab-panel').forEach((p) => p.classList.remove('active'));

          btn.classList.add('active');
          const panel = document.getElementById(`panel-${tabName}`);
          if (panel) panel.classList.add('active');

          if (tabName === 'defense') this.loadDefensePanel();
          if (tabName === 'audit') this.loadAuditTrail();
          if (tabName === 'logs') this.loadLogs();
        });
      });

      // ─── Botão de Varredura Rápida (Rush Scan) ─────────────────────────────
      const btnScan = document.getElementById('btnTriggerScan');
      if (btnScan) {
        btnScan.addEventListener('click', async () => {
          btnScan.disabled = true;
          btnScan.innerHTML = '⚡ VARRENDO REDE...';
          this.showToast('Varredura ativa de radar iniciada...', 'info');

          try {
            await API.triggerScan();
            setTimeout(async () => {
              await this.fetchDevices();
              btnScan.disabled = false;
              btnScan.innerHTML = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg> ⚡ Buscar Dispositivos';
              this.showToast('Varredura concluída! Lista atualizada.', 'success');
            }, 3500);
          } catch (err) {
            btnScan.disabled = false;
            btnScan.innerHTML = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg> ⚡ Buscar Dispositivos';
            this.showToast(`Erro na varredura: ${err.message}`, 'error');
          }
        });
      }

      // ─── Botão de Reclassificação Inteligente L0-L11 ───────────────────────
      const btnReclassify = document.getElementById('btnReclassifyAll');
      if (btnReclassify) {
        btnReclassify.addEventListener('click', async () => {
          btnReclassify.disabled = true;
          btnReclassify.textContent = '🧠 CLASSIFICANDO...';
          try {
            const res = await API.reclassifyDevices();
            this.showToast(res.message, 'success');
            await this.fetchDevices();
          } catch (err) {
            this.showToast(`Erro ao reclassificar: ${err.message}`, 'error');
          } finally {
            btnReclassify.disabled = false;
            btnReclassify.textContent = '🧠 RECLASSIFICAR ATIVOS';
          }
        });
      }

      // ─── Botão de Travar Gateway ARP ───────────────────────────────────────
      const btnLock = document.getElementById('btnLockGateway');
      if (btnLock) {
        btnLock.addEventListener('click', () => this.lockGateway());
      }

      // ─── Botão de Bloqueio Manual no Firewall ──────────────────────────────
      const btnBlock = document.getElementById('btnExecuteBlock');
      if (btnBlock) {
        btnBlock.addEventListener('click', () => this.executeManualBlock());
      }

      // ─── Botão de Configuração do Honeyport ────────────────────────────────
      const btnHoneyport = document.getElementById('btnSaveHoneyport');
      if (btnHoneyport) {
        btnHoneyport.addEventListener('click', () => this.saveHoneyportConfig());
      }

      // ─── Botão de Verificação de Auditoria SHA-256 ─────────────────────────
      const btnVerify = document.getElementById('btnVerifyAudit');
      if (btnVerify) {
        btnVerify.addEventListener('click', async () => {
          btnVerify.disabled = true;
          this.showToast('Verificando integridade matemática dos hashes SHA-256...', 'info');
          try {
            const res = await API.verifyAudit();
            const banner = document.getElementById('auditIntegrityBanner');
            if (banner) {
              banner.style.display = 'flex';
              if (res.is_valid) {
                banner.className = 'integrity-banner';
                banner.innerHTML = `
                  <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#00ff88" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                  <div>
                    <strong>TRILHA DE AUDITORIA 100% ÍNTEGRA</strong>
                    <div style="font-size:0.8rem; color:var(--text-secondary);">${res.verified_entries_count} eventos validados criptograficamente. Nenhuma fraude detectada.</div>
                  </div>
                `;
                this.showToast('Auditoria verificada com 100% de integridade!', 'success');
              } else {
                banner.className = 'integrity-banner invalid';
                banner.innerHTML = `
                  <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#ff3b30" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
                  <div>
                    <strong>VIOLAÇÃO CRÍTICA DE INTEGRIDADE</strong>
                    <div style="font-size:0.8rem; color:var(--crimson-alert);">${res.error_message}</div>
                  </div>
                `;
                this.showToast('ALERTA: Adulteração detectada nos logs!', 'error');
              }
            }
          } catch (err) {
            this.showToast(`Erro na verificação: ${err.message}`, 'error');
          } finally {
            btnVerify.disabled = false;
          }
        });
      }

      // ─── Botão de Expurgo de Legados ───────────────────────────────────────
      const btnPurge = document.getElementById('btnPurgeLegacy');
      if (btnPurge) {
        btnPurge.addEventListener('click', () => this.purgeLegacy());
      }

      // ─── Botões de Logs (Atualizar e Limpar) ───────────────────────────────
      const btnRefreshLogs = document.getElementById('btnRefreshLogs');
      if (btnRefreshLogs) {
        btnRefreshLogs.addEventListener('click', () => this.loadLogs());
      }
      const btnClearLogs = document.getElementById('btnClearLogs');
      if (btnClearLogs) {
        btnClearLogs.addEventListener('click', async () => {
          try {
            await API.clearLogs();
            this.showToast('Logs de telemetria limpos com sucesso!', 'success');
            await this.loadLogs();
          } catch (err) {
            this.showToast(`Erro ao limpar logs: ${err.message}`, 'error');
          }
        });
      }

      // ─── Busca e Filtros de Status ─────────────────────────────────────────
      const searchInput = document.getElementById('deviceSearchInput');
      if (searchInput) {
        searchInput.addEventListener('input', (e) => {
          this.searchQuery = e.target.value.toLowerCase().trim();
          this.renderInventoryTable();
        });
      }

      document.querySelectorAll('#panel-devices .filter-chip[data-filter]').forEach((chip) => {
        chip.addEventListener('click', () => {
          document.querySelectorAll('#panel-devices .filter-chip[data-filter]').forEach((c) => c.classList.remove('active'));
          chip.classList.add('active');
          this.currentFilter = chip.dataset.filter;
          this.renderInventoryTable();
        });
      });

      // ─── Alternância Visão Agrupada vs Lista ───────────────────────────────
      const btnGrouped = document.getElementById('btnViewGrouped');
      const btnFlat = document.getElementById('btnViewFlat');
      if (btnGrouped && btnFlat) {
        btnGrouped.addEventListener('click', () => {
          this.viewMode = 'grouped';
          btnGrouped.classList.add('active');
          btnFlat.classList.remove('active');
          this.renderInventoryTable();
        });
        btnFlat.addEventListener('click', () => {
          this.viewMode = 'flat';
          btnFlat.classList.add('active');
          btnGrouped.classList.remove('active');
          this.renderInventoryTable();
        });
      }

      // ─── Eventos do Modal de Dossiê ────────────────────────────────────────
      const btnSaveMeta = document.getElementById('btnSaveDossierMeta');
      if (btnSaveMeta) {
        btnSaveMeta.addEventListener('click', () => this.saveDossierMeta());
      }
      const btnDeepScan = document.getElementById('btnDossierDeepScan');
      if (btnDeepScan) {
        btnDeepScan.addEventListener('click', () => this.executeDossierDeepScan());
      }
      const btnDossierHandshake = document.getElementById('btnDossierHandshake');
      if (btnDossierHandshake) {
        btnDossierHandshake.addEventListener('click', () => {
          const dev = this.devices.find((d) => d.mac === this.activeDossierMac);
          if (dev) {
            this.sendDeviceHandshake(dev.mac, dev.ip || '', btnDossierHandshake);
          }
        });
      }
      const btnDossierWoL = document.getElementById('btnDossierWoL');
      if (btnDossierWoL) {
        btnDossierWoL.addEventListener('click', () => {
          if (this.activeDossierMac) this.triggerWakeOnLan(this.activeDossierMac);
        });
      }
      const btnDossierBlock = document.getElementById('btnDossierBlock');
      if (btnDossierBlock) {
        btnDossierBlock.addEventListener('click', () => {
          const dev = this.devices.find((d) => d.mac === this.activeDossierMac);
          if (dev) {
            this.closeDossierModal();
            this.blockDeviceFromRow(dev.ip || '', dev.mac);
          }
        });
      }

      // ─── Eventos do Modal de Câmera CFTV HUD ───────────────────────────────
      const btnCamProbe = document.getElementById('btnCamProbe');
      if (btnCamProbe) {
        btnCamProbe.addEventListener('click', () => this.probeAndRenderCamera());
      }
      const btnCamNoPass = document.getElementById('btnCamNoPass');
      if (btnCamNoPass) {
        btnCamNoPass.addEventListener('click', () => {
          const passEl = document.getElementById('camInputPass');
          if (passEl) passEl.value = '';
          this.showToast('Sondando acesso sem senha nas portas abertas...', 'info');
          this.probeAndRenderCamera(true);
        });
      }
      const btnCamConnect = document.getElementById('btnCamConnect');
      if (btnCamConnect) {
        btnCamConnect.addEventListener('click', () => this.connectCameraStream());
      }

      // ─── Eventos de Tema, Layout & UAC Firewall ──────────────
      const btnQuickTheme = document.getElementById('btnQuickThemeToggle');
      if (btnQuickTheme) {
        btnQuickTheme.addEventListener('click', () => {
          this.setTheme(this.theme === 'light' ? 'dark' : 'light');
        });
      }
      const btnOpenSettings = document.getElementById('btnOpenSettings');
      if (btnOpenSettings) {
        btnOpenSettings.addEventListener('click', () => this.openSettingsModal());
      }
      const btnElevateUac = document.getElementById('btnElevateUac');
      if (btnElevateUac) {
        btnElevateUac.addEventListener('click', async () => {
          try {
            const res = await API.elevateFirewallUac();
            this.showToast(res.message, 'success');
            setTimeout(() => this.loadDefensePanel(), 1500);
          } catch (err) {
            this.showToast(err.message, 'error');
          }
        });
      }
    },

    async fetchInitialData() {
      await this.fetchDevices();
      await this.fetchStatus();
    },

    startPolling() {
      this.pollInterval = setInterval(async () => {
        await this.fetchDevices();
        await this.fetchStatus();
      }, 6000);
    },

    formatLocalDateTime(isoStr, timeOnly = false) {
      if (!isoStr) return '—';
      try {
        const d = new Date(isoStr);
        if (isNaN(d.getTime())) {
          return isoStr.replace('T', ' ');
        }
        if (timeOnly) {
          return d.toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
        }
        return d.toLocaleString('pt-BR', {
          day: '2-digit',
          month: '2-digit',
          year: 'numeric',
          hour: '2-digit',
          minute: '2-digit',
          second: '2-digit',
        });
      } catch (e) {
        return isoStr.replace('T', ' ');
      }
    },

    isLegacyDevice(dev) {
      const ip = dev.ip || '';
      const meta = dev.metadata || {};
      const devType = meta.device_type || '';
      const mac = (dev.mac || '').toLowerCase();

      const isProtocol =
        [
          'Endereço Multicast (não é dispositivo)',
          'Endereço Broadcast',
          'Protocolo de Rede (STP/VRRP/HSRP)',
        ].includes(devType) ||
        mac.startsWith('01:00:5e') ||
        mac.startsWith('33:33') ||
        mac === 'ff:ff:ff:ff:ff:ff';

      const isNoIp = !ip || ip === '0.0.0.0' || ip === 'IP Indisponível';
      return isProtocol || isNoIp;
    },

    // ─── CLASSIFICAÇÃO DE CATEGORIAS INTELIGENTES ────────────────────────────
    getDeviceCategory(dev) {
      const meta = dev.metadata || {};
      const dt = (meta.device_type || '').toLowerCase();
      const vendor = (dev.vendor || '').toLowerCase();
      const ports = meta.open_ports || [];
      const ip = dev.ip || '';

      // 1. Smart TV / Google Cast / Consoles (Prioridade antes de portas genéricas 9000/8443)
      if (
        dt.includes('tv') ||
        dt.includes('mídia') ||
        dt.includes('console') ||
        dt.includes('videogame') ||
        vendor.includes('tcl') ||
        vendor.includes('playstation') ||
        vendor.includes('google cast') ||
        ports.some((p) => Number(p) === 8008)
      ) {
        return 'iot';
      }

      // 2. Câmeras & CFTV
      if (
        dt.includes('câmera') ||
        dt.includes('camera') ||
        dt.includes('cftv') ||
        dt.includes('nvr') ||
        dt.includes('dvr') ||
        vendor.includes('hikvision') ||
        vendor.includes('dahua') ||
        vendor.includes('intelbras') ||
        vendor.includes('cftv') ||
        ports.some((p) => [554, 8554, 34567, 37777].includes(Number(p)))
      ) {
        return 'cameras';
      }

      // 3. Roteadores & Infraestrutura de Rede
      if (
        dt.includes('router') ||
        dt.includes('gateway') ||
        dt.includes('switch') ||
        dt.includes('access point') ||
        dt.includes('sonda') ||
        ip.endsWith('.1') ||
        ip.endsWith('.254')
      ) {
        return 'network';
      }

      // 4. Celulares & Dispositivos Móveis
      if (
        dt.includes('android') ||
        dt.includes('iphone') ||
        dt.includes('ipad') ||
        dt.includes('smartphone') ||
        (meta.is_mac_randomized && (!dt || dt.includes('desconhecido')))
      ) {
        return 'mobile';
      }

      // 5. Computadores, VMs & Servidores
      if (
        dt.includes('windows') ||
        dt.includes('linux') ||
        dt.includes('mac') ||
        dt.includes('virtual') ||
        dt.includes('container')
      ) {
        return 'computers';
      }

      // 6. Impressoras, VoIP & Outros IoT
      if (
        dt.includes('impressora') ||
        dt.includes('voip') ||
        dt.includes('iot')
      ) {
        return 'iot';
      }

      return 'unclassified';
    },

    isCameraCandidate(dev) {
      return this.getDeviceCategory(dev) === 'cameras' || Boolean(dev.metadata && dev.metadata.is_camera_capable);
    },

    getDeviceIcon(deviceType, dev = null) {
      const deviceIcons = {
        'Router/Gateway':                       '🌐',
        'Switch Gerenciável':                   '🔀',
        'Access Point (Wi-Fi)':                 '📡',
        'Computador Windows':                    '🖥️',
        'Servidor Linux':                        '🖧',
        'Mac / MacBook':                        '🍎',
        'iPhone / iPad':                        '📱',
        'Smartphone/Tablet Android':             '📱',
        'Câmera IP / CFTV':                    '📷',
        'NVR / DVR':                            '📹',
        'Impressora de Rede':                    '🖨️',
        'Telefone VoIP':                        '☎️',
        'Smart TV / Mídia':                      '📺',
        'Console de Videogame':                  '🎮',
        'Dispositivo IoT':                       '💡',
        'Máquina Virtual / Container':           '🐳',
        'Sonda de Rede / SNMP':                '🔍',
        'Endereço Multicast (não é dispositivo)':'〽️',
        'Endereço Broadcast':                   '📢',
        'Protocolo de Rede (STP/VRRP/HSRP)':   '🔗',
        'Dispositivo Desconhecido':              '❓',
      };
      if (deviceIcons[deviceType] && deviceType !== 'Dispositivo Desconhecido') {
        return deviceIcons[deviceType];
      }
      if (dev) {
        const cat = this.getDeviceCategory(dev);
        const fallbackIcons = {
          cameras: '📹',
          mobile: '📱',
          network: '🛜',
          computers: '💻',
          iot: '📺',
        };
        if (fallbackIcons[cat]) return fallbackIcons[cat];
      }
      return '❓';
    },

    async fetchStatus() {
      try {
        const data = await API.getStatus();
        if (data.local_ip && data.local_ip !== '127.0.0.1') {
          this.localServerIp = data.local_ip;
        }
        const onlineCount = this.devices.filter((d) => !this.isLegacyDevice(d)).length;
        const legacyCount = this.devices.filter((d) => this.isLegacyDevice(d)).length;
        const authorizedCount = this.devices.filter(
          (d) => !this.isLegacyDevice(d) && d.status.toLowerCase() === 'authorized'
        ).length;
        const unknownCount = this.devices.filter(
          (d) => !this.isLegacyDevice(d) && d.status.toLowerCase() === 'unknown'
        ).length;

        const statOnline = document.getElementById('statOnlineDevices');
        if (statOnline) statOnline.textContent = onlineCount;

        const statAuth = document.getElementById('statAuthorized');
        if (statAuth) statAuth.textContent = authorizedCount;

        const statUnk = document.getElementById('statUnknown');
        if (statUnk) statUnk.textContent = unknownCount;

        const statLeg = document.getElementById('statLegacyDevices');
        if (statLeg) statLeg.textContent = legacyCount;

        const dot = document.getElementById('statusDot');
        const text = document.getElementById('statusText');
        if (dot && text) {
          if (data.wan_online) {
            dot.className = 'status-dot';
            text.textContent = `ONLINE (${data.wan_latency_ms > 0 ? data.wan_latency_ms + 'ms' : 'WAN OK'})`;
          } else {
            dot.className = 'status-dot offline';
            text.textContent = 'FALHA DE LINK';
          }
        }
      } catch (err) {
        console.error('Falha ao obter status:', err);
      }
    },

    async fetchDevices() {
      try {
        const res = await API.getDevices();
        this.devices = res.devices || [];

        const activeForRadar = this.devices.filter((d) => !this.isLegacyDevice(d));
        if (this.radar) {
          this.radar.setDevices(activeForRadar);
        }

        this.renderCategoryBars();
        this.renderOverviewTable();
        this.renderInventoryTable();
        this.renderLegacyTable();
      } catch (err) {
        console.error('Falha ao obter dispositivos:', err);
      }
    },

    // ─── RENDERIZA BARRAS DE FILTRO POR CATEGORIA COM CONTADORES ─────────────
    renderCategoryBars() {
      const operational = this.devices.filter((d) => !this.isLegacyDevice(d));
      const counts = { all: operational.length };
      CATEGORY_DEFINITIONS.forEach((c) => {
        if (c.id !== 'all') counts[c.id] = 0;
      });
      operational.forEach((d) => {
        const cat = this.getDeviceCategory(d);
        counts[cat] = (counts[cat] || 0) + 1;
      });

      // 1. Barra do Overview (Tab 1)
      const ovBar = document.getElementById('overviewCategoryBar');
      if (ovBar) {
        ovBar.innerHTML = CATEGORY_DEFINITIONS.map(
          (cat) => `
          <button class="cat-pill-btn ${this.overviewCategory === cat.id ? 'active' : ''}"
                  onclick="App.setOverviewCategory('${cat.id}')">
            <span>${cat.icon}</span>
            <span>${cat.label}</span>
            <span class="cat-pill-count">${counts[cat.id] || 0}</span>
          </button>
        `
        ).join('');
      }

      // 2. Barra do Inventário (Tab 2)
      const invBar = document.getElementById('inventoryCategoryBar');
      if (invBar) {
        invBar.innerHTML = CATEGORY_DEFINITIONS.map(
          (cat) => `
          <button class="cat-pill-btn ${this.currentCategory === cat.id ? 'active' : ''}"
                  onclick="App.setInventoryCategory('${cat.id}')">
            <span>${cat.icon}</span>
            <span>${cat.label}</span>
            <span class="cat-pill-count">${counts[cat.id] || 0}</span>
          </button>
        `
        ).join('');
      }
    },

    setOverviewCategory(catId) {
      this.overviewCategory = catId;
      this.renderCategoryBars();
      this.renderOverviewTable();
    },

    setInventoryCategory(catId) {
      this.currentCategory = catId;
      this.renderCategoryBars();
      this.renderInventoryTable();
    },

    // ─── GERA HTML DE UMA LINHA DE DISPOSITIVO (5 COLUNAS ESPAÇOSAS & AMIGÁVEIS) ──
    buildDeviceRowHtml(dev) {
      const meta = dev.metadata || {};
      let deviceType = meta.device_type || 'Dispositivo Desconhecido';
      const cat = this.getDeviceCategory(dev);
      if (deviceType === 'Dispositivo Desconhecido' && cat === 'mobile') {
        deviceType = 'Celular / Tablet';
      } else if (deviceType === 'Dispositivo Desconhecido' && cat === 'network') {
        deviceType = 'Roteador / Rede';
      }

      const osHint = meta.os_hint && meta.os_hint !== 'Indefinido' ? meta.os_hint : '';
      let hardwareModel = meta.hardware_model || '';
      if (hardwareModel.includes('MAC Privado — use /id')) {
        hardwareModel = 'Celular Android';
      }
      const confidence = meta.confidence_score || 0;
      const isMacRand = meta.is_mac_randomized;
      const customName = meta.custom_name || '';
      const hostname = dev.hostname || '';
      const openPorts = meta.open_ports || [];
      const latencyMs = meta.latency_ms;
      const icon = this.getDeviceIcon(deviceType, dev);

      // Determina nome principal priorizando: Apelido -> ID Único de Rede (Hostname) ou Modelo Exato -> IP
      const isGenericModel =
        !hardwareModel ||
        hardwareModel === 'Smartphone Android' ||
        hardwareModel === 'Celular Android' ||
        hardwareModel.startsWith('Celular / Aparelho Wi-Fi');

      let primaryName = customName;
      if (!primaryName) {
        if (hostname && isGenericModel) {
          primaryName = hostname.startsWith('Android_') ? `Celular (${hostname})` : hostname;
        } else if (hardwareModel && !isGenericModel) {
          primaryName = hardwareModel;
        } else if (hostname) {
          primaryName = hostname;
        } else if (hardwareModel) {
          primaryName = hardwareModel;
        } else {
          primaryName = dev.ip || 'Dispositivo';
        }
      }

      let subDetails = [];
      if (hostname && !primaryName.toLowerCase().includes(hostname.toLowerCase())) {
        subDetails.push(`ID: ${hostname}`);
      }
      if (hardwareModel && !primaryName.toLowerCase().includes(hardwareModel.toLowerCase())) {
        subDetails.push(hardwareModel);
      }
      if (deviceType && !subDetails.some(s => s.toLowerCase().includes(deviceType.toLowerCase())) && !primaryName.toLowerCase().includes(deviceType.toLowerCase())) {
        subDetails.push(deviceType);
      }
      if (latencyMs !== undefined && latencyMs !== null) {
        subDetails.push(`⚡ ${latencyMs}ms`);
      }

      // Selos e status amigáveis
      const statusMap = {
        'authorized': { label: 'Confiável', class: 'authorized' },
        'unknown':    { label: 'Novo / Pendente', class: 'unknown' },
        'quarantined':{ label: 'Bloqueado', class: 'quarantined' },
      };
      const statusInfo = statusMap[dev.status.toLowerCase()] || { label: dev.status, class: dev.status.toLowerCase() };

      // Informações técnicas detalhadas (exibidas no modo técnico)
      const portsHtml = openPorts.length > 0
        ? `<div style="margin-top:4px; display:flex; gap:3px; flex-wrap:wrap;">${openPorts.slice(0, 6).map(p => `<span class="port-tag">:${p}</span>`).join('')}</div>`
        : '';

      const techInfoHtml = `
        <div class="col-tech-detail" style="font-size:0.75rem; color:var(--text-muted); margin-top:4px; line-height:1.4;">
          ${osHint ? `<div>Sistema: <strong style="color:var(--text-secondary);">${escapeHtml(osHint)}</strong></div>` : ''}
          ${confidence > 0 ? `<div>Confiança: <strong style="color:var(--neon-emerald);">${confidence}%</strong></div>` : ''}
          ${portsHtml}
        </div>
      `;

      const handshakeButton = `
        <button class="btn-action-icon" title="Enviar Handshake de Rede para Identificar Modelo / ID e Testar Resposta (${dev.ip || dev.mac})" onclick="App.sendDeviceHandshake('${dev.mac}', '${dev.ip || ''}', this)" style="border-color:var(--neon-cyan); color:var(--neon-cyan); width:auto; padding:0 8px; font-weight:700;">
          📡 Identificar
        </button>`;

      return `
      <tr>
        <!-- 1. DISPOSITIVO & MODELO -->
        <td>
          <div style="display:flex; align-items:flex-start; gap:0.5rem;">
            <span style="font-size:1.35rem; line-height:1;">${icon}</span>
            <div>
              <div style="font-weight:700; font-size:1.02rem; color:var(--text-primary); line-height:1.25;">
                ${escapeHtml(primaryName)}
              </div>
              <div style="font-size:0.82rem; color:var(--text-secondary); margin-top:2px;">
                ${subDetails.map(s => escapeHtml(s)).join(' · ')}
              </div>
              ${techInfoHtml}
            </div>
          </div>
        </td>

        <!-- 2. ENDEREÇO DE REDE (IP + MAC) -->
        <td>
          <div class="ip-pill" style="font-size:1.05rem; font-weight:700;">${dev.ip || '—'}</div>
          <div style="font-size:0.8rem; font-family:var(--font-mono); color:var(--text-muted); margin-top:3px; display:flex; align-items:center; gap:5px;">
            <span>${dev.mac}</span>
            ${isMacRand ? `<span title="MAC Aleatório / Privado (recurso de privacidade do celular)" style="color:var(--cyber-amber); font-size:0.75rem;">🔀 Privado</span>` : ''}
          </div>
        </td>

        <!-- 3. FABRICANTE -->
        <td>
          <span class="vendor-chip" style="font-size:0.88rem; max-width:210px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;" title="${escapeHtml(dev.vendor)}">
            ${dev.vendor !== 'Fabricante desconhecido' ? escapeHtml(dev.vendor) : '—'}
          </span>
        </td>

        <!-- 4. STATUS -->
        <td>
          <span class="status-badge ${statusInfo.class}">${statusInfo.label}</span>
          <div class="col-tech-detail" style="font-size:0.75rem; color:var(--text-muted); margin-top:4px; font-family:var(--font-mono);" title="${this.formatLocalDateTime(dev.last_seen)}">
            ⏱️ ${this.formatLocalDateTime(dev.last_seen, true)}
          </div>
        </td>

        <!-- 5. AÇÕES -->
        <td>
          <div class="action-btns">
            ${handshakeButton}
            <button class="btn-action-icon" title="Ver Detalhes do Dispositivo" onclick="App.openDossierModal('${dev.mac}')" style="border-color:var(--border-glow); color:var(--neon-cyan); width:auto; padding:0 8px; font-weight:600;">
              🔍 Detalhes
            </button>
            <button class="btn-action-icon" title="Marcar como Confiável" onclick="App.changeStatus('${dev.mac}', 'authorized')" style="color:var(--neon-emerald); font-weight:700;">
              ✓
            </button>
            <button class="btn-action-icon" title="Bloquear Acesso à Rede" onclick="App.blockDeviceFromRow('${dev.ip || ''}', '${dev.mac}')" style="border-color:rgba(220,38,38,0.45); color:var(--crimson-alert); width:auto; padding:0 8px; font-weight:700;">
              ⛔ Bloquear
            </button>
          </div>
        </td>
      </tr>
      `;
    },

    // ─── TAB 1: Renderiza Ativos Online no Radar ─────────────────────────────
    renderOverviewTable() {
      const tbody = document.getElementById('devicesTableBody');
      if (!tbody) return;

      let onlineDevices = this.devices.filter((d) => !this.isLegacyDevice(d));
      if (this.overviewCategory !== 'all') {
        onlineDevices = onlineDevices.filter((d) => this.getDeviceCategory(d) === this.overviewCategory);
      }

      if (onlineDevices.length === 0) {
        tbody.innerHTML = `
          <tr>
            <td colspan="7" style="text-align:center; padding: 2rem; color: var(--text-muted);">
              Nenhum ativo encontrado nesta categoria.
            </td>
          </tr>
        `;
        return;
      }

      tbody.innerHTML = onlineDevices.map((dev) => this.buildDeviceRowHtml(dev)).join('');
    },

    // ─── TAB 2: Renderiza Inventário Operacional (Agrupado ou Lista) ─────────
    renderInventoryTable() {
      const groupedContainer = document.getElementById('groupedInventoryContainer');
      const flatContainer = document.getElementById('flatInventoryContainer');
      const tbody = document.getElementById('devicesTableBodyFull');
      if (!tbody || !groupedContainer || !flatContainer) return;

      const operational = this.devices.filter((d) => !this.isLegacyDevice(d));

      const filtered = operational.filter((dev) => {
        const matchesStatus =
          this.currentFilter === 'all' ||
          dev.status.toLowerCase() === this.currentFilter.toLowerCase();

        const cat = this.getDeviceCategory(dev);
        const matchesCategory = this.currentCategory === 'all' || cat === this.currentCategory;

        const meta = dev.metadata || {};
        const devType = meta.device_type || '';
        const customName = meta.custom_name || '';
        const hwModel = meta.hardware_model || '';
        const matchesSearch =
          !this.searchQuery ||
          dev.mac.toLowerCase().includes(this.searchQuery) ||
          (dev.ip || '').toLowerCase().includes(this.searchQuery) ||
          (dev.vendor || '').toLowerCase().includes(this.searchQuery) ||
          devType.toLowerCase().includes(this.searchQuery) ||
          customName.toLowerCase().includes(this.searchQuery) ||
          hwModel.toLowerCase().includes(this.searchQuery) ||
          (dev.hostname || '').toLowerCase().includes(this.searchQuery);

        return matchesStatus && matchesCategory && matchesSearch;
      });

      if (this.viewMode === 'grouped') {
        groupedContainer.style.display = 'flex';
        flatContainer.style.display = 'none';

        if (filtered.length === 0) {
          groupedContainer.innerHTML = `
            <div style="text-align:center; padding: 2.5rem; color: var(--text-muted);">
              Nenhum dispositivo corresponde aos filtros selecionados.
            </div>
          `;
          return;
        }

        const groupsToRender = CATEGORY_DEFINITIONS.filter((c) => c.id !== 'all');
        const htmlGroups = groupsToRender
          .map((catDef) => {
            const items = filtered.filter((d) => this.getDeviceCategory(d) === catDef.id);
            if (items.length === 0) return '';

            return `
              <div class="category-group-card">
                <div class="category-group-header">
                  <div class="category-group-title">
                    <span style="font-size:1.25rem;">${catDef.icon}</span>
                    <span>${catDef.label}</span>
                    <span class="cat-pill-count" style="background:rgba(0,210,255,0.2); color:var(--neon-cyan);">${items.length} aparelho(s)</span>
                  </div>
                  <span style="font-size:0.8rem; color:var(--text-muted);">Rede Local</span>
                </div>
                <div class="data-table-container">
                  <table class="cyber-table">
                    <thead>
                      <tr>
                        <th>Dispositivo & Modelo</th>
                        <th>Endereço de Rede</th>
                        <th>Fabricante</th>
                        <th>Status</th>
                        <th>Ações</th>
                      </tr>
                    </thead>
                    <tbody>
                      ${items.map((dev) => this.buildDeviceRowHtml(dev)).join('')}
                    </tbody>
                  </table>
                </div>
              </div>
            `;
          })
          .filter(Boolean)
          .join('');

        groupedContainer.innerHTML = htmlGroups;
      } else {
        groupedContainer.style.display = 'none';
        flatContainer.style.display = 'block';

        if (filtered.length === 0) {
          tbody.innerHTML = `
            <tr>
              <td colspan="7" style="text-align:center; padding: 2rem; color: var(--text-muted);">
                Nenhum ativo operacional encontrado para os filtros atuais.
              </td>
            </tr>
          `;
          return;
        }

        tbody.innerHTML = filtered.map((dev) => this.buildDeviceRowHtml(dev)).join('');
      }
    },

    // ─── MODAL 1: DETALHES DO DISPOSITIVO ─────────────────────────────
    openDossierModal(mac) {
      const dev = this.devices.find((d) => d.mac === mac);
      if (!dev) return;

      this.activeDossierMac = mac;
      const meta = dev.metadata || {};

      document.getElementById('dossierTitle').textContent = `🔍 Detalhes: ${meta.custom_name || meta.hardware_model || dev.ip || dev.mac}`;
      document.getElementById('dossierSubtitle').textContent = `MAC: ${dev.mac} | IP: ${dev.ip || 'N/A'} | Fabricante: ${dev.vendor}`;
      document.getElementById('dossierCustomName').value = meta.custom_name || '';
      const hwInput = document.getElementById('dossierHardwareModel');
      if (hwInput) {
        hwInput.value = meta.hardware_model || '';
      }
      const probeHint = document.getElementById('dossierProbeUrlHint');
      if (probeHint) {
        probeHint.textContent = `http://${this.localServerIp || '192.168.1.12'}:5055/id`;
      }

      const typeSelect = document.getElementById('dossierDeviceType');
      if (typeSelect) {
        typeSelect.value = meta.device_type || 'Dispositivo Desconhecido';
      }

      this.renderDossierScanDetails(dev);
      document.getElementById('assetDossierModal').style.display = 'flex';
    },

    closeDossierModal() {
      document.getElementById('assetDossierModal').style.display = 'none';
      this.activeDossierMac = null;
    },

    renderDossierScanDetails(dev) {
      const container = document.getElementById('dossierScanContent');
      if (!container) return;

      const meta = dev.metadata || {};
      const ports = meta.open_ports || [];
      const evidence = meta.evidence || [];
      const findings = meta.risk_findings || [];
      const riskLevel = meta.risk_level || 'LOW';
      const latencyMs = meta.latency_ms;

      const riskLabels = {
        LOW: 'Seguro / Normal',
        MEDIUM: 'Atenção Moderada',
        HIGH: 'Alerta de Porta Exposta',
        CRITICAL: 'Crítico',
      };
      const friendlyRisk = riskLabels[riskLevel] || riskLevel;

      const portsHtml =
        ports.length > 0
          ? ports.map((p) => `<span class="port-tag" style="font-size:0.8rem; padding:3px 9px;">Porta ${p}</span>`).join(' ')
          : '<span style="color:var(--text-muted); font-size:0.8rem;">Nenhuma porta aberta detectada na varredura rápida. Clique em "📡 Enviar Handshake" ou "🔬 Diagnóstico de Portas" acima.</span>';

      const findingsHtml =
        findings.length > 0
          ? findings
              .map(
                (f) => `
              <div style="display:flex; justify-content:space-between; align-items:center; padding:0.5rem 0.75rem; background:rgba(0,0,0,0.12); border-radius:6px; margin-top:0.4rem; border-left:3px solid ${
                f.severity === 'CRITICAL' || f.severity === 'HIGH' ? 'var(--crimson-alert)' : 'var(--neon-cyan)'
              };">
                <div>
                  <strong style="font-size:0.82rem; color:var(--text-primary);">${escapeHtml(f.title)}</strong>
                  <div style="font-size:0.74rem; color:var(--text-secondary);">${escapeHtml(f.description)}</div>
                </div>
                <span class="status-badge ${f.severity === 'CRITICAL' || f.severity === 'HIGH' ? 'quarantined' : 'authorized'}">${f.severity}</span>
              </div>
            `
              )
              .join('')
          : '';

      const cleanEvidence = (text) => String(text).replace(/^L\d+\s+(OUI\s+)?/i, '');
      const evHtml =
        evidence.length > 0
          ? evidence.map((e) => `<li style="font-size:0.82rem; color:var(--text-secondary); margin-bottom:4px;">${escapeHtml(cleanEvidence(e))}</li>`).join('')
          : '<li style="font-size:0.82rem; color:var(--text-muted);">Sem informações adicionais registradas.</li>';

      container.innerHTML = `
        <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:0.5rem; margin-bottom:0.75rem;">
          <h4>📡 Respostas do Handshake, Identidade & Portas Abertas</h4>
          <div style="display:flex; gap:0.5rem; align-items:center;">
            ${latencyMs !== undefined && latencyMs !== null ? `<span class="status-badge authorized">⚡ Resposta: ${latencyMs}ms</span>` : ''}
            <span class="status-badge ${riskLevel === 'CRITICAL' || riskLevel === 'HIGH' ? 'quarantined' : 'authorized'}">
              Segurança: ${friendlyRisk}
            </span>
          </div>
        </div>
        <div style="margin-bottom:0.85rem;">
          <div style="font-size:0.78rem; font-weight:600; color:var(--text-muted); margin-bottom:4px;">PORTAS E SERVIÇOS DE REDE ATIVOS:</div>
          ${portsHtml}
        </div>
        ${findingsHtml ? `<div style="margin-bottom:0.85rem;"><div style="font-size:0.78rem; font-weight:600; color:var(--text-muted); margin-bottom:4px;">DIAGNÓSTICO DE SERVIÇOS:</div>${findingsHtml}</div>` : ''}
        <div>
          <div style="font-size:0.78rem; font-weight:600; color:var(--text-muted); margin-bottom:4px;">DADOS COLETADOS PELO IDENTIFICADOR:</div>
          <ul style="padding-left:1.2rem;">${evHtml}</ul>
        </div>
      `;
    },

    async sendDeviceHandshake(mac, ip, btnEl = null) {
      if (!ip || ip === '0.0.0.0' || ip === 'IP Indisponível') {
        this.showToast('Este aparelho está desconectado (sem IP ativo no momento).', 'error');
        return;
      }

      const origHtml = btnEl ? btnEl.innerHTML : '';
      if (btnEl) {
        btnEl.disabled = true;
        btnEl.innerHTML = '⏳ Sondando...';
      }
      this.showToast(`Enviando handshake de identificação para ${ip}...`, 'info');

      try {
        const res = await API.handshakeDevice(mac, ip);
        await this.fetchDevices();

        if (this.activeDossierMac === mac) {
          const updated = this.devices.find((d) => d.mac === mac);
          if (updated) {
            const meta = updated.metadata || {};
            document.getElementById('dossierTitle').textContent = `🔍 Detalhes: ${meta.custom_name || meta.hardware_model || updated.hostname || updated.ip}`;
            const hwInput = document.getElementById('dossierHardwareModel');
            if (hwInput && meta.hardware_model) hwInput.value = meta.hardware_model;
            const typeSelect = document.getElementById('dossierDeviceType');
            if (typeSelect && meta.device_type) typeSelect.value = meta.device_type;
            this.renderDossierScanDetails(updated);
          }
        }

        const modelOrId = res.hostname || res.hardware_model || res.device_type || ip;
        const latMsg = res.latency_ms !== null && res.latency_ms !== undefined ? ` (${Math.round(res.latency_ms)}ms)` : '';
        if (res.reachable || res.alive) {
          this.showToast(res.message || `✅ Handshake concluído: ${modelOrId}${latMsg}`, 'success');
        } else {
          this.showToast(`⚠️ Aparelho em modo economia de bateria ou tela apagada (${modelOrId}).`, 'info');
        }
      } catch (err) {
        this.showToast(`Erro no handshake: ${err.message}`, 'error');
      } finally {
        if (btnEl) {
          btnEl.disabled = false;
          btnEl.innerHTML = origHtml;
        }
      }
    },

    async saveDossierMeta() {
      if (!this.activeDossierMac) return;
      const customName = document.getElementById('dossierCustomName').value;
      const hwModelEl = document.getElementById('dossierHardwareModel');
      const hardwareModel = hwModelEl ? hwModelEl.value : '';
      const deviceType = document.getElementById('dossierDeviceType').value;

      try {
        await API.updateDeviceMeta({
          mac: this.activeDossierMac,
          custom_name: customName,
          hardware_model: hardwareModel,
          device_type: deviceType,
        });
        this.showToast('Identificação, modelo exato e categoria salvos com sucesso!', 'success');
        await this.fetchDevices();
        const updated = this.devices.find((d) => d.mac === this.activeDossierMac);
        if (updated) this.renderDossierScanDetails(updated);
      } catch (err) {
        this.showToast(`Erro ao salvar: ${err.message}`, 'error');
      }
    },

    async executeDossierDeepScan() {
      if (!this.activeDossierMac) return;
      const dev = this.devices.find((d) => d.mac === this.activeDossierMac);
      if (!dev) return;

      const btn = document.getElementById('btnDossierDeepScan');
      if (btn) {
        btn.disabled = true;
        btn.textContent = '🔬 SONDANDO 29 PORTAS...';
      }
      this.showToast(`Executando auditoria profunda em ${dev.ip || dev.mac}...`, 'info');

      try {
        await API.deepScanDevice(dev.mac, dev.ip);
        await this.fetchDevices();
        const updated = this.devices.find((d) => d.mac === this.activeDossierMac);
        if (updated) {
          document.getElementById('dossierDeviceType').value =
            (updated.metadata && updated.metadata.device_type) || 'Dispositivo Desconhecido';
          const hwInput = document.getElementById('dossierHardwareModel');
          if (hwInput && updated.metadata && updated.metadata.hardware_model) {
            hwInput.value = updated.metadata.hardware_model;
          }
          this.renderDossierScanDetails(updated);
        }
        this.showToast('Sonda profunda concluída com sucesso!', 'success');
      } catch (err) {
        this.showToast(`Falha na sonda profunda: ${err.message}`, 'error');
      } finally {
        if (btn) {
          btn.disabled = false;
          btn.textContent = '🔬 Executar Sonda Profunda (29 Portas)';
        }
      }
    },

    async triggerWakeOnLan(mac) {
      try {
        const res = await API.sendWakeOnLan(mac);
        this.showToast(res.message, 'success');
      } catch (err) {
        this.showToast(`Erro no Wake-on-LAN: ${err.message}`, 'error');
      }
    },

    // ─── MODAL 2: CYBER CFTV HUD (VISUALIZADOR DE CÂMERA IP / NVR) ───────────
    async openCameraModal(ip, mac) {
      if (!ip || ip === '0.0.0.0') {
        this.showToast('Este dispositivo não possui um endereço IP ativo no momento.', 'error');
        return;
      }

      this.activeCamIp = ip;
      this.activeCamMac = mac;
      const dev = this.devices.find((d) => d.mac === mac) || {};
      const meta = dev.metadata || {};

      document.getElementById('camHudTitle').textContent = `📹 CFTV HUD — ${meta.custom_name || meta.device_type || 'Câmera / NVR'}`;
      document.getElementById('camHudSubtitle').textContent = `ALVO: ${ip} [${mac}] · ${dev.vendor || ''}`;
      document.getElementById('camOsdTarget').textContent = `CAM // ${ip}`;
      document.getElementById('camInputUser').value = meta.camera_user || 'admin';
      document.getElementById('camInputPass').value = meta.camera_pass || '';
      document.getElementById('camInputUrl').value = meta.camera_url || '';

      document.getElementById('camLiveImage').style.display = 'none';
      document.getElementById('camPlaceholderMsg').style.display = 'block';
      document.getElementById('cameraHudModal').style.display = 'flex';

      this.startCamClock();
      await this.probeAndRenderCamera();
    },

    closeCameraModal() {
      document.getElementById('cameraHudModal').style.display = 'none';
      this.stopCameraStream();
      if (this.camClockTimer) {
        clearInterval(this.camClockTimer);
        this.camClockTimer = null;
      }
      const iframe = document.getElementById('camWebIframe');
      if (iframe) iframe.src = 'about:blank';
    },

    startCamClock() {
      if (this.camClockTimer) clearInterval(this.camClockTimer);
      const updateClock = () => {
        const el = document.getElementById('camOsdClock');
        if (el) el.textContent = new Date().toLocaleTimeString('pt-BR');
      };
      updateClock();
      this.camClockTimer = setInterval(updateClock, 1000);
    },

    switchCameraTab(tabId) {
      document.querySelectorAll('[data-camtab]').forEach((b) => {
        b.classList.toggle('active', b.dataset.camtab === tabId);
      });
      document.getElementById('camPanelLive').style.display = tabId === 'live' ? 'block' : 'none';
      document.getElementById('camPanelWebui').style.display = tabId === 'webui' ? 'block' : 'none';
      document.getElementById('camPanelRtsp').style.display = tabId === 'rtsp' ? 'block' : 'none';
    },

    toggleCameraFilter(mode) {
      const vp = document.getElementById('camViewport');
      if (!vp) return;
      if (this.camFilterMode === mode) {
        this.camFilterMode = null;
        vp.classList.remove('filter-night', 'filter-thermal');
      } else {
        this.camFilterMode = mode;
        vp.classList.remove('filter-night', 'filter-thermal');
        vp.classList.add(mode === 'night' ? 'filter-night' : 'filter-thermal');
      }
    },

    async probeAndRenderCamera(autoConnectIfNoPass = false) {
      if (!this.activeCamIp) return;
      const user = document.getElementById('camInputUser').value.trim() || 'admin';
      const pass = document.getElementById('camInputPass').value;
      const osdStatus = document.getElementById('camOsdStatus');
      if (osdStatus) osdStatus.textContent = 'SONDANDO PORTAS ABERTAS E TESTANDO ACESSO SEM SENHA...';

      try {
        const res = await API.probeCamera(this.activeCamIp, user, pass);
        const cam = res.camera;

        // Renderiza o Diagnóstico de Acesso Sem Senha & Identidade do Hardware (#camAnonymousAuditBox)
        const anonBox = document.getElementById('camAnonymousAuditBox');
        if (anonBox) {
          anonBox.style.display = 'block';
          const hwAlert = cam.is_smart_tv_cast
            ? `<div style="padding:0.6rem 0.85rem; border-radius:8px; background:rgba(217,119,6,0.12); border:1px solid var(--cyber-amber); color:var(--text-primary); font-size:0.82rem; margin-bottom:0.65rem;">
                 📺 <strong>Descoberta Automática de Hardware:</strong> Este IP (<strong>${escapeHtml(cam.ip)}</strong>) respondeu nas portas abertas como <strong>${escapeHtml(cam.hardware_identity || 'Smart TV / Google Cast')}</strong>! As portas 8008/8443/9000 pertencem ao sistema Chromecast da TV, e não a uma câmera CFTV.
               </div>`
            : cam.hardware_identity
            ? `<div style="font-size:0.8rem; color:var(--neon-cyan); margin-bottom:0.5rem;">🔍 <strong>Assinatura do Equipamento:</strong> ${escapeHtml(cam.hardware_identity)}</div>`
            : '';

          const auditRows = (cam.anonymous_port_audit || [])
            .map(
              (a) => `
              <div style="display:flex; justify-content:space-between; align-items:center; padding:0.4rem 0.65rem; border-bottom:1px solid var(--border-subtle); font-size:0.78rem; gap:0.5rem;">
                <div>
                  <span class="port-tag">PORTA ${a.port}</span>
                  <strong style="margin-left:6px; color:var(--text-primary);">${escapeHtml(a.service)}</strong>
                </div>
                <div style="display:flex; align-items:center; gap:8px;">
                  <span style="color:var(--text-secondary);">${escapeHtml(a.status)}</span>
                  <span class="status-badge ${a.open_without_password ? 'authorized' : 'quarantined'}">
                    ${a.open_without_password ? '🔓 SEM SENHA' : '🔒 EXIGE SENHA'}
                  </span>
                </div>
              </div>
            `
            )
            .join('');

          anonBox.innerHTML = `
            <div style="font-size:0.8rem; font-weight:700; color:var(--text-primary); margin-bottom:0.45rem;">
              🔓 Diagnóstico de Conexão Sem Senha pelas Portas Abertas (${cam.open_camera_ports.length} porta(s) ativa(s)):
            </div>
            ${hwAlert}
            ${
              auditRows ||
              '<div style="font-size:0.78rem; color:var(--text-muted);">Nenhuma porta TCP de câmera/web aberta respondeu neste IP no momento.</div>'
            }
          `;
        }

        // Preenche automaticamente URL de snapshot se descobriu algum endpoint ativo
        const urlInput = document.getElementById('camInputUrl');
        const openSnapshot = (cam.working_snapshots || []).find((s) => s.content_type !== 'auth_required');
        if (urlInput && openSnapshot) {
          urlInput.value = openSnapshot.url;
          if (autoConnectIfNoPass) {
            this.showToast('Stream aberto sem senha encontrado! Conectando...', 'success');
            this.connectCameraStream();
          }
        } else if (urlInput && !urlInput.value && cam.working_snapshots && cam.working_snapshots.length > 0) {
          urlInput.value = cam.working_snapshots[0].url;
        } else if (urlInput && !urlInput.value && cam.web_interfaces && cam.web_interfaces.length > 0) {
          urlInput.value = `${cam.web_interfaces[0].url}/cgi-bin/snapshot.cgi`;
        }

        // Renderiza botões da aba Interface Web Nativa
        const linksBar = document.getElementById('camWebLinksBar');
        const iframe = document.getElementById('camWebIframe');
        if (linksBar) {
          if (cam.web_interfaces && cam.web_interfaces.length > 0) {
            linksBar.innerHTML = cam.web_interfaces
              .map(
                (w) => `
                <button class="btn-secondary" onclick="document.getElementById('camWebIframe').src='${w.url}'">
                  🖥️ Carregar no Visor (${w.protocol.toUpperCase()} :${w.port})
                </button>
                <a href="${w.url}" target="_blank" rel="noopener" class="btn-primary" style="text-decoration:none;">
                  ↗ Abrir Painel ${w.protocol.toUpperCase()} :${w.port} em Nova Guia
                </a>
              `
              )
              .join('');
            if (iframe && iframe.src === 'about:blank') {
              iframe.src = cam.web_interfaces[0].url;
            }
          } else {
            linksBar.innerHTML = `<span style="color:var(--cyber-amber); font-size:0.82rem;">Nenhuma porta HTTP/HTTPS padrão aberta. Este equipamento opera via protocolo dedicado NVR/RTSP (Portas: ${cam.open_camera_ports.join(', ') || 'Nenhuma'}). Veja a aba Matriz RTSP.</span>`;
          }
        }

        // Renderiza aba Matriz RTSP & Portas
        const summaryEl = document.getElementById('camProbeSummary');
        const rtspListEl = document.getElementById('camRtspList');
        if (summaryEl) {
          const portsBadges =
            cam.open_camera_ports.length > 0
              ? cam.open_camera_ports.map((p) => `<span class="port-tag" style="font-size:0.82rem; padding:3px 10px;">PORTA ${p} ABERTA</span>`).join(' ')
              : '<span style="color:var(--text-muted);">Nenhuma porta de vídeo padrão respondeu ao probe rápido.</span>';
          summaryEl.innerHTML = `
            <div style="font-size:0.8rem; color:var(--text-secondary); margin-bottom:0.4rem;">PORTAS DE MÍDIA / GERÊNCIA ATIVAS EM <strong>${cam.ip}</strong>:</div>
            <div>${portsBadges}</div>
          `;
        }
        if (rtspListEl && cam.rtsp_profiles) {
          rtspListEl.innerHTML = cam.rtsp_profiles
            .map(
              (prof) => `
              <div style="display:flex; justify-content:space-between; align-items:center; gap:0.75rem; background:rgba(0,0,0,0.3); padding:0.65rem 1rem; border-radius:8px; border:1px solid var(--border-subtle);">
                <div style="overflow:hidden;">
                  <div style="font-size:0.78rem; font-weight:700; color:var(--neon-cyan);">${escapeHtml(prof.brand)}</div>
                  <div style="font-size:0.78rem; font-family:var(--font-mono); color:var(--text-primary); text-overflow:ellipsis; overflow:hidden;">${escapeHtml(prof.url)}</div>
                </div>
                <div style="display:flex; gap:0.4rem; flex-shrink:0;">
                  <button class="btn-secondary" style="padding:4px 10px; font-size:0.75rem;" onclick="navigator.clipboard.writeText('${prof.url}'); App.showToast('URL RTSP copiada!', 'success');">
                    📋 Copiar RTSP
                  </button>
                  <a href="vlc://${prof.url}" class="btn-primary" style="padding:4px 10px; font-size:0.75rem; text-decoration:none;">
                    ▶️ Abrir VLC
                  </a>
                </div>
              </div>
            `
            )
            .join('');
        }

        if (osdStatus) {
          osdStatus.textContent = `PORTAS DETECTADAS: [${cam.open_camera_ports.join(', ') || 'NENHUMA'}]`;
        }
      } catch (err) {
        if (osdStatus) osdStatus.textContent = `ERRO NA SONDA: ${err.message}`;
      }
    },

    async connectCameraStream() {
      this.stopCameraStream();
      const user = document.getElementById('camInputUser').value.trim();
      const pass = document.getElementById('camInputPass').value;
      let targetUrl = document.getElementById('camInputUrl').value.trim();

      if (!targetUrl && this.activeCamIp) {
        targetUrl = `http://${this.activeCamIp}/cgi-bin/snapshot.cgi`;
        document.getElementById('camInputUrl').value = targetUrl;
      }

      // Salva credenciais/URL nos metadados do ativo
      if (this.activeCamMac) {
        API.updateDeviceMeta({
          mac: this.activeCamMac,
          camera_url: targetUrl,
          camera_user: user,
          camera_pass: pass,
        }).catch(() => {});
      }

      const img = document.getElementById('camLiveImage');
      const placeholder = document.getElementById('camPlaceholderMsg');
      const osdStatus = document.getElementById('camOsdStatus');

      const refreshFrame = () => {
        const proxyUrl = `${API.baseUrl}/api/camera/snapshot?url=${encodeURIComponent(targetUrl)}&user=${encodeURIComponent(user)}&pass=${encodeURIComponent(pass)}&_t=${Date.now()}`;
        const tempImg = new Image();
        tempImg.onload = () => {
          img.src = proxyUrl;
          img.style.display = 'block';
          placeholder.style.display = 'none';
          if (osdStatus) osdStatus.textContent = 'SINAL ÓPTICO ATIVO (LIVE STREAM PROXY)';
        };
        tempImg.onerror = () => {
          if (osdStatus) {
            osdStatus.textContent = 'SEM RESPOSTA DE SNAPSHOT HTTP (USE A ABA INTERFACE WEB OU MATRIZ RTSP)';
          }
        };
        tempImg.src = proxyUrl;
      };

      refreshFrame();
      this.camStreamTimer = setInterval(refreshFrame, 1500);
    },

    stopCameraStream() {
      if (this.camStreamTimer) {
        clearInterval(this.camStreamTimer);
        this.camStreamTimer = null;
      }
    },

    captureCameraFrame() {
      const img = document.getElementById('camLiveImage');
      if (!img || img.style.display === 'none' || !img.src) {
        this.showToast('Conecte um feed de vídeo primeiro para capturar o frame.', 'error');
        return;
      }
      const a = document.createElement('a');
      a.href = img.src;
      a.download = `bastion_cam_${this.activeCamIp || 'capture'}_${Date.now()}.jpg`;
      a.click();
      this.showToast('Frame capturado com sucesso!', 'success');
    },

    // ─── TAB: CENTRAL DE DEFESA, FIREWALL & HONEYPORT ────────────────────────
    async loadDefensePanel() {
      try {
        const data = await API.getDefenseStatus();

        // Badge de Privilégio Kernel vs Usuário
        const adminBadge = document.getElementById('defAdminBadge');
        if (adminBadge) {
          if (data.is_admin_elevated) {
            adminBadge.className = 'status-badge authorized';
            adminBadge.textContent = '⚡ KERNEL ENFORCED (ADMIN)';
          } else {
            adminBadge.className = 'status-badge unknown';
            adminBadge.textContent = '🛡️ MODO USUÁRIO (RODE COMO ADMIN P/ FIREWALL NATIVO)';
          }
        }

        // Atualiza card do Gateway
        const gwInfo = document.getElementById('defGatewayInfo');
        const gwBadge = document.getElementById('defGatewayBadge');
        if (gwInfo && data.gateway_protection) {
          const gw = data.gateway_protection;
          gwInfo.textContent = gw.ip ? `${gw.ip} [${gw.mac || 'Resolvendo...'}]` : 'Aguardando verificação...';
          if (gwBadge) {
            if (gw.is_locked) {
              gwBadge.className = 'status-badge authorized';
              gwBadge.textContent = '🔒 TRAVADO ESTÁTICO';
            } else {
              gwBadge.className = 'status-badge unknown';
              gwBadge.textContent = 'MONITORANDO';
            }
          }
        }

        // Atualiza card e tabela do Honeyport
        if (data.honeyport) {
          const hp = data.honeyport;
          const hpBadge = document.getElementById('honeyportStatusBadge');
          const hpPorts = document.getElementById('honeyportPortsList');
          const chkAuto = document.getElementById('chkHoneyportAutoBlock');
          if (hpBadge) {
            hpBadge.className = hp.enabled ? 'status-badge authorized' : 'status-badge quarantined';
            hpBadge.textContent = hp.enabled ? `ATIVO (${hp.total_hits} HITS)` : 'DESATIVADO';
          }
          if (hpPorts && hp.ports) {
            hpPorts.textContent = hp.ports.join(', ');
          }
          if (chkAuto) {
            chkAuto.checked = Boolean(hp.auto_block);
          }

          const hpTbody = document.getElementById('honeyportHitsTableBody');
          if (hpTbody) {
            const hits = hp.recent_hits || [];
            if (hits.length === 0) {
              hpTbody.innerHTML = `
                <tr>
                  <td colspan="7" style="text-align:center; padding: 1.5rem; color: var(--text-muted);">
                    Nenhuma tentativa de varredura de portas (Nmap) detectada nas portas isca até o momento.
                  </td>
                </tr>
              `;
            } else {
              hpTbody.innerHTML = hits
                .map(
                  (h) => `
                  <tr>
                    <td><span class="ip-pill" style="color:var(--crimson-alert); font-weight:700;">${escapeHtml(h.attacker_ip)}:${h.attacker_port}</span></td>
                    <td><span class="port-tag">TCP/${h.trap_port}</span></td>
                    <td><span class="vendor-chip">${escapeHtml(h.decoy_service)}</span></td>
                    <td style="font-family:var(--font-mono); font-size:0.75rem; color:var(--cyber-amber);">${escapeHtml(h.payload_sample)}</td>
                    <td><span class="status-badge ${h.auto_blocked ? 'quarantined' : 'unknown'}">${h.auto_blocked ? 'BLOQUEADO AUTO' : 'ALERTADO'}</span></td>
                    <td style="font-size:0.74rem; color:var(--text-muted); font-family:var(--font-mono);">${this.formatLocalDateTime(h.timestamp)}</td>
                    <td>
                      <button class="btn-action-icon" title="Bloquear IP Atacante" onclick="App.blockDeviceFromRow('${h.attacker_ip}', '')" style="border-color:rgba(255,59,48,0.4); color:#ff3b30;">
                        ⛔
                      </button>
                    </td>
                  </tr>
                `
                )
                .join('');
            }
          }
        }

        // Renderiza tabela de regras de firewall
        const tbody = document.getElementById('firewallRulesTableBody');
        if (tbody) {
          const rules = data.active_blocks || [];
          if (rules.length === 0) {
            tbody.innerHTML = `
              <tr>
                <td colspan="7" style="text-align:center; padding: 2rem; color: var(--text-muted);">
                  Nenhuma regra de bloqueio ativa. O tráfego para dispositivos autorizados flui normalmente.
                </td>
              </tr>
            `;
          } else {
            tbody.innerHTML = rules
              .map(
                (r) => `
              <tr>
                <td><span class="mac-pill" style="font-family:var(--font-mono);">${escapeHtml(r.rule_id)}</span></td>
                <td><span class="ip-pill">${escapeHtml(r.ip || '—')}</span></td>
                <td><span class="mac-pill">${escapeHtml(r.mac || '—')}</span></td>
                <td style="color:var(--text-primary); font-weight:500;">${escapeHtml(r.reason)}</td>
                <td>
                  <span class="status-badge ${r.kernel_enforced ? 'authorized' : 'unknown'}">
                    ${r.kernel_enforced ? 'KERNEL FIREWALL (IN+OUT)' : 'ISOLAMENTO LÓGICO'}
                  </span>
                </td>
                <td style="font-size:0.75rem; color:var(--text-muted); font-family:var(--font-mono);">${this.formatLocalDateTime(r.timestamp)}</td>
                <td>
                  <button class="btn-action-icon" title="Remover Bloqueio" onclick="App.unblockThreat('${r.ip || ''}', '${r.mac || ''}')" style="border-color:rgba(0,255,136,0.4); color:var(--neon-emerald);">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>
                  </button>
                </td>
              </tr>
            `
              )
              .join('');
          }
        }
      } catch (err) {
        this.showToast(`Erro ao carregar Central de Defesa: ${err.message}`, 'error');
      }
    },

    async saveHoneyportConfig() {
      const chkAuto = document.getElementById('chkHoneyportAutoBlock');
      const autoBlock = chkAuto ? chkAuto.checked : false;
      try {
        const res = await API.configureHoneyport(true, autoBlock);
        this.showToast(res.message, 'success');
        await this.loadDefensePanel();
      } catch (err) {
        this.showToast(`Erro no Honeyport: ${err.message}`, 'error');
      }
    },

    async executeManualBlock() {
      const inputTarget = document.getElementById('inputBlockTarget');
      const inputReason = document.getElementById('inputBlockReason');
      if (!inputTarget) return;

      const target = inputTarget.value.trim();
      const reason = inputReason ? inputReason.value.trim() : '';

      if (!target) {
        this.showToast('Informe um IP ou MAC para aplicar o bloqueio no firewall.', 'error');
        return;
      }

      const isIp = target.includes('.') || (target.includes(':') && target.length < 8);
      const ip = isIp ? target : '';
      const mac = !isIp ? target : '';

      try {
        const res = await API.blockThreat(ip, mac, reason || 'Bloqueio manual via Dashboard');
        this.showToast(res.message, 'success');
        inputTarget.value = '';
        if (inputReason) inputReason.value = '';
        await this.loadDefensePanel();
      } catch (err) {
        this.showToast(`Erro no bloqueio: ${err.message}`, 'error');
      }
    },

    async blockDeviceFromRow(ip, mac) {
      const reason = prompt(
        `Confirma aplicar DROP bidirecional (Entrada + Saída) no Firewall para ${ip || mac}?\nInforme o motivo:`,
        'Ação defensiva rápida'
      );
      if (reason === null) return;

      try {
        const res = await API.blockThreat(ip, mac, reason || 'Ação defensiva rápida');
        this.showToast(res.message, 'success');
        if (mac) await this.changeStatus(mac, 'quarantined');
        await this.loadDefensePanel();
      } catch (err) {
        this.showToast(`Erro ao bloquear: ${err.message}`, 'error');
      }
    },

    async unblockThreat(ip, mac) {
      if (!confirm(`Deseja revogar o bloqueio de firewall para ${ip || mac}?`)) return;
      try {
        const res = await API.unblockThreat(ip, mac);
        this.showToast(res.message, 'success');
        await this.loadDefensePanel();
      } catch (err) {
        this.showToast(`Erro ao desbloquear: ${err.message}`, 'error');
      }
    },

    async lockGateway() {
      try {
        const res = await API.lockGateway();
        this.showToast(res.message, 'success');
        await this.loadDefensePanel();
      } catch (err) {
        this.showToast(`Erro ao travar Gateway: ${err.message}`, 'error');
      }
    },

    // ─── TAB 3: Renderiza Baseline Legada & Protocolos L2 ────────────────────
    renderLegacyTable() {
      const tbody = document.getElementById('legacyTableBody');
      if (!tbody) return;

      const legacyDevices = this.devices.filter((d) => this.isLegacyDevice(d));

      if (legacyDevices.length === 0) {
        tbody.innerHTML = `
          <tr>
            <td colspan="7" style="text-align:center; padding: 2rem; color: var(--text-muted);">
              Nenhum dispositivo inativo encontrado. Todos os aparelhos cadastrados estão ativos ou a base está limpa.
            </td>
          </tr>
        `;
        return;
      }

      tbody.innerHTML = legacyDevices
        .map((dev) => {
          const meta = dev.metadata || {};
          const deviceType = meta.device_type || 'Dispositivo Legado';
          const osHint = meta.os_hint || '';
          const icon = this.getDeviceIcon(deviceType, dev);

          return `
          <tr style="opacity:0.75;">
            <td><span class="mac-pill" style="background:rgba(100,100,120,0.25); color:var(--text-muted);">${dev.mac}</span></td>
            <td><span class="ip-pill" style="border-color:rgba(255,255,255,0.08);">${dev.ip || '0.0.0.0'}</span></td>
            <td>
              <div style="font-size:0.85rem; font-weight:600; display:flex; align-items:center; gap:0.35rem;">
                <span>${icon}</span>
                <span style="color:var(--text-secondary);">${escapeHtml(deviceType)}</span>
              </div>
              ${osHint ? `<div style="font-size:0.72rem; color:var(--text-muted); margin-top:2px;">${escapeHtml(osHint)}</div>` : ''}
            </td>
            <td><span class="vendor-chip" style="font-size:0.75rem;">${dev.vendor !== 'Fabricante desconhecido' ? escapeHtml(dev.vendor) : '—'}</span></td>
            <td><span class="status-badge ${dev.status.toLowerCase()}">${dev.status}</span></td>
            <td style="font-size:0.75rem; color:var(--text-muted); font-family:var(--font-mono);">${this.formatLocalDateTime(dev.first_seen || dev.last_seen)}</td>
            <td>
              <button class="btn-action-icon" title="Excluir Registro Legado" onclick="App.deleteDevice('${dev.mac}')" style="border-color:rgba(255,59,48,0.3); color:#ff453a;">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
              </button>
            </td>
          </tr>
          `;
        })
        .join('');
    },

    async deleteDevice(mac) {
      if (!confirm(`Deseja realmente remover o registro ${mac} do inventário?`)) return;
      try {
        await API.deleteDevice(mac);
        this.showToast(`Ativo ${mac} removido com sucesso`, 'success');
        await this.fetchDevices();
      } catch (err) {
        this.showToast(`Erro ao remover: ${err.message}`, 'error');
      }
    },

    async purgeLegacy() {
      if (!confirm('Deseja expurgar todos os registros legados com IP 0.0.0.0 e endereços multicast?')) return;
      try {
        const res = await API.purgeLegacy();
        this.showToast(res.message, 'success');
        await this.fetchDevices();
      } catch (err) {
        this.showToast(`Erro ao expurgar: ${err.message}`, 'error');
      }
    },

    async changeStatus(mac, status) {
      try {
        await API.updateDeviceStatus(mac, status);
        this.showToast(`Status de ${mac} alterado para ${status.toUpperCase()}`, 'success');
        await this.fetchDevices();
      } catch (err) {
        this.showToast(`Erro ao alterar status: ${err.message}`, 'error');
      }
    },

    async loadAuditTrail() {
      const container = document.getElementById('blockchainStream');
      if (!container) return;

      container.innerHTML = '<div style="color:var(--text-muted); padding:1rem;">Carregando blocos criptográficos...</div>';
      try {
        const data = await API.getAuditTrail();
        if (!data.events || data.events.length === 0) {
          container.innerHTML = '<div style="color:var(--text-muted); padding:1rem;">Nenhum evento registrado no audit trail ainda.</div>';
          return;
        }

        container.innerHTML = data.events
          .map(
            (ev, idx) => `
          <div class="block-card">
            <div>
              <div class="block-event-type">${escapeHtml(ev.event_type)}</div>
              <div style="font-size:0.75rem; color:var(--text-muted); font-family:var(--font-mono);">${this.formatLocalDateTime(ev.timestamp)}</div>
              <div style="font-size:0.75rem; color:var(--neon-emerald); font-weight:600; margin-top:4px;">BLOCO #${data.total_events - idx}</div>
            </div>
            <div class="block-hashes">
              <div class="hash-row"><span class="hash-label">PREV HASH:</span> <span class="hash-val">${ev.previous_hash}</span></div>
              <div class="hash-row"><span class="hash-label">HASH ATUAL:</span> <span class="hash-val" style="color:var(--neon-cyan);">${ev.entry_hash}</span></div>
            </div>
            <div style="font-size:0.75rem; color:var(--text-secondary); text-align:right;">
              <div>Fonte: <strong>${escapeHtml(ev.source)}</strong></div>
              <div>Severidade: <span class="status-badge ${ev.severity === 'CRITICAL' ? 'quarantined' : ev.severity === 'WARNING' ? 'unknown' : 'authorized'}">${ev.severity}</span></div>
            </div>
          </div>
        `
          )
          .join('');
      } catch (err) {
        container.innerHTML = `<div style="color:var(--crimson-alert);">Falha ao carregar audit trail: ${err.message}</div>`;
      }
    },

    async loadLogs() {
      const body = document.getElementById('terminalLogBody');
      if (!body) return;
      try {
        const data = await API.getLogs();
        if (data.logs && data.logs.length > 0) {
          body.innerHTML = data.logs
            .map((line) => {
              let cls = 'info';
              if (line.includes('[WARNING]') || line.includes('[ALERT-WARN]') || line.includes('HONEYPORT')) cls = 'warn';
              if (line.includes('[ERROR]') || line.includes('[CRITICAL]') || line.includes('KILLCAM')) cls = 'error';
              return `<div class="log-line ${cls}">${escapeHtml(line)}</div>`;
            })
            .join('');
          body.scrollTop = body.scrollHeight;
        } else {
          body.innerHTML = '<div class="log-line info">Log limpo. Monitorando telemetria em tempo real...</div>';
        }
      } catch (err) {
        body.innerHTML = `<div class="log-line error">Falha ao obter logs: ${err.message}</div>`;
      }
    },

    showToast(message, type = 'info') {
      const container = document.getElementById('toastContainer');
      if (!container) return;

      const toast = document.createElement('div');
      toast.className = 'toast';
      const iconColor = type === 'success' ? '#00ff88' : type === 'error' ? '#ff3b30' : '#00d2ff';

      toast.innerHTML = `
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="${iconColor}" stroke-width="2">
          <circle cx="12" cy="12" r="10"/>
          <line x1="12" y1="8" x2="12" y2="12"/>
          <line x1="12" y1="16" x2="12.01" y2="16"/>
        </svg>
        <span>${escapeHtml(message)}</span>
      `;
      container.appendChild(toast);

      setTimeout(() => {
        toast.style.animation = 'slideIn 0.3s reverse';
        setTimeout(() => toast.remove(), 250);
      }, 4000);
    },
  };

  function escapeHtml(unsafe) {
    return String(unsafe || '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  window.App = App;
  App.init();
});
