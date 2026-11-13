/**
 * Bastion-Core — Internationalization (i18n) Engine
 * Supported: 'pt' (Português - Brasil), 'en' (English - US)
 * Zero external dependencies. Fast runtime DOM mapping.
 */
(function() {
  'use strict';

  const DICTIONARY = {
    pt: {
      brand_title: 'BASTION AUDIT',
      brand_subtitle: 'Painel de Segurança & Monitoramento da Rede',
      status_connected: 'CONECTADO (INTERNET OK)',
      status_connecting: 'CONECTANDO...',
      status_offline: 'OFFLINE / SEM CONEXÃO',
      btn_theme_light: '☀️ Modo Claro',
      btn_theme_dark: '🌙 Modo Escuro',
      btn_settings: '⚙️ Personalizar Visual',
      btn_reclassify: '🔄 Atualizar Modelos',
      btn_export: '📥 Exportar Planilha',
      btn_scan: '⚡ Buscar Dispositivos',
      btn_lang: '🌐 PT',

      tab_overview: 'Dispositivos Online',
      tab_devices: 'Todos os Dispositivos',
      tab_legacy: 'Dispositivos Inativos',
      tab_defense: 'Segurança & Bloqueios',
      tab_audit: 'Histórico de Alterações',
      tab_logs: 'Logs do Sistema',

      stat_online_title: 'Dispositivos Conectados',
      stat_online_sub: 'Aparelhos ativos na sua rede agora',
      stat_trusted_title: 'Dispositivos Confiáveis',
      stat_trusted_sub: 'Aparelhos aprovados por você',
      stat_unknown_title: 'Não Reconhecidos / Novos',
      stat_unknown_sub: 'Aguardando sua confirmação',
      stat_inactive_title: 'Histórico / Inativos',
      stat_inactive_sub: 'Guardados na memória do Bastion',

      search_placeholder: '🔍 Buscar por nome do aparelho, IP ou fabricante...',
      filter_all: 'Todos',
      filter_trusted: 'Confiáveis',
      filter_warning: 'Atenção',
      filter_quarantine: 'Quarentena',

      section_live_devices: '📡 Aparelhos Conectados na Rede Agora',
      empty_devices: 'Nenhum dispositivo encontrado no radar.',

      audit_title: '🛡️ Trilha de Auditoria Criptográfica (SHA-256)',
      audit_sub: 'Registro imutável encadeado de cada evento ocorrido na sua rede.',
      btn_verify_audit: '🔍 Verificar Integridade',
      btn_export_audit: '📥 Exportar JSONL',

      logs_title: '📜 Registro do Sistema (bastion_system.log)',
      btn_clear_logs: '🗑️ Limpar Logs',
      btn_refresh_logs: '🔄 Atualizar',

      defense_title: '🛡️ Central de Defesa & Firewall Ativo',
      defense_sub: 'Controle de perímetro, isolamento de invasores e proteção do Gateway.',
      label_target: 'IP ou MAC Alvo:',
      btn_block: '🚫 Bloquear Alvo',

      settings_title: '⚙️ Personalizar Visual do Bastion',
      settings_theme: 'Tema de Cores',
      settings_density: 'Estilo da Lista de Aparelhos',
      density_simple_title: '✨ Visual Simples (Recomendado)',
      density_simple_sub: 'Foco no essencial: Nome, IP, Fabricante e ações rápidas.',
      density_tech_title: '🔧 Visual Técnico Completo',
      density_tech_sub: 'Exibe portas de rede detectadas, sistema operacional e métricas.',
      btn_save_settings: '✅ Concluir e Salvar',

      toast_theme_light: '☀️ Visual Claro ativado!',
      toast_theme_dark: '🌙 Visual Escuro ativado!',
      toast_scan_start: 'Varredura ativa de radar iniciada...',
      toast_scan_done: 'Varredura concluída! Lista atualizada.',
      toast_audit_verified: 'Auditoria verificada com 100% de integridade!',
      toast_lang_changed: 'Idioma alterado para Português (Brasil)'
    },
    en: {
      brand_title: 'BASTION AUDIT',
      brand_subtitle: 'Network Security & Active Monitoring Dashboard',
      status_connected: 'CONNECTED (INTERNET OK)',
      status_connecting: 'CONNECTING...',
      status_offline: 'OFFLINE / NO CONNECTION',
      btn_theme_light: '☀️ Light Mode',
      btn_theme_dark: '🌙 Dark Mode',
      btn_settings: '⚙️ Customize View',
      btn_reclassify: '🔄 Update Models',
      btn_export: '📥 Export CSV',
      btn_scan: '⚡ Scan Devices',
      btn_lang: '🌐 EN',

      tab_overview: 'Online Devices',
      tab_devices: 'All Devices',
      tab_legacy: 'Inactive Devices',
      tab_defense: 'Security & Defense',
      tab_audit: 'Audit History',
      tab_logs: 'System Logs',

      stat_online_title: 'Connected Devices',
      stat_online_sub: 'Active devices currently on your network',
      stat_trusted_title: 'Trusted Devices',
      stat_trusted_sub: 'Devices approved and authorized by you',
      stat_unknown_title: 'Unrecognized / New',
      stat_unknown_sub: 'Pending security review or confirmation',
      stat_inactive_title: 'History / Inactive',
      stat_inactive_sub: 'Retained in Bastion security inventory',

      search_placeholder: '🔍 Search by device name, IP, or vendor...',
      filter_all: 'All',
      filter_trusted: 'Trusted',
      filter_warning: 'Warning',
      filter_quarantine: 'Quarantine',

      section_live_devices: '📡 Active Devices On Network Now',
      empty_devices: 'No devices detected on radar yet.',

      audit_title: '🛡️ Cryptographic Audit Ledger (SHA-256)',
      audit_sub: 'Immutable, chained append-only event log of every network mutation.',
      btn_verify_audit: '🔍 Verify Integrity',
      btn_export_audit: '📥 Export JSONL',

      logs_title: '📜 System Telemetry Logs (bastion_system.log)',
      btn_clear_logs: '🗑️ Clear Logs',
      btn_refresh_logs: '🔄 Refresh Logs',

      defense_title: '🛡️ Defense Center & Active Firewall',
      defense_sub: 'Perimeter defense, intruder isolation, and Gateway shield.',
      label_target: 'Target IP or MAC:',
      btn_block: '🚫 Block Target',

      settings_title: '⚙️ Customize Bastion Interface',
      settings_theme: 'Color Theme',
      settings_density: 'Device List Density',
      density_simple_title: '✨ Minimalist View (Recommended)',
      density_simple_sub: 'Essential details: Device Name, IP, Vendor, and quick actions.',
      density_tech_title: '🔧 Full Technical View',
      density_tech_sub: 'Displays open ports, operating system fingerprints, and telemetry.',
      btn_save_settings: '✅ Save & Close',

      toast_theme_light: '☀️ Light mode enabled!',
      toast_theme_dark: '🌙 Cyber Dark mode enabled!',
      toast_scan_start: 'Active radar network sweep initiated...',
      toast_scan_done: 'Sweep finished! Inventory updated.',
      toast_audit_verified: 'Audit trail verified with 100% cryptographic integrity!',
      toast_lang_changed: 'Language switched to English (US)'
    }
  };

  const I18N = {
    current: localStorage.getItem('bastion_lang') || 'pt',

    getLang() {
      return this.current;
    },

    setLang(lang) {
      if (!DICTIONARY[lang]) return;
      this.current = lang;
      localStorage.setItem('bastion_lang', lang);
      this.apply();
      window.dispatchEvent(new CustomEvent('languageChanged', { detail: { lang } }));
    },

    toggle() {
      const next = this.current === 'pt' ? 'en' : 'pt';
      this.setLang(next);
      return next;
    },

    t(key, fallback = '') {
      const dict = DICTIONARY[this.current] || DICTIONARY.pt;
      return dict[key] !== undefined ? dict[key] : (fallback || key);
    },

    apply() {
      const dict = DICTIONARY[this.current] || DICTIONARY.pt;
      document.documentElement.setAttribute('lang', this.current === 'pt' ? 'pt-BR' : 'en');

      // Update text nodes
      document.querySelectorAll('[data-i18n]').forEach(el => {
        const key = el.getAttribute('data-i18n');
        if (dict[key]) {
          el.textContent = dict[key];
        }
      });

      // Update placeholders
      document.querySelectorAll('[data-i18n-placeholder]').forEach(el => {
        const key = el.getAttribute('data-i18n-placeholder');
        if (dict[key]) {
          el.setAttribute('placeholder', dict[key]);
        }
      });

      // Update titles
      document.querySelectorAll('[data-i18n-title]').forEach(el => {
        const key = el.getAttribute('data-i18n-title');
        if (dict[key]) {
          el.setAttribute('title', dict[key]);
        }
      });

      // Update toggle button text
      const btn = document.getElementById('btnLangToggle');
      if (btn) {
        btn.textContent = this.current === 'pt' ? '🇧🇷 PT' : '🇺🇸 EN';
        btn.setAttribute('title', this.current === 'pt' ? 'Mudar para Inglês (Switch to English)' : 'Switch to Portuguese (Mudar para Português)');
      }
    }
  };

  window.I18N = I18N;

  // Auto-apply on DOM ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => I18N.apply());
  } else {
    I18N.apply();
  }
})();
