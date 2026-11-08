/**
 * Bastion Audit v2.0 Enterprise - Canvas Radar Renderer
 * Animação de radar circular militar/SOC com posicionamento estocástico e persistente de alvos.
 */
class CyberRadar {
  constructor(canvasId) {
    this.canvas = document.getElementById(canvasId);
    if (!this.canvas) return;
    this.ctx = this.canvas.getContext('2d');
    this.width = this.canvas.width = 280;
    this.height = this.canvas.height = 280;
    this.centerX = this.width / 2;
    this.centerY = this.height / 2;
    this.radius = this.width / 2 - 10;

    this.angle = 0;
    this.speed = 0.035;
    this.devices = [];
    this.blips = [];

    this._initAnimation();
  }

  setDevices(devices) {
    this.devices = devices;
    this.blips = devices.map((dev, idx) => {
      // Gera posição polar pseudo-aleatória consistente baseada no MAC
      let hash = 0;
      for (let i = 0; i < dev.mac.length; i++) {
        hash = (hash << 5) - hash + dev.mac.charCodeAt(i);
        hash |= 0;
      }
      const pseudoRandAngle = Math.abs(hash % 360) * (Math.PI / 180);
      const pseudoRandDist = 0.25 + (Math.abs((hash >> 4) % 65) / 100) * 0.65;

      return {
        mac: dev.mac,
        ip: dev.ip,
        vendor: dev.vendor,
        status: dev.status,
        angle: pseudoRandAngle,
        dist: pseudoRandDist,
        opacity: 0.3,
        lastHit: 0,
      };
    });
  }

  _drawGrid() {
    const ctx = this.ctx;
    const isLight = document.body.classList.contains('theme-light');
    ctx.save();
    ctx.translate(this.centerX, this.centerY);

    // Fundo circular sutil no modo claro
    if (isLight) {
      ctx.fillStyle = '#f8fafc';
      ctx.beginPath();
      ctx.arc(0, 0, this.radius, 0, Math.PI * 2);
      ctx.fill();
    }

    // Círculos concêntricos
    ctx.strokeStyle = isLight ? 'rgba(2, 132, 199, 0.22)' : 'rgba(0, 210, 255, 0.15)';
    ctx.lineWidth = 1;
    for (let r = 0.25; r <= 1.0; r += 0.25) {
      ctx.beginPath();
      ctx.arc(0, 0, this.radius * r, 0, Math.PI * 2);
      ctx.stroke();
    }

    // Eixos Cardeais
    ctx.strokeStyle = isLight ? 'rgba(2, 132, 199, 0.18)' : 'rgba(0, 210, 255, 0.12)';
    ctx.beginPath();
    ctx.moveTo(-this.radius, 0);
    ctx.lineTo(this.radius, 0);
    ctx.moveTo(0, -this.radius);
    ctx.lineTo(0, this.radius);
    ctx.stroke();

    // Borda Externa Metálica
    ctx.strokeStyle = isLight ? 'rgba(2, 132, 199, 0.55)' : 'rgba(0, 210, 255, 0.4)';
    ctx.lineWidth = 2;
    ctx.beginPath();
    ctx.arc(0, 0, this.radius, 0, Math.PI * 2);
    ctx.stroke();

    ctx.restore();
  }

  _drawSweep() {
    const ctx = this.ctx;
    const isLight = document.body.classList.contains('theme-light');
    ctx.save();
    ctx.translate(this.centerX, this.centerY);

    // Cone de Varredura
    const gradient = ctx.createRadialGradient(0, 0, 0, 0, 0, this.radius);
    gradient.addColorStop(0, isLight ? 'rgba(2, 132, 199, 0.04)' : 'rgba(0, 210, 255, 0.05)');
    gradient.addColorStop(1, isLight ? 'rgba(2, 132, 199, 0.18)' : 'rgba(0, 210, 255, 0.2)');

    ctx.beginPath();
    ctx.moveTo(0, 0);
    ctx.arc(0, 0, this.radius, this.angle - 0.4, this.angle);
    ctx.lineTo(0, 0);
    ctx.fillStyle = gradient;
    ctx.fill();

    // Linha do Feixe
    ctx.beginPath();
    ctx.moveTo(0, 0);
    ctx.lineTo(Math.cos(this.angle) * this.radius, Math.sin(this.angle) * this.radius);
    ctx.strokeStyle = isLight ? '#0284c7' : '#00d2ff';
    ctx.lineWidth = 2;
    ctx.shadowColor = isLight ? 'rgba(2, 132, 199, 0.4)' : '#00d2ff';
    ctx.shadowBlur = isLight ? 4 : 10;
    ctx.stroke();

    ctx.restore();
  }

  _drawBlips() {
    const ctx = this.ctx;
    const isLight = document.body.classList.contains('theme-light');
    ctx.save();
    ctx.translate(this.centerX, this.centerY);

    const now = Date.now();

    this.blips.forEach((blip) => {
      // Verifica se a linha de varredura acabou de cruzar o blip
      let diff = Math.abs(this.angle - blip.angle);
      if (diff > Math.PI) diff = Math.PI * 2 - diff;

      if (diff < 0.08) {
        blip.opacity = 1.0;
        blip.lastHit = now;
      } else {
        blip.opacity = Math.max(isLight ? 0.45 : 0.25, blip.opacity - 0.008);
      }

      const x = Math.cos(blip.angle) * (this.radius * blip.dist);
      const y = Math.sin(blip.angle) * (this.radius * blip.dist);

      let color = isLight ? '#059669' : '#00ff88'; // authorized
      if (blip.status === 'unknown') color = isLight ? '#d97706' : '#ffb800';
      if (blip.status === 'quarantined' || blip.status === 'suspicious') color = isLight ? '#dc2626' : '#ff3b30';

      ctx.save();
      ctx.globalAlpha = blip.opacity;
      ctx.shadowColor = color;
      ctx.shadowBlur = isLight ? 4 : blip.opacity * 12;

      // Ponto Central
      ctx.fillStyle = color;
      ctx.beginPath();
      ctx.arc(x, y, isLight ? 4.5 : 3.5, 0, Math.PI * 2);
      ctx.fill();

      // Ondulação de Pulso
      if (blip.opacity > 0.7) {
        ctx.strokeStyle = color;
        ctx.lineWidth = 1;
        ctx.beginPath();
        ctx.arc(x, y, 7 + (1 - blip.opacity) * 10, 0, Math.PI * 2);
        ctx.stroke();
      }

      ctx.restore();
    });

    ctx.restore();
  }

  _animate() {
    this.ctx.clearRect(0, 0, this.width, this.height);
    this._drawGrid();
    this._drawBlips();
    this._drawSweep();

    this.angle += this.speed;
    if (this.angle >= Math.PI * 2) {
      this.angle = 0;
    }

    requestAnimationFrame(() => this._animate());
  }

  _initAnimation() {
    this._animate();
  }
}
