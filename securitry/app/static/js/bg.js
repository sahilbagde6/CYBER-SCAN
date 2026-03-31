// Animated neon grid + particles background
(function() {
  const canvas = document.getElementById('bg-canvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');

  let W, H, particles = [], gridOffset = 0;

  function resize() {
    W = canvas.width = window.innerWidth;
    H = canvas.height = window.innerHeight;
  }

  function initParticles() {
    particles = [];
    const count = Math.floor((W * H) / 18000);
    for (let i = 0; i < count; i++) {
      particles.push({
        x: Math.random() * W,
        y: Math.random() * H,
        r: Math.random() * 1.5 + 0.3,
        vx: (Math.random() - 0.5) * 0.3,
        vy: (Math.random() - 0.5) * 0.3,
        alpha: Math.random() * 0.6 + 0.1,
        color: Math.random() > 0.5 ? '0,212,255' : '0,255,136',
      });
    }
  }

  function drawGrid() {
    const size = 60;
    gridOffset = (gridOffset + 0.2) % size;
    ctx.strokeStyle = 'rgba(0,212,255,0.04)';
    ctx.lineWidth = 0.5;
    // Vertical lines
    for (let x = (gridOffset % size) - size; x < W + size; x += size) {
      ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, H); ctx.stroke();
    }
    // Horizontal lines
    for (let y = (gridOffset % size) - size; y < H + size; y += size) {
      ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(W, y); ctx.stroke();
    }
  }

  function drawParticles() {
    for (const p of particles) {
      ctx.beginPath();
      ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
      ctx.fillStyle = `rgba(${p.color},${p.alpha})`;
      ctx.fill();

      // Move
      p.x += p.vx; p.y += p.vy;
      if (p.x < 0) p.x = W;
      if (p.x > W) p.x = 0;
      if (p.y < 0) p.y = H;
      if (p.y > H) p.y = 0;
    }
  }

  function drawScanLines() {
    // Occasional horizontal scan sweep
    const t = Date.now() * 0.001;
    const y = ((Math.sin(t * 0.4) + 1) / 2) * H;
    const grad = ctx.createLinearGradient(0, y - 40, 0, y + 40);
    grad.addColorStop(0, 'rgba(0,212,255,0)');
    grad.addColorStop(0.5, 'rgba(0,212,255,0.06)');
    grad.addColorStop(1, 'rgba(0,212,255,0)');
    ctx.fillStyle = grad;
    ctx.fillRect(0, y - 40, W, 80);
  }

  function frame() {
    ctx.clearRect(0, 0, W, H);
    drawGrid();
    drawParticles();
    drawScanLines();
    requestAnimationFrame(frame);
  }

  resize();
  initParticles();
  frame();
  window.addEventListener('resize', () => { resize(); initParticles(); });
})();
