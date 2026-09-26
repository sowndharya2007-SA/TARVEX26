import React, { useEffect, useRef } from "react";

const CyberBackground = () => {
  const canvasRef = useRef(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext("2d");

    let width = 0;
    let height = 0;
    let animationFrame;

    const mouse = {
      x: -1000,
      y: -1000,
    };

    const particles = [];
    const PARTICLE_COUNT = 75;
    const CONNECTION_DISTANCE = 150;

    const resize = () => {
      const dpr = Math.min(window.devicePixelRatio || 1, 2);

      width = window.innerWidth;
      height = window.innerHeight;

      canvas.width = width * dpr;
      canvas.height = height * dpr;

      canvas.style.width = `${width}px`;
      canvas.style.height = `${height}px`;

      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    };

    const createParticle = () => ({
      x: Math.random() * width,
      y: Math.random() * height,
      vx: (Math.random() - 0.5) * 0.35,
      vy: (Math.random() - 0.5) * 0.35,
      radius: Math.random() * 1.6 + 0.5,
      pulse: Math.random() * Math.PI * 2,
      pulseSpeed: Math.random() * 0.015 + 0.005,
    });

    const initializeParticles = () => {
      particles.length = 0;

      for (let i = 0; i < PARTICLE_COUNT; i++) {
        particles.push(createParticle());
      }
    };

    const drawGrid = () => {
      ctx.save();

      ctx.strokeStyle = "rgba(0, 210, 255, 0.035)";
      ctx.lineWidth = 1;

      const gridSize = 70;

      for (let x = 0; x < width; x += gridSize) {
        ctx.beginPath();
        ctx.moveTo(x, 0);
        ctx.lineTo(x, height);
        ctx.stroke();
      }

      for (let y = 0; y < height; y += gridSize) {
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(width, y);
        ctx.stroke();
      }

      ctx.restore();
    };

    const drawConnections = () => {
      for (let i = 0; i < particles.length; i++) {
        for (let j = i + 1; j < particles.length; j++) {
          const p1 = particles[i];
          const p2 = particles[j];

          const dx = p1.x - p2.x;
          const dy = p1.y - p2.y;

          const distance = Math.sqrt(dx * dx + dy * dy);

          if (distance < CONNECTION_DISTANCE) {
            const opacity =
              (1 - distance / CONNECTION_DISTANCE) * 0.22;

            ctx.beginPath();
            ctx.moveTo(p1.x, p1.y);
            ctx.lineTo(p2.x, p2.y);

            ctx.strokeStyle = `rgba(0, 210, 255, ${opacity})`;
            ctx.lineWidth = 0.7;

            ctx.stroke();
          }
        }
      }
    };

    const drawParticles = (time) => {
      particles.forEach((particle) => {
        particle.pulse += particle.pulseSpeed;

        const glow =
          particle.radius +
          Math.sin(particle.pulse) * 0.45;

        ctx.beginPath();
        ctx.arc(
          particle.x,
          particle.y,
          Math.max(0.4, glow),
          0,
          Math.PI * 2
        );

        ctx.fillStyle = "rgba(0, 220, 255, 0.75)";
        ctx.shadowBlur = 8;
        ctx.shadowColor = "rgba(0, 210, 255, 0.65)";

        ctx.fill();

        ctx.shadowBlur = 0;
      });
    };

    const updateParticles = () => {
      particles.forEach((particle) => {
        particle.x += particle.vx;
        particle.y += particle.vy;

        if (particle.x < -20) particle.x = width + 20;
        if (particle.x > width + 20) particle.x = -20;

        if (particle.y < -20) particle.y = height + 20;
        if (particle.y > height + 20) particle.y = -20;

        const dx = particle.x - mouse.x;
        const dy = particle.y - mouse.y;

        const distance = Math.sqrt(dx * dx + dy * dy);

        if (distance < 120) {
          const force = (120 - distance) / 120;

          particle.x += (dx / Math.max(distance, 1)) * force * 0.25;
          particle.y += (dy / Math.max(distance, 1)) * force * 0.25;
        }
      });
    };

    const animate = (time) => {
      ctx.clearRect(0, 0, width, height);

      drawGrid();
      drawConnections();
      drawParticles(time);
      updateParticles();

      animationFrame = requestAnimationFrame(animate);
    };

    const handleMouseMove = (event) => {
      mouse.x = event.clientX;
      mouse.y = event.clientY;
    };

    const handleMouseLeave = () => {
      mouse.x = -1000;
      mouse.y = -1000;
    };

    resize();
    initializeParticles();

    window.addEventListener("resize", resize);
    window.addEventListener("mousemove", handleMouseMove);
    window.addEventListener("mouseleave", handleMouseLeave);

    animationFrame = requestAnimationFrame(animate);

    return () => {
      cancelAnimationFrame(animationFrame);

      window.removeEventListener("resize", resize);
      window.removeEventListener("mousemove", handleMouseMove);
      window.removeEventListener("mouseleave", handleMouseLeave);
    };
  }, []);

  return (
    <canvas
      ref={canvasRef}
      className="tarvex-cyber-background"
      aria-hidden="true"
    />
  );
};

export default CyberBackground;