"use client";

import { useEffect, useRef, useState } from "react";

export default function HeroScene() {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
  }, []);

  useEffect(() => {
    if (!mounted) return;
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    let animationFrameId: number;
    let width = (canvas.width = window.innerWidth);
    let height = (canvas.height = window.innerHeight);

    const blobs = [
      { x: width * 0.3, y: height * 0.4, vx: 0.2, vy: 0.15, radius: 300, baseRadius: 300, speed: 0.0008 },
      { x: width * 0.7, y: height * 0.6, vx: -0.15, vy: 0.2, radius: 360, baseRadius: 360, speed: 0.0006 },
      { x: width * 0.5, y: height * 0.3, vx: 0.1, vy: -0.1, radius: 250, baseRadius: 250, speed: 0.001 }
    ];

    const handleResize = () => {
      if (!canvas) return;
      width = canvas.width = window.innerWidth;
      height = canvas.height = window.innerHeight;
    };

    window.addEventListener("resize", handleResize);

    let time = 0;
    const render = () => {
      time += 0.01;
      ctx.fillStyle = "#030305"; 
      ctx.fillRect(0, 0, width, height);

      // Premium Technical Telemetry Grid (Apple/Linear Style)
      ctx.strokeStyle = "rgba(255, 255, 255, 0.012)";
      ctx.lineWidth = 1;
      const gridSize = 64;
      
      for (let x = 0; x < width; x += gridSize) {
        ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, height); ctx.stroke();
      }
      for (let y = 0; y < height; y += gridSize) {
        ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(width, y); ctx.stroke();
      }

      // Morphing Liquid Entities (Ultra-muted platinum slate)
      blobs.forEach((blob) => {
        blob.x += blob.vx;
        blob.y += blob.vy;

        if (blob.x - blob.radius < 0 || blob.x + blob.radius > width) blob.vx *= -1;
        if (blob.y - blob.radius < 0 || blob.y + blob.radius > height) blob.vy *= -1;

        blob.radius = blob.baseRadius + Math.sin(time * blob.speed * 100) * 20;

        const gradient = ctx.createRadialGradient(blob.x, blob.y, 0, blob.x, blob.y, blob.radius);
        gradient.addColorStop(0, "rgba(241, 245, 249, 0.035)"); 
        gradient.addColorStop(0.5, "rgba(148, 163, 184, 0.008)"); 
        gradient.addColorStop(1, "rgba(0, 0, 0, 0)");

        ctx.fillStyle = gradient;
        ctx.beginPath(); ctx.arc(blob.x, blob.y, blob.radius, 0, Math.PI * 2); ctx.fill();
      });

      animationFrameId = requestAnimationFrame(render);
    };

    render();

    return () => {
      window.removeEventListener("resize", handleResize);
      cancelAnimationFrame(animationFrameId);
    };
  }, []);

  return (
    <div className="absolute inset-0 -z-20 overflow-hidden bg-[#030305]">
      <canvas ref={canvasRef} className="h-full w-full opacity-90 filter blur-[50px] contrast-[115%]" />
    </div>
  );
}
