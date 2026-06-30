"use client";
import { useEffect } from "react";

export function useSmoothScroll() {
  useEffect(() => {
    let lenis: any;
    
    async function initLenis() {
      const Lenis = (await import("lenis")).default;
      lenis = new Lenis({
        duration: 1.4,
        easing: (t: number) => Math.min(1, 1.001 - Math.pow(2, -10 * t)),
      });

      function raf(time: number) {
        lenis.raf(time);
        requestAnimationFrame(raf);
      }
      requestAnimationFrame(raf);
    }

    initLenis();
    return () => lenis?.destroy();
  }, []);
}
