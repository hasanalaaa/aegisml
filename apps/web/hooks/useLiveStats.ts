"use client";

import { useEffect, useState } from "react";

export interface LiveStatsData {
  totalScans: number;
  threatsFound: number;
  activeScans: number;
}

export function useLiveStats() {
  const [stats, setStats] = useState<LiveStatsData | null>(null);

  useEffect(() => {
    let ws: WebSocket | null = null;
    let isSubscribed = true;

    const connectWS = () => {
      const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
      const apiUrl = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";
      const host = apiUrl.replace(/^https?:\/\//, "");
      
      ws = new WebSocket(`${protocol}//${host}/ws/stats`);

      ws.onmessage = (event) => {
        if (!isSubscribed) return;
        try {
          const parsed = JSON.parse(event.data);
          setStats(parsed);
        } catch (e) {
          console.error("Invalid WS stats message", e);
        }
      };

      ws.onerror = (e) => {
        console.warn("LiveStats WS error", e);
      };
      
      ws.onclose = () => {
        if (isSubscribed) {
          setTimeout(connectWS, 5000); // Reconnect loop
        }
      };
    };

    connectWS();

    return () => {
      isSubscribed = false;
      if (ws) ws.close();
    };
  }, []);

  return stats;
}
