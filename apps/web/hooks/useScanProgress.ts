"use client";

import { useEffect, useState } from "react";

export type ScanStage = "uploading" | "downloading" | "header_check" | "signature_scan" | "ai_analysis" | "complete" | "error";

export interface ScanProgressData {
  stage: ScanStage;
  progress: number;
  message: string;
  threat_count: number;
  timestamp: string;
}

export function useScanProgress(scanId: string | null) {
  const [data, setData] = useState<ScanProgressData | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!scanId) return;

    let ws: WebSocket | null = null;
    let es: EventSource | null = null;
    let isSubscribed = true;

    const connectWS = () => {
      const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
      const apiUrl = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";
      const host = apiUrl.replace(/^https?:\/\//, "");
      
      ws = new WebSocket(`${protocol}//${host}/ws/scan/${scanId}`);

      ws.onmessage = (event) => {
        if (!isSubscribed) return;
        try {
          const parsed = JSON.parse(event.data);
          setData(parsed);
          if (parsed.stage === "complete" || parsed.stage === "error") {
            ws?.close();
          }
        } catch (e) {
          console.error("Invalid WS message", e);
        }
      };

      ws.onerror = () => {
        if (!isSubscribed) return;
        console.warn("WebSocket failed, falling back to SSE...");
        ws?.close();
        connectSSE();
      };
    };

    const connectSSE = () => {
      const apiUrl = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";
      es = new EventSource(`${apiUrl}/api/v1/scan/${scanId}/stream`);

      es.onmessage = (event) => {
        if (!isSubscribed) return;
        try {
          const parsed = JSON.parse(event.data);
          setData(parsed);
          if (parsed.stage === "complete" || parsed.stage === "error") {
            es?.close();
          }
        } catch (e) {
          console.error("Invalid SSE message", e);
        }
      };

      es.onerror = (err) => {
        if (!isSubscribed) return;
        console.error("SSE failed", err);
        setError("Failed to connect to real-time engine.");
        es?.close();
      };
    };

    connectWS();

    return () => {
      isSubscribed = false;
      if (ws) ws.close();
      if (es) es.close();
    };
  }, [scanId]);

  return { data, error };
}
