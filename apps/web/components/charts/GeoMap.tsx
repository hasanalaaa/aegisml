"use client";
import React, { useEffect } from "react";
import { MapContainer, TileLayer, CircleMarker, Tooltip } from "react-leaflet";
import "leaflet/dist/leaflet.css";

// Fix Leaflet's default icon path issues with webpack/Next.js
import L from "leaflet";
L.Icon.Default.imagePath = "/images/";

interface GeoMapProps {
  points: { lat: number; lng: number; intensity: number; label: string }[];
}

export default function GeoMap({ points }: GeoMapProps) {
  return (
    <div style={{ height: "100%", width: "100%", borderRadius: 12, overflow: "hidden", border: "1px solid #232326" }}>
      <MapContainer 
        center={[20, 0]} 
        zoom={2} 
        style={{ height: "100%", width: "100%", background: "#0B0B0C" }}
        scrollWheelZoom={false}
      >
        <TileLayer
          url="https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png"
          attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors &copy; <a href="https://carto.com/attributions">CARTO</a>'
        />
        {points.map((pt, i) => (
          <CircleMarker
            key={i}
            center={[pt.lat, pt.lng]}
            radius={Math.max(4, pt.intensity / 5)}
            fillColor="#C9A84C"
            color="#C9A84C"
            weight={1}
            opacity={0.8}
            fillOpacity={0.4}
          >
            <Tooltip 
              direction="top" 
              offset={[0, -10]} 
              opacity={1}
              className="custom-leaflet-tooltip"
            >
              <div style={{ background: "#12121E", color: "#D1D1D1", padding: "4px 8px", borderRadius: 4, fontSize: 12, border: "1px solid #C9A84C44" }}>
                <strong>{pt.label}</strong>: {pt.intensity} scans
              </div>
            </Tooltip>
          </CircleMarker>
        ))}
      </MapContainer>
      <style>{`
        .leaflet-tooltip.custom-leaflet-tooltip {
          background: transparent;
          border: none;
          box-shadow: none;
        }
        .leaflet-tooltip-top.custom-leaflet-tooltip::before {
          border-top-color: #C9A84C44;
        }
      `}</style>
    </div>
  );
}
