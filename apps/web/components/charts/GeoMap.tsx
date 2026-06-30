"use client";
import React, { useEffect } from "react";
import { MapContainer, TileLayer, CircleMarker, Popup } from "react-leaflet";
import "leaflet/dist/leaflet.css";

const threatLocations = [
  { name: "US-East (Virginia)", coords: [38.9072, -77.0369], count: 120 },
  { name: "EU-West (Frankfurt)", coords: [50.1109, 8.6821], count: 85 },
  { name: "AP-East (Tokyo)", coords: [35.6762, 139.6503], count: 45 },
  { name: "SA-East (São Paulo)", coords: [-23.5505, -46.6333], count: 12 },
];

export default function GeoMap() {
  // Leaflet marker icon fix for Next.js SSR
  useEffect(() => {
    import("leaflet").then((L) => {
      delete (L.Icon.Default.prototype as any)._getIconUrl;
      L.Icon.Default.mergeOptions({
        iconRetinaUrl: require("leaflet/dist/images/marker-icon-2x.png").default,
        iconUrl: require("leaflet/dist/images/marker-icon.png").default,
        shadowUrl: require("leaflet/dist/images/marker-shadow.png").default,
      });
    });
  }, []);

  return (
    <div className="h-64 w-full rounded-xl overflow-hidden border border-[#262626]" style={{ zIndex: 0 }}>
      <MapContainer 
        center={[20, 0]} 
        zoom={1.5} 
        style={{ height: "100%", width: "100%", background: "#0A0A0F" }}
        zoomControl={false}
        attributionControl={false}
      >
        <TileLayer
          url="https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png"
        />
        {threatLocations.map((loc, idx) => (
          <CircleMarker
            key={idx}
            center={loc.coords as [number, number]}
            radius={Math.max(5, loc.count / 10)}
            pathOptions={{ color: "#C9A84C", fillColor: "#E4C46B", fillOpacity: 0.6 }}
          >
            <Popup>
              <div style={{ color: "#0A0A0F", fontWeight: "bold" }}>
                {loc.name}<br/>
                Threats: {loc.count}
              </div>
            </Popup>
          </CircleMarker>
        ))}
      </MapContainer>
    </div>
  );
}
