"use client";
import React from "react";
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from "recharts";

interface TrendLineProps {
  data: { date: string; safe: number; threats: number }[];
  lang: "ar" | "en";
}

export default function TrendLine({ data, lang }: TrendLineProps) {
  return (
    <ResponsiveContainer width="100%" height={300}>
      <LineChart data={data} margin={{ top: 20, right: 30, left: 0, bottom: 0 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="#232326" />
        <XAxis dataKey="date" stroke="#71717A" fontSize={12} tickMargin={10} />
        <YAxis stroke="#71717A" fontSize={12} tickMargin={10} />
        <Tooltip 
          contentStyle={{ background: "#12121E", border: "1px solid #2A2A3E", borderRadius: 8, color: "#D1D1D1" }}
          itemStyle={{ fontSize: 13, fontWeight: "bold" }}
          labelStyle={{ color: "#A8A8C4", marginBottom: 8 }}
        />
        <Line 
          type="monotone" 
          dataKey="safe" 
          stroke="#2ECC71" 
          strokeWidth={3} 
          name={lang === "ar" ? "الفحوصات الآمنة" : "Safe Scans"} 
          dot={{ fill: "#2ECC71", r: 4 }} 
          activeDot={{ r: 6 }} 
        />
        <Line 
          type="monotone" 
          dataKey="threats" 
          stroke="#E74C3C" 
          strokeWidth={3} 
          name={lang === "ar" ? "التهديدات" : "Threats"} 
          dot={{ fill: "#E74C3C", r: 4 }} 
          activeDot={{ r: 6 }} 
        />
      </LineChart>
    </ResponsiveContainer>
  );
}
