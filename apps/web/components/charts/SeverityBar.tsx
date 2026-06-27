"use client";
import React from "react";
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell } from "recharts";

interface SeverityBarProps {
  data: { name: string; count: number; fill: string }[];
  lang: "ar" | "en";
}

export default function SeverityBar({ data, lang }: SeverityBarProps) {
  if (!data || data.length === 0) {
    return (
      <div style={{ height: 300, display: "flex", alignItems: "center", justifyContent: "center", color: "#71717A" }}>
        {lang === "ar" ? "لا توجد بيانات متاحة" : "No data available"}
      </div>
    );
  }

  return (
    <ResponsiveContainer width="100%" height={300}>
      <BarChart data={data} margin={{ top: 20, right: 30, left: 0, bottom: 0 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="#232326" vertical={false} />
        <XAxis dataKey="name" stroke="#71717A" fontSize={11} tickMargin={10} axisLine={false} tickLine={false} />
        <YAxis stroke="#71717A" fontSize={12} tickMargin={10} axisLine={false} tickLine={false} />
        <Tooltip 
          cursor={{ fill: "#1A1A2E" }}
          contentStyle={{ background: "#12121E", border: "1px solid #2A2A3E", borderRadius: 8, color: "#D1D1D1" }}
          itemStyle={{ fontSize: 13, fontWeight: "bold" }}
        />
        <Bar dataKey="count" radius={[6, 6, 0, 0]}>
          {data.map((entry, index) => (
            <Cell key={`cell-${index}`} fill={entry.fill} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}
