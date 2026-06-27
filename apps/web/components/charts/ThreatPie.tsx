"use client";
import React from "react";
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer, Legend } from "recharts";

interface ThreatPieProps {
  data: { name: string; value: number }[];
  lang: "ar" | "en";
}

const COLORS = ["#E74C3C", "#E67E22", "#F1C40F", "#9B59B6", "#3498DB", "#1ABC9C"];

export default function ThreatPie({ data, lang }: ThreatPieProps) {
  if (!data || data.length === 0) {
    return (
      <div style={{ height: 300, display: "flex", alignItems: "center", justifyContent: "center", color: "#71717A" }}>
        {lang === "ar" ? "لا توجد بيانات متاحة" : "No data available"}
      </div>
    );
  }

  return (
    <ResponsiveContainer width="100%" height={300}>
      <PieChart>
        <Pie
          data={data}
          cx="50%"
          cy="50%"
          innerRadius={60}
          outerRadius={100}
          paddingAngle={5}
          dataKey="value"
          stroke="none"
        >
          {data.map((entry, index) => (
            <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
          ))}
        </Pie>
        <Tooltip 
          contentStyle={{ background: "#12121E", border: "1px solid #2A2A3E", borderRadius: 8, color: "#D1D1D1" }}
          itemStyle={{ fontSize: 13, fontWeight: "bold" }}
        />
        <Legend verticalAlign="bottom" height={36} iconType="circle" wrapperStyle={{ fontSize: 12, color: "#A8A8C4" }} />
      </PieChart>
    </ResponsiveContainer>
  );
}
