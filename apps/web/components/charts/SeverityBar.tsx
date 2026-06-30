"use client";
import React from "react";
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from "recharts";

const data = [
  { name: "Critical", count: 120 },
  { name: "High", count: 210 },
  { name: "Medium", count: 180 },
  { name: "Low", count: 350 },
];

export default function SeverityBar() {
  return (
    <div className="h-64 w-full">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart
          data={data}
          margin={{ top: 10, right: 10, left: -20, bottom: 0 }}
        >
          <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" vertical={false} />
          <XAxis dataKey="name" stroke="#A8A8C4" fontSize={12} tickLine={false} axisLine={false} />
          <YAxis stroke="#A8A8C4" fontSize={12} tickLine={false} axisLine={false} />
          <Tooltip 
            cursor={{ fill: "rgba(255,255,255,0.02)" }}
            contentStyle={{ 
              backgroundColor: "rgba(10, 10, 15, 0.9)", 
              border: "1px solid rgba(201, 168, 76, 0.2)",
              borderRadius: "8px",
              color: "#F0F0F8"
            }}
          />
          <Bar dataKey="count" fill="#C9A84C" radius={[4, 4, 0, 0]} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
