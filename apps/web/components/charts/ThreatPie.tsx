"use client";
import React from "react";
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip, Legend } from "recharts";

const data = [
  { name: "OS Command Injection", value: 400 },
  { name: "Deserialization", value: 300 },
  { name: "Network Access", value: 300 },
  { name: "File Write", value: 200 },
];

const COLORS = ["#EA4335", "#C9A84C", "#A8A8C4", "#262626"];

export default function ThreatPie() {
  return (
    <div className="h-64 w-full">
      <ResponsiveContainer width="100%" height="100%">
        <PieChart>
          <Pie
            data={data}
            cx="50%"
            cy="50%"
            innerRadius={60}
            outerRadius={80}
            paddingAngle={5}
            dataKey="value"
            stroke="none"
          >
            {data.map((entry, index) => (
              <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
            ))}
          </Pie>
          <Tooltip 
            contentStyle={{ 
              backgroundColor: "rgba(10, 10, 15, 0.9)", 
              border: "1px solid rgba(201, 168, 76, 0.2)",
              borderRadius: "8px",
              color: "#F0F0F8"
            }} 
            itemStyle={{ color: "#C9A84C" }}
          />
          <Legend verticalAlign="bottom" height={36} wrapperStyle={{ fontSize: "12px", color: "#A8A8C4" }}/>
        </PieChart>
      </ResponsiveContainer>
    </div>
  );
}
