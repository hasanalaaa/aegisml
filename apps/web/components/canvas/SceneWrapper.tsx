"use client";
import dynamic from "next/dynamic";
import React from "react";

const Scene = dynamic(() => import("./Scene"), { ssr: false });

export default function SceneWrapper() {
  return <Scene />;
}
