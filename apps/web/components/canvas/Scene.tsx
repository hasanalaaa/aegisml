"use client";
import { Canvas } from "@react-three/fiber";
import { Environment, Stars } from "@react-three/drei";
import { Suspense } from "react";

export default function Scene({ children }: { children?: React.ReactNode }) {
  return (
    <div
      style={{
        position: "fixed",
        top: 0,
        left: 0,
        width: "100vw",
        height: "100vh",
        zIndex: 0,
        backgroundColor: "#0A0A0F",
        pointerEvents: "none",
      }}
    >
      <Canvas
        camera={{ position: [0, 0, 6], fov: 60 }}
        gl={{ antialias: true, alpha: true }}
        dpr={[1, 2]}
      >
        <Suspense fallback={null}>
          <ambientLight intensity={0.15} color="#1a1a2e" />
          <pointLight position={[5, 5, 5]} color="#C9A84C" intensity={3} />
          <pointLight position={[-5, -3, -5]} color="#4a3f8c" intensity={1.5} />
          <Stars radius={80} depth={50} count={3000} factor={4} saturation={0} fade speed={0.5} />
          <Environment preset="night" />
          {children}
        </Suspense>
      </Canvas>
    </div>
  );
}
