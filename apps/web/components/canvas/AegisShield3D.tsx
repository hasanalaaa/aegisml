"use client";
import { useRef, useMemo } from "react";
import { useFrame, useThree } from "@react-three/fiber";
import { Float, MeshDistortMaterial } from "@react-three/drei";
import * as THREE from "three";

export default function AegisShield3D() {
  const meshRef = useRef<THREE.Mesh>(null);
  const particlesRef = useRef<THREE.Points>(null);
  const { mouse } = useThree();

  // إنشاء 3000 جسيم حول الـ Shield
  const particles = useMemo(() => {
    const count = 3000;
    const positions = new Float32Array(count * 3);
    for (let i = 0; i < count; i++) {
      const theta = Math.random() * Math.PI * 2;
      const phi = Math.random() * Math.PI;
      const r = 1.5 + Math.random() * 2.5;
      positions[i * 3] = r * Math.sin(phi) * Math.cos(theta);
      positions[i * 3 + 1] = r * Math.sin(phi) * Math.sin(theta);
      positions[i * 3 + 2] = r * Math.cos(phi);
    }
    return positions;
  }, []);

  useFrame((state) => {
    if (!meshRef.current || !particlesRef.current) return;
    const time = state.clock.elapsedTime;

    // تتبع الماوس
    meshRef.current.rotation.y = THREE.MathUtils.lerp(
      meshRef.current.rotation.y,
      mouse.x * 0.4,
      0.05
    );
    meshRef.current.rotation.x = THREE.MathUtils.lerp(
      meshRef.current.rotation.x,
      -mouse.y * 0.2,
      0.05
    );

    // دوران الـ particles
    particlesRef.current.rotation.y = time * 0.08;
    particlesRef.current.rotation.x = time * 0.04;
  });

  return (
    <group>
      {/* الـ Particles */}
      <points ref={particlesRef}>
        <bufferGeometry>
          <bufferAttribute
            attach="attributes-position"
            args={[particles, 3]}
            count={particles.length / 3}
            array={particles}
            itemSize={3}
          />
        </bufferGeometry>
        <pointsMaterial
          size={0.012}
          color="#C9A84C"
          transparent
          opacity={0.5}
          sizeAttenuation
        />
      </points>

      {/* الـ Shield الرئيسي */}
      <Float speed={1.2} rotationIntensity={0.1} floatIntensity={0.3}>
        <mesh ref={meshRef} scale={1.4}>
          <icosahedronGeometry args={[1, 3]} />
          <MeshDistortMaterial
            color="#0d0d1a"
            emissive="#C9A84C"
            emissiveIntensity={0.15}
            metalness={0.9}
            roughness={0.1}
            distort={0.15}
            speed={1.5}
            wireframe={false}
          />
        </mesh>

        {/* Ring خارجي ذهبي */}
        <mesh rotation={[Math.PI / 2, 0, 0]} scale={1.8}>
          <torusGeometry args={[1, 0.008, 8, 100]} />
          <meshStandardMaterial
            color="#C9A84C"
            emissive="#C9A84C"
            emissiveIntensity={0.8}
            metalness={1}
            roughness={0}
          />
        </mesh>
        <mesh rotation={[0, 0, Math.PI / 3]} scale={1.8}>
          <torusGeometry args={[1, 0.005, 8, 100]} />
          <meshStandardMaterial
            color="#E4C46B"
            emissive="#E4C46B"
            emissiveIntensity={0.5}
            metalness={1}
            roughness={0}
          />
        </mesh>
      </Float>
    </group>
  );
}
