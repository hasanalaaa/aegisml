// components/HexGridBackground.tsx
// SVG pattern خلف كل الصفحات — سداسيات شفافة صغيرة
export function HexGridBackground() {
  return (
    <div style={{ position: "absolute", inset: 0, overflow: "hidden", pointerEvents: "none", zIndex: 0 }}>
      <svg width="100%" height="100%" xmlns="http://www.w3.org/2000/svg">
        <defs>
          <pattern id="hexgrid" x="0" y="0" width="60" height="52" patternUnits="userSpaceOnUse">
            <polygon points="30,2 56,16 56,44 30,58 4,44 4,16"
              fill="none" stroke="rgba(201,168,76,0.04)" strokeWidth="1"/>
          </pattern>
        </defs>
        <rect width="100%" height="100%" fill="url(#hexgrid)"/>
      </svg>
      {/* Radial fade */}
      <div style={{
        position: "absolute", inset: 0,
        background: "radial-gradient(ellipse at 60% 50%, transparent 40%, var(--bg-void) 75%)"
      }}/>
    </div>
  )
}
