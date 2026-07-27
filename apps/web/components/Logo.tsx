// components/Logo.tsx
export function Logo({ size = 40 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 80 80" fill="none" xmlns="http://www.w3.org/2000/svg">
      <defs>
        <linearGradient id="goldGrad" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stopColor="#6B4E10"/>
          <stop offset="50%" stopColor="#C9A84C"/>
          <stop offset="100%" stopColor="#FFD97D"/>
        </linearGradient>
        <linearGradient id="goldGrad2" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stopColor="#C9A84C"/>
          <stop offset="100%" stopColor="#E4C46B"/>
        </linearGradient>
        <filter id="glow">
          <feGaussianBlur stdDeviation="2" result="coloredBlur"/>
          <feMerge><feMergeNode in="coloredBlur"/><feMergeNode in="SourceGraphic"/></feMerge>
        </filter>
      </defs>
      {/* Outer hexagon */}
      <polygon
        points="40,4 72,22 72,58 40,76 8,58 8,22"
        fill="none" stroke="url(#goldGrad)" strokeWidth="2"
        filter="url(#glow)"
      />
      {/* Inner hexagon */}
      <polygon
        points="40,14 64,28 64,52 40,66 16,52 16,28"
        fill="none" stroke="url(#goldGrad2)" strokeWidth="1" opacity="0.5"
      />
      {/* Circuit lines */}
      <line x1="40" y1="4" x2="40" y2="18" stroke="url(#goldGrad)" strokeWidth="1.5" opacity="0.6"/>
      <line x1="72" y1="22" x2="62" y2="28" stroke="url(#goldGrad)" strokeWidth="1.5" opacity="0.6"/>
      <line x1="72" y1="58" x2="62" y2="52" stroke="url(#goldGrad)" strokeWidth="1.5" opacity="0.6"/>
      <line x1="40" y1="76" x2="40" y2="62" stroke="url(#goldGrad)" strokeWidth="1.5" opacity="0.6"/>
      <line x1="8" y1="58" x2="18" y2="52" stroke="url(#goldGrad)" strokeWidth="1.5" opacity="0.6"/>
      <line x1="8" y1="22" x2="18" y2="28" stroke="url(#goldGrad)" strokeWidth="1.5" opacity="0.6"/>
      {/* Center "A" shape */}
      <path
        d="M40 22 L52 54 L46 54 L40 36 L34 54 L28 54 Z M34 44 L46 44 L46 48 L34 48 Z"
        fill="url(#goldGrad)" filter="url(#glow)"
      />
      {/* Corner dots */}
      <circle cx="40" cy="11" r="2" fill="#C9A84C" opacity="0.8"/>
      <circle cx="67" cy="26.5" r="2" fill="#C9A84C" opacity="0.8"/>
      <circle cx="67" cy="53.5" r="2" fill="#C9A84C" opacity="0.8"/>
      <circle cx="40" cy="69" r="2" fill="#C9A84C" opacity="0.8"/>
      <circle cx="13" cy="53.5" r="2" fill="#C9A84C" opacity="0.8"/>
      <circle cx="13" cy="26.5" r="2" fill="#C9A84C" opacity="0.8"/>
    </svg>
  )
}

export function LogoFull({ className }: { className?: string }) {
  return (
    <div className={`flex items-center gap-3 ${className}`}>
      <Logo size={36}/>
      <span style={{
        fontFamily: "var(--font-sora)",
        fontWeight: 700,
        fontSize: "1.4rem",
        letterSpacing: "-0.02em",
        background: "linear-gradient(90deg, #C9A84C, #FFD97D, #C9A84C)",
        backgroundSize: "200% auto",
        WebkitBackgroundClip: "text",
        WebkitTextFillColor: "transparent",
        backgroundClip: "text",
        animation: "shimmer 3s linear infinite"
      }}>
        AegisML
      </span>
    </div>
  )
}
