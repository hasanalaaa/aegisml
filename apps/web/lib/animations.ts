export const fadeUpVariants = {
  hidden: { opacity: 0, y: 30 },
  visible: (i = 0) => ({
    opacity: 1, y: 0,
    transition: { duration: 0.6, delay: i * 0.1, ease: [0.22, 1, 0.36, 1] as [number, number, number, number] }
  })
}

export const fadeInVariants = {
  hidden: { opacity: 0 },
  visible: { opacity: 1, transition: { duration: 0.5 } }
}

export const scaleInVariants = {
  hidden: { opacity: 0, scale: 0.90 },
  visible: { opacity: 1, scale: 1, transition: { duration: 0.5, ease: [0.22, 1, 0.36, 1] as [number, number, number, number] } }
}

export const cardHoverVariants = {
  rest: { scale: 1, rotateX: 0, rotateY: 0 },
  hover: { scale: 1.02, transition: { duration: 0.3, ease: "easeOut" } }
}

export const staggerContainer = {
  hidden: {},
  visible: { transition: { staggerChildren: 0.1, delayChildren: 0.2 } }
}

// Editorial blur-up reveal — the Vercel/Linear mount signature.
export const blurUpVariants = {
  hidden: { opacity: 0, y: 24, filter: "blur(8px)" },
  visible: (i = 0) => ({
    opacity: 1, y: 0, filter: "blur(0px)",
    transition: { duration: 0.7, delay: i * 0.08, ease: [0.22, 1, 0.36, 1] as [number, number, number, number] }
  })
}

// Tight cascade for dense lists (threat rows, stat grids).
export const cascadeContainer = {
  hidden: {},
  visible: { transition: { staggerChildren: 0.06, delayChildren: 0.1 } }
}

export const cascadeItem = {
  hidden: { opacity: 0, y: 16, scale: 0.98 },
  visible: {
    opacity: 1, y: 0, scale: 1,
    transition: { duration: 0.5, ease: [0.22, 1, 0.36, 1] as [number, number, number, number] }
  }
}

// Shared spring for tactile micro-interactions (buttons, chips, steppers).
export const tactileSpring = { type: "spring" as const, stiffness: 400, damping: 28 }

export const glowPulse = {
  initial: { boxShadow: "0 0 0px rgba(201,168,76,0)" },
  animate: {
    boxShadow: ["0 0 20px rgba(201,168,76,0.1)", "0 0 40px rgba(201,168,76,0.25)", "0 0 20px rgba(201,168,76,0.1)"],
    transition: { duration: 3, repeat: Infinity, ease: "easeInOut" }
  }
}

// Tab/page-level shell used with <AnimatePresence mode="wait"> — blur-up in,
// blur-down out, staggering direct children that carry their own variants.
export const tabVariants = {
  hidden: { opacity: 0, y: 18, filter: "blur(8px)" },
  visible: {
    opacity: 1, y: 0, filter: "blur(0px)",
    transition: { duration: 0.5, ease: [0.22, 1, 0.36, 1] as [number, number, number, number], staggerChildren: 0.08, delayChildren: 0.05 }
  },
  exit: {
    opacity: 0, y: -14, filter: "blur(6px)",
    transition: { duration: 0.28, ease: "easeIn" as const }
  }
}

// Child of tabVariants — cinematic rise with a whisper of scale.
export const riseItem = {
  hidden: { opacity: 0, y: 24, scale: 0.985 },
  visible: {
    opacity: 1, y: 0, scale: 1,
    transition: { duration: 0.6, ease: [0.22, 1, 0.36, 1] as [number, number, number, number] }
  }
}

// Continuous ambient gold breathing for hero surfaces (infinite, subtle).
export const ambientGoldPulse = {
  animate: {
    boxShadow: [
      "0 0 0 1px rgba(212,175,55,0.16), 0 0 28px rgba(212,175,55,0.08)",
      "0 0 0 1px rgba(212,175,55,0.30), 0 0 52px rgba(212,175,55,0.18)",
      "0 0 0 1px rgba(212,175,55,0.16), 0 0 28px rgba(212,175,55,0.08)",
    ],
    transition: { duration: 4, repeat: Infinity, ease: "easeInOut" }
  }
}
