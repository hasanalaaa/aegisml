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

export const glowPulse = {
  initial: { boxShadow: "0 0 0px rgba(201,168,76,0)" },
  animate: {
    boxShadow: ["0 0 20px rgba(201,168,76,0.1)", "0 0 40px rgba(201,168,76,0.25)", "0 0 20px rgba(201,168,76,0.1)"],
    transition: { duration: 3, repeat: Infinity, ease: "easeInOut" }
  }
}
