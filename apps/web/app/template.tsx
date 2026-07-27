"use client"
import { usePathname } from "next/navigation"
import { AnimatePresence, motion } from "framer-motion"

/**
 * Route-level transition shell. Next.js remounts a template on every
 * navigation, so each page gets a cinematic blur-up entrance under
 * AnimatePresence, plus a gold sweep flash that reveals the new route.
 */
export default function Template({ children }: { children: React.ReactNode }) {
  const pathname = usePathname()
  return (
    <AnimatePresence mode="wait">
      <motion.div
        key={pathname}
        initial={{ opacity: 0, y: 14, filter: "blur(10px)" }}
        animate={{ opacity: 1, y: 0, filter: "blur(0px)" }}
        transition={{ duration: 0.55, ease: [0.22, 1, 0.36, 1] }}
      >
        {/* gold sweep flash on route entry */}
        <motion.div
          aria-hidden
          initial={{ scaleX: 1, opacity: 1 }}
          animate={{ scaleX: 0, opacity: 0 }}
          transition={{ duration: 0.7, ease: [0.22, 1, 0.36, 1] }}
          style={{
            position: "fixed", inset: 0, zIndex: 9999, pointerEvents: "none",
            transformOrigin: "left",
            background: "linear-gradient(90deg, #000 0%, rgba(212,175,55,0.05) 60%, transparent 100%)",
          }}
        />
        {children}
      </motion.div>
    </AnimatePresence>
  )
}
