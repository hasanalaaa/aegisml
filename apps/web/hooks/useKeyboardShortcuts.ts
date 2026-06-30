"use client"
import { useEffect, useState } from "react"
import { useRouter } from "next/navigation"

export function useKeyboardShortcuts() {
  const router = useRouter()
  const [isModalOpen, setIsModalOpen] = useState(false)

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      // Ignore if typing in input/textarea
      if (
        document.activeElement?.tagName === "INPUT" ||
        document.activeElement?.tagName === "TEXTAREA"
      ) {
        return
      }

      switch (e.key.toLowerCase()) {
        case "k":
          e.preventDefault()
          router.push("/")
          break
        case "d":
          e.preventDefault()
          router.push("/dashboard")
          break
        case "t":
          e.preventDefault()
          router.push("/threats")
          break
        case "m":
          e.preventDefault()
          router.push("/monitor")
          break
        case "?":
          e.preventDefault()
          setIsModalOpen(true)
          break
      }
    }

    window.addEventListener("keydown", handleKeyDown)
    return () => window.removeEventListener("keydown", handleKeyDown)
  }, [router])

  return { isModalOpen, setIsModalOpen }
}
