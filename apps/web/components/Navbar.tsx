import Link from "next/link"
import AuthButton from "./AuthButton"

export default function Navbar() {
  return (
    <nav className="sticky top-0 z-50 w-full border-b border-[#232326] bg-[#0B0B0C]/80 backdrop-blur-md">
      <div className="container mx-auto px-4 h-16 flex items-center justify-between">
        <div className="flex items-center gap-6">
          <Link href="/" className="flex items-center gap-2">
            <div className="w-8 h-8 rounded-md bg-[#D4AF37] flex items-center justify-center">
              <svg className="w-5 h-5 text-slate-950" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
              </svg>
            </div>
            <span className="text-xl font-bold bg-gradient-to-r from-[#E5D08F] to-[#D4AF37] bg-clip-text text-transparent">AegisML</span>
          </Link>
          
          <div className="hidden md:flex items-center gap-4">
            <Link href="/scan" className="text-sm font-medium text-gray-300 hover:text-[#C5A880] transition">Scan Model</Link>
            <Link href="/threats" className="text-sm font-medium text-gray-300 hover:text-[#C5A880] transition">Threat Patterns</Link>
            <Link href="/compare" className="text-sm font-medium text-gray-300 hover:text-[#C5A880] transition">Compare</Link>
          </div>
        </div>

        <div className="flex items-center gap-4">
          <AuthButton />
        </div>
      </div>
    </nav>
  )
}
