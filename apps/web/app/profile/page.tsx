import { auth } from "@/auth"
import { redirect } from "next/navigation"

export default async function ProfilePage() {
  const session = await auth()

  if (!session || !session.user) {
    redirect("/")
  }

  return (
    <div className="container mx-auto px-4 py-12 max-w-4xl text-gray-100">
      <div className="bg-[#121214] border border-[#232326] rounded-xl p-8 mb-8">
        <div className="flex items-center gap-6 mb-8">
          {session.user.image ? (
            <img src={session.user.image} alt="Avatar" className="w-20 h-20 rounded-full border-2 border-[#D4AF37]" />
          ) : (
            <div className="w-20 h-20 rounded-full bg-[#161618] flex items-center justify-center border-2 border-[#D4AF37]">
              <span className="text-[#D4AF37] text-3xl font-bold">{session.user.name?.[0] || session.user.email?.[0] || "U"}</span>
            </div>
          )}
          <div>
            <h1 className="text-3xl font-bold text-white mb-2">{session.user.name || session.user.email}</h1>
            <p className="text-gray-400">{session.user.email}</p>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div className="bg-[#0B0B0C] p-6 rounded-lg border border-[#232326]">
            <h2 className="text-lg font-semibold text-[#D4AF37] mb-2">Account Plan</h2>
            <p className="text-2xl font-bold text-white uppercase mb-1">Free Tier</p>
            <p className="text-sm text-gray-400 mb-4">Max file size: 200 MB</p>
            <button className="bg-amber-600 hover:bg-[#D4AF37] text-slate-950 font-bold py-2 px-4 rounded transition w-full">
              Upgrade to Pro
            </button>
          </div>

          <div className="bg-[#0B0B0C] p-6 rounded-lg border border-[#232326]">
            <h2 className="text-lg font-semibold text-[#D4AF37] mb-2">API Key</h2>
            <p className="text-sm text-gray-400 mb-4">Use this key to authenticate with the AegisML CLI.</p>
            <div className="flex gap-2">
              <input 
                type="password" 
                readOnly 
                value="sk_test_..." 
                className="bg-[#121214] border border-[#262626] text-gray-300 rounded px-3 py-2 w-full font-mono text-sm"
              />
              <button className="bg-[#161618] hover:bg-slate-700 text-gray-300 px-4 py-2 rounded transition border border-[#262626]">
                Reveal
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
