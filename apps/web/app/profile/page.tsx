import { auth } from "@/auth"
import { redirect } from "next/navigation"

export default async function ProfilePage() {
  const session = await auth()

  if (!session || !session.user) {
    redirect("/")
  }

  return (
    <div className="container mx-auto px-4 py-12 max-w-4xl text-slate-200">
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-8 mb-8">
        <div className="flex items-center gap-6 mb-8">
          {session.user.image ? (
            <img src={session.user.image} alt="Avatar" className="w-20 h-20 rounded-full border-2 border-amber-500" />
          ) : (
            <div className="w-20 h-20 rounded-full bg-slate-800 flex items-center justify-center border-2 border-amber-500">
              <span className="text-amber-500 text-3xl font-bold">{session.user.name?.[0] || session.user.email?.[0] || "U"}</span>
            </div>
          )}
          <div>
            <h1 className="text-3xl font-bold text-white mb-2">{session.user.name || session.user.email}</h1>
            <p className="text-slate-400">{session.user.email}</p>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div className="bg-slate-950 p-6 rounded-lg border border-slate-800">
            <h2 className="text-lg font-semibold text-amber-500 mb-2">Account Plan</h2>
            <p className="text-2xl font-bold text-white uppercase mb-1">Free Tier</p>
            <p className="text-sm text-slate-400 mb-4">Max file size: 200 MB</p>
            <button className="bg-amber-600 hover:bg-amber-500 text-slate-950 font-bold py-2 px-4 rounded transition w-full">
              Upgrade to Pro
            </button>
          </div>

          <div className="bg-slate-950 p-6 rounded-lg border border-slate-800">
            <h2 className="text-lg font-semibold text-amber-500 mb-2">API Key</h2>
            <p className="text-sm text-slate-400 mb-4">Use this key to authenticate with the AegisML CLI.</p>
            <div className="flex gap-2">
              <input 
                type="password" 
                readOnly 
                value="sk_test_..." 
                className="bg-slate-900 border border-slate-700 text-slate-300 rounded px-3 py-2 w-full font-mono text-sm"
              />
              <button className="bg-slate-800 hover:bg-slate-700 text-slate-300 px-4 py-2 rounded transition border border-slate-700">
                Reveal
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
