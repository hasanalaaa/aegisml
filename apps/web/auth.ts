import NextAuth from "next-auth"
import GitHub from "next-auth/providers/github"
import Google from "next-auth/providers/google"

export const { handlers, signIn, signOut, auth } = NextAuth({
  providers: [
    GitHub({
      clientId: process.env.GITHUB_CLIENT_ID,
      clientSecret: process.env.GITHUB_CLIENT_SECRET,
    }),
    Google({
      clientId: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    })
  ],
  callbacks: {
    async jwt({ token, account, user }) {
      if (account && user) {
        try {
          // Point to backend auth/sync endpoint
          const baseUrl = process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000/api/v1";
          const apiUrl = baseUrl.replace("/api/v1", "/auth/sync");
          const res = await fetch(apiUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              email: user.email,
              name: user.name || "",
              image: user.image || "",
              provider: account.provider,
              providerAccountId: account.providerAccountId
            })
          })
          if (res.ok) {
            const data = await res.json()
            token.backendToken = data.access_token
          }
        } catch (error) {
          console.error("Failed to sync auth with backend", error)
        }
      }
      return token
    },
    async session({ session, token }) {
      // @ts-ignore
      session.backendToken = token.backendToken
      return session
    }
  }
})
