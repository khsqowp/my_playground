import NextAuth from "next-auth";
import CredentialsProvider from "next-auth/providers/credentials";
import { CredentialsSignin } from "next-auth";
import bcrypt from "bcryptjs";
import prisma from "@/lib/prisma";

class PendingApprovalError extends CredentialsSignin {
  code = "pending_approval";
}

class RejectedAccountError extends CredentialsSignin {
  code = "rejected_account";
}

export const { handlers, auth, signIn, signOut } = NextAuth({
  providers: [
    CredentialsProvider({
      name: "Credentials",
      credentials: {
        email: { label: "Email", type: "email" },
        password: { label: "Password", type: "password" },
      },
      async authorize(credentials) {
        if (!credentials?.email || !credentials?.password) {
          return null;
        }

        const email = (credentials.email as string).toLowerCase().trim();

        // findFirst with insensitive mode for case-insensitive email matching
        const user = await prisma.user.findFirst({
          where: { email: { equals: email, mode: "insensitive" } },
        });

        if (!user) {
          console.log(`[AUTH] Login failed: User not found (${email})`);
          return null;
        }

        const isPasswordValid = await bcrypt.compare(
          credentials.password as string,
          user.password
        );

        if (!isPasswordValid) {
          console.log(`[AUTH] Login failed: Invalid password for ${email}`);
          return null;
        }

        console.log(`[AUTH] User found: ${email}, Status: ${user.status}`);

        // 승인 대기 또는 거절 상태인 경우 로그인 차단
        if (user.status === "PENDING") {
          console.log(`[AUTH] Login blocked: Status is PENDING for ${email}`);
          throw new PendingApprovalError();
        }
        if (user.status !== "APPROVED") {
          console.log(`[AUTH] Login blocked: Status is ${user.status} (not APPROVED) for ${email}`);
          throw new RejectedAccountError();
        }

        return {
          id: user.id,
          email: user.email,
          name: user.name,
          role: user.role,
          permissions: user.permissions,
        };
      },
    }),
  ],
  callbacks: {
    async jwt({ token, user }) {
      if (user) {
        token.id = user.id ?? "";
        token.role = (user as any).role;
        token.permissions = (user as any).permissions;
      }
      return token;
    },
    async session({ session, token }) {
      if (session.user) {
        (session.user as any).id = token.id as string;
        (session.user as any).role = token.role as string;
        (session.user as any).permissions = token.permissions;
      }
      return session;
    },
  },
  pages: {
    signIn: "/login",
  },
  session: {
    strategy: "jwt",
  },
  secret: process.env.NEXTAUTH_SECRET || process.env.AUTH_SECRET,
});
