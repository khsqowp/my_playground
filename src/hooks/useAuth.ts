import { useSession } from "next-auth/react";

export function useAuth() {
  const { data: session, status } = useSession();

  return {
    user: session?.user,
    isLoading: status === "loading",
    isAuthenticated: status === "authenticated",
    isOwner: session?.user?.role === "OWNER",
    isAdmin: session?.user?.role === "ADMIN" || session?.user?.role === "OWNER",
  };
}
