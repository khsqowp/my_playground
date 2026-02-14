"use client";

import { signIn } from "next-auth/react";
import { useRouter } from "next/navigation";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Bike, UserCircle } from "lucide-react";

export default function GuestPage() {
  const router = useRouter();

  async function handleGuestAccess() {
    const result = await signIn("credentials", {
      email: "guest@88motorcycle.com",
      password: "guest",
      redirect: false,
    });

    if (result?.ok) {
      router.push("/dashboard");
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-background p-4">
      <Card className="w-full max-w-md">
        <CardHeader className="text-center">
          <div className="flex justify-center mb-4">
            <Bike className="h-12 w-12" />
          </div>
          <CardTitle className="text-2xl">Guest Access</CardTitle>
          <CardDescription>
            Browse with limited access. Some features may be restricted.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <Button onClick={handleGuestAccess} className="w-full" variant="outline">
            <UserCircle className="mr-2 h-4 w-4" />
            Continue as Guest
          </Button>
          <Button onClick={() => router.push("/login")} className="w-full">
            Sign In
          </Button>
        </CardContent>
      </Card>
    </div>
  );
}
