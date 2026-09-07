"use client";

import { useEffect, useRef, useState } from "react";
import Link from "next/link";

// Konversify SSO handoff: the shell opens /sso#t=<jwt> and this page exchanges
// the token for a cal.diy session. The token lives in the URL fragment only
// and is stripped from the URL/history as soon as it is read — it is never
// placed in a query string, a log, or the console.
export function SsoHandoff() {
  const [failed, setFailed] = useState(false);
  const started = useRef(false);

  useEffect(() => {
    if (started.current) {
      return;
    }
    started.current = true;

    const exchangeToken = async () => {
      const token = new URLSearchParams(
        window.location.hash.replace(/^#/, "")
      ).get("t");

      if (!token) {
        setFailed(true);
        return;
      }

      window.history.replaceState(null, "", window.location.pathname);

      const request = await fetch("/api/konversify/sso", {
        method: "POST",
        credentials: "include",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
        },
        body: JSON.stringify({ token }),
      });

      if (request.status === 200) {
        window.location.replace("/");
        return;
      }

      setFailed(true);
    };

    exchangeToken().catch((err) => {
      console.error("sso token exchange failed", err);
      setFailed(true);
    });
  }, []);

  return (
    <div className="flex min-h-screen w-full flex-col items-center justify-center bg-neutral-100 p-6 text-neutral-900 dark:bg-neutral-900 dark:text-white">
      {failed ? (
        <div className="flex max-w-md flex-col items-center gap-4 text-center">
          <h1 className="text-2xl font-medium">
            Sign-in link is invalid or expired
          </h1>
          <p className="text-sm text-neutral-500 dark:text-neutral-400">
            Please go back to Konversify and open the tool again, or sign in
            with your email and password.
          </p>
          <Link href="/auth/login" className="font-medium underline">
            Sign in
          </Link>
        </div>
      ) : (
        <h1 className="text-lg font-medium">Signing you in…</h1>
      )}
    </div>
  );
}
