import type { Metadata } from "next";

import { SsoHandoff } from "@components/konversify/SsoHandoff";

export const metadata: Metadata = {
  title: "Signing in",
  description: "",
};

export default function SsoPage() {
  return <SsoHandoff />;
}
