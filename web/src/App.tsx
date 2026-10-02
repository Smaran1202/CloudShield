import { useEffect, useState } from "react";

const API_URL = import.meta.env.VITE_API_URL ?? "http://localhost:8000";

type Health = { status: string; version: string };

export default function App() {
  const [health, setHealth] = useState<Health | null | "loading">("loading");

  useEffect(() => {
    fetch(`${API_URL}/api/health`)
      .then((res) => (res.ok ? res.json() : Promise.reject(new Error(res.statusText))))
      .then(setHealth)
      .catch(() => setHealth(null));
  }, []);

  let text = "Checking API...";
  if (health === null) text = "API offline";
  else if (health !== "loading") text = `API online (version ${health.version})`;

  return (
    <main className="flex min-h-screen flex-col items-center justify-center gap-2">
      <h1 className="text-3xl font-semibold">CloudShield</h1>
      <p className={health === null ? "text-red-600" : "text-slate-700"}>{text}</p>
    </main>
  );
}
