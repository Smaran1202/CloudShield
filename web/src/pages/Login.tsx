import { useEffect, useRef, useState, type FormEvent } from "react";
import { Navigate, useLocation } from "react-router-dom";
import type { Role } from "../api";
import { useAuth } from "../auth";
import { FIELD, PageTitle, PRIMARY_BUTTON, Spinner } from "../components/ui";
import { messageOf } from "../useAsync";

const ROLES: { role: Role; label: string; hint: string }[] = [
  { role: "owner", label: "Owner", hint: "Can start scans and change things" },
  { role: "viewer", label: "Viewer", hint: "Can only look" },
];

export function Login() {
  const { state, logIn } = useAuth();
  const location = useLocation();
  const [role, setRole] = useState<Role>("owner");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const field = useRef<HTMLInputElement>(null);
  const from = (location.state as { from?: string } | null)?.from ?? "/";

  useEffect(() => field.current?.focus(), []);

  if (state.status === "in") return <Navigate to={from} replace />;

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await logIn(role, password);
    } catch (failure) {
      setError(messageOf(failure));
      setPassword("");
      field.current?.focus();
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="mx-auto w-full max-w-xl px-4 py-16">
      <PageTitle sub="Enter the password for the role you want.">Log in</PageTitle>
      <form
        onSubmit={submit}
        className="rise space-y-6 rounded-lane border-2 border-ink bg-white p-6"
      >
        <fieldset className="space-y-3">
          <legend className="mb-2 text-label font-semibold">Role</legend>
          {ROLES.map((item) => (
            <label key={item.role} className="flex min-h-11 items-center gap-3">
              <input
                type="radio"
                name="role"
                value={item.role}
                checked={role === item.role}
                onChange={() => setRole(item.role)}
              />
              <span>
                <span className="font-semibold">{item.label}</span>
                <span className="block text-secondary text-dim">{item.hint}</span>
              </span>
            </label>
          ))}
        </fieldset>
        <label className="flex flex-col gap-1 text-label font-semibold">
          Password
          <input
            ref={field}
            type="password"
            autoComplete="current-password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            className={FIELD}
          />
        </label>
        {error && (
          <p role="alert" className="text-secondary font-semibold text-red">
            {error}
          </p>
        )}
        <button
          type="submit"
          disabled={busy || password === ""}
          className={`${PRIMARY_BUTTON} inline-flex items-center gap-2`}
        >
          {busy && <Spinner />}
          Log in
        </button>
      </form>
    </main>
  );
}
