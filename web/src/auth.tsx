import {
  createContext,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import { api, setUnauthorizedHandler, type Role } from "./api";

export const VIEWING_ONLY = "Viewing only";

// "unknown" is before the API has answered. The app is shown then, because the API refuses what
// a visitor may not do anyway, and any 401 sends them to the login page.
type AuthState =
  | { status: "unknown" }
  | { status: "in"; role: Role; enabled: boolean }
  | { status: "out" };

interface AuthValue {
  state: AuthState;
  role: Role;
  // True when the login is turned on, so the header shows who is logged in.
  enabled: boolean;
  logIn: (role: Role, password: string) => Promise<void>;
  logOut: () => Promise<void>;
}

// Used where there is no provider: the same as the login being off.
const AuthContext = createContext<AuthValue>({
  state: { status: "unknown" },
  role: "owner",
  enabled: false,
  logIn: async () => {},
  logOut: async () => {},
});

export function AuthProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<AuthState>({ status: "unknown" });

  useEffect(() => {
    let current = true;
    setUnauthorizedHandler(() => setState({ status: "out" }));
    api.me().then(
      (me) => {
        // A 401 from any request, which may have come first, is the stronger answer.
        const known = { status: "in", role: me.role, enabled: me.auth_enabled } as const;
        if (current) setState((now) => (now.status === "out" ? now : known));
      },
      // A 401 has already been handled. Any other failure leaves the state as it is.
      () => {},
    );
    return () => {
      current = false;
      setUnauthorizedHandler(null);
    };
  }, []);

  const value = useMemo<AuthValue>(
    () => ({
      state,
      role: state.status === "in" ? state.role : "owner",
      enabled: state.status === "in" && state.enabled,
      logIn: async (role, password) => {
        const me = await api.login(role, password);
        setState({ status: "in", role: me.role, enabled: me.auth_enabled });
      },
      logOut: async () => {
        await api.logout();
        setState({ status: "out" });
      },
    }),
    [state],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthValue {
  return useContext(AuthContext);
}

// For a control that changes something. A viewer sees it disabled, with the reason as a tooltip.
export function useLock(): { disabled: boolean; title: string | undefined } {
  const { role } = useAuth();
  return role === "viewer"
    ? { disabled: true, title: VIEWING_ONLY }
    : { disabled: false, title: undefined };
}
