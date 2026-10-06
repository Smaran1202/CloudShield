import { render } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, useLocation } from "react-router-dom";
import App from "../App";
import { mockApi } from "./mockApi";

// The header asks for the scans on every page, so there is always an answer for it.
export const BASE = {
  "GET /api/health": { status: "ok", version: "1.2.3" },
  "GET /api/scans": [],
};

export const never = () => new Promise(() => {});

// Shows the address, so tests can check what ends up in the URL.
function LocationProbe() {
  const location = useLocation();
  return <output data-testid="location">{location.pathname + location.search}</output>;
}

// Renders the whole app (header included) at `path`, with fetch answering from `routes`.
export function renderApp(path: string, routes: Record<string, unknown> = {}) {
  mockApi({ ...BASE, ...routes });
  const user = userEvent.setup();
  render(
    <MemoryRouter
      initialEntries={[path]}
      future={{ v7_startTransition: true, v7_relativeSplatPath: true }}
    >
      <App />
      <LocationProbe />
    </MemoryRouter>,
  );
  return user;
}
