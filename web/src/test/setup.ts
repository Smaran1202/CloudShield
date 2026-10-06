import "@testing-library/jest-dom/vitest";
import { cleanup } from "@testing-library/react";
import { afterEach, beforeEach } from "vitest";
import { config } from "../config";
import { assertNoUnmockedRequests, resetApiMock } from "./mockApi";

beforeEach(() => {
  config.scanPollMs = 5;
  config.healthPollMs = 60_000;
  resetApiMock();
  document.documentElement.classList.remove("dark");
  window.localStorage.clear();
});

afterEach(() => {
  cleanup();
  assertNoUnmockedRequests();
});
