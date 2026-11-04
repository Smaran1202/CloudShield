import { Navigate, Route, Routes, useLocation } from "react-router-dom";
import { AuthProvider, useAuth } from "./auth";
import { Layout } from "./components/Layout";
import { EmptyState } from "./components/ui";
import { FindingDetail } from "./pages/FindingDetail";
import { Findings } from "./pages/Findings";
import { Login } from "./pages/Login";
import { Overview } from "./pages/Overview";
import { ResourceDetail } from "./pages/ResourceDetail";
import { Resources } from "./pages/Resources";
import { Scans } from "./pages/Scans";

// Everything except the login page. When the API says there is no session, the person goes to the
// login page, and comes back to this address after logging in.
function Protected() {
  const { state } = useAuth();
  const location = useLocation();
  if (state.status === "out") {
    return (
      <Navigate
        to="/login"
        replace
        state={{ from: location.pathname + location.search }}
      />
    );
  }
  return <Layout />;
}

export default function App() {
  return (
    <AuthProvider>
      <Routes>
        <Route path="login" element={<Login />} />
        <Route element={<Protected />}>
          <Route index element={<Overview />} />
          <Route path="findings" element={<Findings />} />
          <Route path="findings/:findingId" element={<FindingDetail />} />
          <Route path="resources" element={<Resources />} />
          <Route path="resources/:resourceId" element={<ResourceDetail />} />
          <Route path="scans" element={<Scans />} />
          <Route path="*" element={<EmptyState title="Page not found" />} />
        </Route>
      </Routes>
    </AuthProvider>
  );
}
