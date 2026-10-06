import { Route, Routes } from "react-router-dom";
import { Layout } from "./components/Layout";
import { EmptyState } from "./components/ui";
import { FindingDetail } from "./pages/FindingDetail";
import { Findings } from "./pages/Findings";
import { Overview } from "./pages/Overview";
import { ResourceDetail } from "./pages/ResourceDetail";
import { Resources } from "./pages/Resources";
import { Scans } from "./pages/Scans";

export default function App() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<Overview />} />
        <Route path="findings" element={<Findings />} />
        <Route path="findings/:findingId" element={<FindingDetail />} />
        <Route path="resources" element={<Resources />} />
        <Route path="resources/:resourceId" element={<ResourceDetail />} />
        <Route path="scans" element={<Scans />} />
        <Route path="*" element={<EmptyState title="Page not found" />} />
      </Route>
    </Routes>
  );
}
