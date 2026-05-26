import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Route, Routes } from "react-router-dom";

import { Layout } from "@/components/Layout";
import { ChroniclePage } from "@/pages/Chronicle";
import { CompassPage } from "@/pages/Compass";
import { DashboardPage } from "@/pages/Dashboard";
import { LineagePage } from "@/pages/Lineage";
import { SentinelPage } from "@/pages/Sentinel";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: { retry: 1, refetchOnWindowFocus: false },
  },
});

export function App(): JSX.Element {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <Routes>
          <Route element={<Layout />}>
            <Route index element={<DashboardPage />} />
            <Route path="sentinel" element={<SentinelPage />} />
            <Route path="compass" element={<CompassPage />} />
            <Route path="lineage" element={<LineagePage />} />
            <Route path="chronicle" element={<ChroniclePage />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </QueryClientProvider>
  );
}
