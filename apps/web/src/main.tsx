import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { StrictMode, type ReactNode } from 'react';
import { createRoot } from 'react-dom/client';
import { BrowserRouter, Navigate, Route, Routes, useLocation } from 'react-router-dom';
import { Spinner, ToastProvider } from './components/ui';
import { installWorkerKdf } from './lib/kdf';
import { applyTheme, getThemePref } from './lib/theme';
import { VaultProvider, useVault } from './lib/vault';
import { Account } from './pages/Account';
import { LockScreen, Login, Recover, Register } from './pages/AuthPages';
import { Changes } from './pages/Changes';
import { Compare, Health } from './pages/Insights';
import { Webhooks } from './pages/Webhooks';
import { Landing } from './pages/Landing';
import { ProjectIndex, ProjectLayout } from './pages/Project';
import { Activity, ProjectSettings, Tokens } from './pages/ProjectExtras';
import { Projects } from './pages/Projects';
import { Secrets } from './pages/Secrets';
import { SendCreate, SendOpen } from './pages/Send';
import { Shell } from './pages/Shell';
import { Environments, Members } from './pages/Team';
import './styles/app.css';

installWorkerKdf();
applyTheme(getThemePref());

const queryClient = new QueryClient({
  defaultOptions: { queries: { staleTime: 15_000, retry: 1, refetchOnWindowFocus: false } },
});

function RequireVault({ children }: { children: ReactNode }) {
  const { status } = useVault();
  const location = useLocation();
  if (status === 'loading') return <Spinner />;
  if (status === 'signed-out') return <Navigate to="/login" replace state={{ from: location.pathname + location.search }} />;
  if (status === 'locked') return <LockScreen />;
  return <>{children}</>;
}

function App() {
  return (
    <Routes>
      <Route path="/" element={<Landing />} />
      <Route path="/login" element={<Login />} />
      <Route path="/register" element={<Register />} />
      <Route path="/recover" element={<Recover />} />
      <Route path="/s/:id" element={<SendOpen />} />
      <Route path="/app" element={<RequireVault><Shell /></RequireVault>}>
        <Route index element={<Projects />} />
        <Route path="send" element={<SendCreate />} />
        <Route path="account" element={<Account />} />
        <Route path="p/:projectId" element={<ProjectLayout />}>
          <Route index element={<ProjectIndex />} />
          <Route path="secrets" element={<Secrets />} />
          <Route path="changes" element={<Changes />} />
          <Route path="webhooks" element={<Webhooks />} />
          <Route path="health" element={<Health />} />
          <Route path="compare" element={<Compare />} />
          <Route path="members" element={<Members />} />
          <Route path="environments" element={<Environments />} />
          <Route path="tokens" element={<Tokens />} />
          <Route path="activity" element={<Activity />} />
          <Route path="settings" element={<ProjectSettings />} />
        </Route>
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <ToastProvider>
        <VaultProvider>
          <BrowserRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
            <App />
          </BrowserRouter>
        </VaultProvider>
      </ToastProvider>
    </QueryClientProvider>
  </StrictMode>,
);
