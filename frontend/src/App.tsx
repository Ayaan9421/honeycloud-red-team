import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { LandingPage } from './pages/LandingPage';
import { DashboardLayout } from './layouts/DashboardLayout';
import { DashboardHome } from './pages/DashboardHome';
import { Campaigns } from './pages/Campaigns';
import { Tools } from './pages/Tools';
import { ExploitPipeline } from './pages/ExploitPipeline';
import { Logs } from './pages/Logs';

function App() {
  return (
    <Router>
      <Routes>
        {/* Landing Page */}
        <Route path="/" element={<LandingPage />} />

        {/* Dashboard Sub-routes */}
        <Route element={<DashboardLayout />}>
          <Route path="/dashboard" element={<DashboardHome />} />
          <Route path="/campaigns" element={<Campaigns />} />
          <Route path="/tools" element={<Tools />} />
          <Route path="/exploit" element={<ExploitPipeline />} />
          <Route path="/logs" element={<Logs />} />
        </Route>

        {/* Catch-all redirect to landing */}
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </Router>
  );
}

export default App;
