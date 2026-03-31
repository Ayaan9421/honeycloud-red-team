import React, { useState } from 'react';
import { NavLink, Outlet, useLocation } from 'react-router-dom';
import {
  LayoutDashboard,
  Target,
  Terminal,
  ShieldAlert,
  Database,
  Activity,
  ChevronRight,
  Bell,
  Search,
  User
} from 'lucide-react';
import { clsx } from 'clsx';

import logo from '../assets/honeycloud.png';

const NAV_ITEMS = [
  { id: 'dashboard', label: 'Dashboard', path: '/dashboard', icon: <LayoutDashboard size={18} /> },
  { id: 'campaigns', label: 'APT Campaigns', path: '/campaigns', icon: <Target size={18} /> },
  { id: 'tools', label: 'Attack Tools', path: '/tools', icon: <Terminal size={18} /> },
  { id: 'exploit', label: 'Exploit Pipeline', path: '/exploit', icon: <ShieldAlert size={18} /> },
];

export function DashboardLayout() {
  const location = useLocation();
  const [isNotificationsOpen, setNotificationsOpen] = useState(false);

  return (
    <div className="app-shell">
      {/* ── TOPBAR ── */}
      <header className="topbar">
        <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
          <img src={logo} style={{ width: 70, height: 70, objectFit: 'cover' }} alt="HoneyCloud Logo" />
          <div style={{ fontFamily: 'var(--serif)', fontSize: 22, color: 'var(--char)', fontWeight: 600, letterSpacing: '-.02em' }}>
            HoneyCloud <span style={{ color: 'red', fontStyle: 'italic', marginLeft: 4 }}>RedTeam</span>
          </div>
        </div>


        <div style={{ display: 'flex', alignItems: 'center', gap: 20 }}>
          <div style={{ position: 'relative', width: 280 }}>
            <Search size={16} style={{ position: 'absolute', left: 14, top: '50%', transform: 'translateY(-50%)', color: 'var(--char6)' }} />
            <input
              type="text"
              className="hc-input"
              placeholder="Search campaigns, CVEs, IPs..."
              style={{ paddingLeft: 40, height: 38 }}
            />
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <button className="nav-icon" style={{ background: 'var(--cream-2)', border: 'none', cursor: 'pointer', position: 'relative' }}>
              <Bell size={18} />
              <div className="live-dot amber" style={{ position: 'absolute', top: 6, right: 6, width: 6, height: 6 }} />
            </button>

            <div style={{ width: 1, height: 24, background: 'var(--bdr2)', margin: '0 4px' }} />

            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <div style={{ textAlign: 'right' }}>
                <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--char)' }}>Admin Console</div>
                <div style={{ fontSize: 10, color: 'var(--char6)', textTransform: 'uppercase', letterSpacing: '.1em' }}>Researcher</div>
              </div>
              <div style={{ width: 36, height: 36, borderRadius: 8, background: 'var(--char)', color: 'var(--cream)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                <User size={20} />
              </div>
            </div>
          </div>
        </div>
      </header>

      {/* ── SIDEBAR ── */}
      <aside className="sidebar">
        <div className="nav-section-label">Main Navigation</div>
        <nav style={{ flex: 1 }}>
          {NAV_ITEMS.map((item) => (
            <NavLink
              key={item.id}
              to={item.path}
              className={({ isActive }) => clsx('nav-item', isActive && 'active')}
            >
              <div className="nav-icon">{item.icon}</div>
              <span style={{ flex: 1 }}>{item.label}</span>
              {location.pathname === item.path && <ChevronRight size={14} style={{ opacity: 0.5 }} />}
            </NavLink>
          ))}
        </nav>

      </aside>

      {/* ── MAIN CONTENT ── */}
      <main className="main-content">
        <Outlet />
      </main>
    </div>
  );
}
