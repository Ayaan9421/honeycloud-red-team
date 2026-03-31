import React, { useEffect, useState } from 'react';
import {
  Activity,
  Target,
  ShieldAlert,
  Zap,
  Globe,
  Clock,
  RefreshCw,
  AlertCircle
} from 'lucide-react';
import { api } from '../api/client';

export function DashboardHome() {
  const [health, setHealth] = useState<any>(null);
  const [campaigns, setCampaigns] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchData = async () => {
    try {
      setLoading(true);
      const [healthData, campaignData] = await Promise.all([
        api.get('/health'),
        api.get('/campaigns')
      ]);
      setHealth(healthData);
      setCampaigns(campaignData);
      setError(null);
    } catch (err: any) {
      console.error("Dashboard fetch error:", err);
      setError("Using offline data (API unreachable)");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 30000); // refresh every 30s
    return () => clearInterval(interval);
  }, []);

  const activeCampaignsCount = campaigns.filter(c => c.status === 'running').length;

  // Metrics
  const METRICS = [
    { label: 'Active Campaigns', val: activeCampaignsCount.toString(), trend: `${campaigns.length} total`, icon: <Target size={20} />, color: 'var(--amber)' },
    { label: 'Avg Fingerprint', val: '0.92', trend: 'High confidence', icon: <Zap size={20} />, color: 'var(--high)' },
    { label: 'Honeypot Decoys', val: '1', trend: '', icon: <ShieldAlert size={20} />, color: 'var(--low)' },
    { label: 'System Status', val: health?.status?.toUpperCase() || 'READY', trend: health?.database?.connected ? 'DB Connected' : 'Offline', icon: <Activity size={20} />, color: health?.status === 'ok' ? 'var(--low)' : 'var(--amber)' },
  ];

  return (
    <div className="page-body">
      <div style={{ display: 'flex', alignItems: 'flex-end', justifyContent: 'space-between', marginBottom: 8 }}>
        <div>
          <div className="label" style={{ marginBottom: 4 }}>Overview</div>
          <h1 className="serif" style={{ fontSize: 32, margin: 0 }}>Research Dashboard</h1>
        </div>
        <div style={{ display: 'flex', gap: 10 }}>
          {error && (
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11, color: 'var(--amber)', paddingRight: 12 }}>
              <AlertCircle size={14} /> {error}
            </div>
          )}
        </div>
      </div>

      {/* ── METRICS ── */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 20 }}>
        {METRICS.map((m) => (
          <div key={m.label} className="mc">
            <div className="mc-bar" style={{ background: m.color }} />
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 16 }}>
              <div style={{ color: m.color }}>{m.icon}</div>
              <div style={{ fontSize: 10, color: 'var(--low)', background: 'var(--low-bg)', padding: '2px 6px', borderRadius: 4 }}>{m.trend}</div>
            </div>
            <div className="mc-val">{m.val}</div>
            <div className="label" style={{ marginTop: 8 }}>{m.label}</div>
          </div>
        ))}
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: 20 }}>
        {/* ── LIVE FEED ── */}
        <div className="panel">
          <div className="panel-hd">
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <div className="live-dot amber" />
              <div className="serif" style={{ fontWeight: 600 }}>Live Attack Feed</div>
            </div>
            <button style={{ background: 'none', border: 'none', color: 'var(--char5)', fontSize: 12, cursor: 'pointer' }}>View All</button>
          </div>
          <div style={{ padding: '8px 0', minHeight: 200 }}>
            {campaigns.length === 0 ? (
              <div style={{ padding: 40, textAlign: 'center', color: 'var(--char6)' }}>
                No recent campaigns found.
              </div>
            ) : (
              campaigns.slice(0, 5).map((c) => (
                <div key={c.id} className="feed-item row-hover">
                  <div className={`live-dot ${c.status === 'running' ? 'amber' : ''}`} style={{ width: 6, height: 6 }} />
                  <div>
                    <div style={{ fontWeight: 600, fontSize: 13 }}>{c.name}</div>
                    <div style={{ fontSize: 11, color: 'var(--char5)' }}>Target: {c.target_host}</div>
                  </div>
                  <div className={`chip ${c.status === 'running' ? 'chip-high' : c.status === 'completed' ? 'chip-low' : 'chip-medium'}`} style={{ fontSize: 8 }}>
                    {c.status.toUpperCase()}
                  </div>
                  <div style={{ fontSize: 12, color: 'var(--char2)', fontWeight: 500 }}>{c.playbook_name}</div>
                  <div style={{ fontSize: 11, color: 'var(--char6)', display: 'flex', alignItems: 'center', gap: 4 }}>
                    <Clock size={12} /> {new Date(c.created_at).toLocaleTimeString()}
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        {/* ── SYSTEM HEALTH ── */}
        <div className="panel">
          <div className="panel-hd">
            <div className="serif" style={{ fontWeight: 600 }}>Honeypot Health</div>
          </div>
          <div style={{ padding: 20 }}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              {[
                { name: 'API Status', status: health?.status === 'ok' ? '100%' : '0%', color: health?.status === 'ok' ? 'var(--low)' : 'var(--amber)' },
                { name: 'Database', status: health?.database?.connected ? 'CONNECTED' : 'OFFLINE', color: health?.database?.connected ? 'var(--low)' : 'var(--crit)' },
                { name: 'Redis Cache', status: health?.redis?.connected ? 'CONNECTED' : 'OFFLINE', color: health?.redis?.connected ? 'var(--low)' : 'var(--crit)' },
                { name: 'Target Network', status: 'ALLOWLISTED', color: 'var(--low)' },
              ].map(cluster => (
                <div key={cluster.name}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6, fontSize: 12 }}>
                    <span style={{ fontWeight: 500 }}>{cluster.name}</span>
                    <span style={{ color: cluster.color, fontWeight: 600 }}>{cluster.status}</span>
                  </div>
                  <div className="bar-track" style={{ height: 6 }}>
                    <div className="bar-fill" style={{ width: cluster.status.includes('%') ? cluster.status : '100%', background: cluster.color }} />
                  </div>
                </div>
              ))}
            </div>

            <div style={{ marginTop: 24, padding: 16, background: 'var(--surf2)', borderRadius: 8, border: '1px solid var(--bdr)' }}>
              <div className="label" style={{ marginBottom: 10 }}>Environment</div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                <Globe size={32} color="var(--char4)" />
                <div>
                  <div style={{ fontSize: 13, fontWeight: 600 }}>{health?.env?.toUpperCase() || 'DEVELOPMENT'}</div>
                  <div style={{ fontSize: 11, color: 'var(--char6)' }}>API Version 1.0.0 — Operational</div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
