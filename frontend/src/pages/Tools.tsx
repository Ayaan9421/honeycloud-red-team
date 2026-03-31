import React, { useState, useEffect } from 'react';
import { Terminal, Search, Play, FileText, Globe, Zap, Settings, RefreshCw, AlertCircle, Clock, Trash2 } from 'lucide-react';
import { api } from '../api/client';
import { Shield } from 'lucide-react';

const TOOLS = [
  { id: 'nmap', name: 'Nmap Scanner', desc: 'Port scanning and service enumeration tool.', icon: <Search size={18} /> },
];

export function Tools() {
  const [selectedTool, setSelectedTool] = useState('nmap');
  const [profiles, setProfiles] = useState<any[]>([]);
  const [scans, setScans] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [target, setTarget] = useState('');
  const [selectedProfile, setSelectedProfile] = useState('standard');
  const [error, setError] = useState<string | null>(null);

  const fetchProfiles = async () => {
    try {
      const data = await api.get('/tools/scan/profiles');
      setProfiles(data.profiles || []);
    } catch (err) {
      console.error("Failed to fetch profiles", err);
    }
  };

  const fetchScans = async () => {
    try {
      const data = await api.get('/tools/scan');
      setScans(data);
    } catch (err) {
      console.error("Failed to fetch scans", err);
    }
  };

  useEffect(() => {
    fetchProfiles();
    fetchScans();
    const interval = setInterval(fetchScans, 5000);
    return () => clearInterval(interval);
  }, []);

  const handleRunScan = async () => {
    if (!target) {
      setError("Please specify a target");
      return;
    }
    setError(null);
    setLoading(true);
    try {
      await api.post('/tools/scan', {
        target: target,
        profile: selectedProfile
      });
      fetchScans();
    } catch (err: any) {
      setError(err.message || "Failed to launch scan");
    } finally {
      setLoading(false);
    }
  };

  const handleDeleteScan = async (jobId: string) => {
    try {
      await api.delete(`/tools/scan/${jobId}`);
      fetchScans();
    } catch (err) {
      console.error("Failed to delete scan", err);
    }
  };

  const activeScan = scans.find(s => s.status === 'running' || s.status === 'pending');

  return (
    <div className="page-body">
      <div style={{ display: 'flex', alignItems: 'flex-end', justifyContent: 'space-between', marginBottom: 8 }}>
        <div>
          <div className="label" style={{ marginBottom: 4 }}>Research Tools</div>
          <h1 className="serif" style={{ fontSize: 32, margin: 0 }}>Attack Tools</h1>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 2fr', gap: 20 }}>
        {/* ── TOOL LIST ── */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          {TOOLS.map(t => (
            <div
              key={t.id}
              className={`panel row-hover ${selectedTool === t.id ? 'active-panel' : ''}`}
              style={{
                cursor: t.id === 'nmap' ? 'pointer' : 'not-allowed',
                opacity: t.id === 'nmap' ? 1 : 0.6,
                borderLeft: selectedTool === t.id ? '4px solid var(--amber)' : ''
              }}
              onClick={() => t.id === 'nmap' && setSelectedTool(t.id)}
            >
              <div style={{ padding: 16, display: 'flex', alignItems: 'center', gap: 14 }}>
                <div className="nav-icon" style={{ background: selectedTool === t.id ? 'var(--amber-p)' : 'var(--cream-2)' }}>
                  {t.icon}
                </div>
                <div>
                  <div style={{ fontWeight: 600, fontSize: 14 }}>{t.name}</div>
                  <div style={{ fontSize: 11, color: 'var(--char6)' }}>{t.id === 'nmap' ? t.desc : '(Coming Soon)'}</div>
                </div>
              </div>
            </div>
          ))}

          <div className="panel" style={{ marginTop: 12 }}>
            <div className="panel-hd">
              <div className="label">Recent Scans</div>
            </div>
            <div style={{ maxHeight: 300, overflowY: 'auto' }}>
              {scans.length === 0 ? (
                <div style={{ padding: 20, textAlign: 'center', fontSize: 12, color: 'var(--char6)' }}>No recent scans</div>
              ) : (
                scans.map(s => (
                  <div key={s.job_id} className="feed-item row-hover" style={{ gridTemplateColumns: '1fr auto auto' }}>
                    <div style={{ overflow: 'hidden', textOverflow: 'ellipsis' }}>
                      <div style={{ fontWeight: 600, fontSize: 12 }}>{s.target}</div>
                      <div style={{ fontSize: 10, color: 'var(--char6)' }}>{s.profile} • {new Date(s.created_at).toLocaleTimeString()}</div>
                    </div>
                    <div className={`chip ${s.status === 'done' ? 'chip-low' : s.status === 'error' ? 'chip-critical' : 'chip-high'}`} style={{ fontSize: 8 }}>
                      {s.status.toUpperCase()}
                    </div>
                    <button
                      onClick={() => handleDeleteScan(s.job_id)}
                      style={{ background: 'none', border: 'none', color: 'var(--char6)', cursor: 'pointer' }}
                    >
                      <Trash2 size={14} />
                    </button>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>

        {/* ── TOOL CONFIG/OUTPUT ── */}
        <div className="panel" style={{ display: 'flex', flexDirection: 'column' }}>
          <div className="panel-hd">
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <Settings size={18} />
              <div style={{ fontWeight: 600 }}>Configure {TOOLS.find(t => t.id === selectedTool)?.name}</div>
            </div>
            <button
              className="btn-amber"
              style={{ padding: '6px 16px', fontSize: 12, display: 'flex', alignItems: 'center', gap: 6 }}
              onClick={handleRunScan}
              disabled={loading || !!activeScan}
            >
              {loading || !!activeScan ? <RefreshCw size={14} className="spinner" /> : <Play size={14} />}
              Run Scan
            </button>
          </div>
          <div style={{ padding: 20, flex: 1 }}>
            {error && (
              <div style={{ marginBottom: 20, padding: 12, background: 'var(--crit-bg)', border: '1px solid var(--crit-b)', borderRadius: 8, color: 'var(--crit)', display: 'flex', alignItems: 'center', gap: 10, fontSize: 13 }}>
                <AlertCircle size={16} /> {error}
              </div>
            )}

            <div style={{ marginBottom: 20 }}>
              <div className="label" style={{ marginBottom: 10 }}>Target Specification</div>
              <input
                className="hc-input"
                placeholder="e.g. 192.168.1.50"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
              />
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20, marginBottom: 24 }}>
              <div>
                <div className="label" style={{ marginBottom: 10 }}>Scan Profile</div>
                <select
                  className="hc-input"
                  style={{ background: 'var(--cream)' }}
                  value={selectedProfile}
                  onChange={(e) => setSelectedProfile(e.target.value)}
                >
                  {profiles.map(p => (
                    <option key={p.name} value={p.name}>{p.name.charAt(0).toUpperCase() + p.name.slice(1)} - {p.description}</option>
                  ))}
                </select>
              </div>
              <div>
                <div className="label" style={{ marginBottom: 10 }}>Safety Status</div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, height: 44, padding: '0 16px', background: 'var(--low-bg)', borderRadius: 8, border: '1.5px solid var(--low-b)', color: 'var(--low)', fontSize: 13, fontWeight: 500 }}>
                  <Shield size={16} /> Restricted to Allowlist
                </div>
              </div>
            </div>

            <div className="label" style={{ marginBottom: 10 }}>Live Terminal Output</div>
            <div style={{ background: 'var(--char)', borderRadius: 8, padding: 16, fontFamily: 'var(--mono)', fontSize: 12, color: '#00FF41', minHeight: 300, overflowY: 'auto' }}>
              {activeScan ? (
                <>
                  <div>$ nmap {activeScan.profile === 'standard' ? '-sT -sV' : activeScan.profile} {activeScan.target}</div>
                  <div style={{ opacity: 0.7 }}>[SYSTEM] Job ID: {activeScan.job_id}</div>
                  <div style={{ opacity: 0.7 }}>[SYSTEM] Status: {activeScan.status}...</div>
                  <div style={{ marginTop: 8, animation: 'pulse-s 1s infinite' }}>_</div>
                </>
              ) : scans.length > 0 && scans[0].status === 'done' ? (
                <>
                  <div>$ nmap result for {scans[0].target}</div>
                  <div style={{ opacity: 0.7 }}>Scan finished in {scans[0].elapsed_s}s</div>
                  <div style={{ marginTop: 8 }}>PORT    STATE SERVICE VERSION</div>
                  {scans[0].result?.open_ports?.map((p: number) => (
                    <div key={p}>{p}/tcp  open  {scans[0].result?.services?.[p] || 'unknown'}</div>
                  ))}
                  {scans[0].result?.open_ports?.length === 0 && (
                    <div style={{ opacity: 0.5 }}>No open ports found.</div>
                  )}
                </>
              ) : (
                <div style={{ opacity: 0.4 }}>Launch a scan to see output...</div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
