import React, { useState, useEffect } from 'react';
import { Activity, Download, Trash2, Filter, Search, RefreshCw, AlertCircle } from 'lucide-react';
import { api } from '../api/client';

export function Logs() {
  const [events, setEvents] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchEvents = async () => {
    try {
      const data = await api.get('/campaigns/events');
      setEvents(data);
      setError(null);
    } catch (err: any) {
      console.error("Failed to fetch events", err);
      setError("Failed to load event stream");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchEvents();
    const interval = setInterval(fetchEvents, 5000);
    return () => clearInterval(interval);
  }, []);

  const getSeverityColor = (sev: string) => {
    switch (sev?.toLowerCase()) {
      case 'critical': return 'var(--crit)';
      case 'high': return 'var(--high)';
      case 'medium': return 'var(--amber)';
      case 'low': return 'var(--low)';
      default: return 'var(--char5)';
    }
  };

  return (
    <div className="page-body">
      <div style={{ display: 'flex', alignItems: 'flex-end', justifyContent: 'space-between', marginBottom: 8 }}>
        <div>
          <div className="label" style={{ marginBottom: 4 }}>System Diagnostics</div>
          <h1 className="serif" style={{ fontSize: 32, margin: 0 }}>Live Event Logs</h1>
        </div>
        <div style={{ display: 'flex', gap: 10 }}>
          <button className="btn-outline" style={{ height: 40, display: 'flex', alignItems: 'center', gap: 8, color: 'var(--char)' }}>
            <Download size={16} /> Export JSON
          </button>
        </div>
      </div>

      {error && (
        <div style={{ padding: 12, background: 'var(--crit-bg)', border: '1px solid var(--crit-b)', borderRadius: 8, color: 'var(--crit)', display: 'flex', alignItems: 'center', gap: 10, fontSize: 13, marginBottom: 10 }}>
          <AlertCircle size={16} /> {error}
        </div>
      )}

      <div className="panel" style={{ display: 'flex', flexDirection: 'column', height: 'calc(100vh - 220px)' }}>
         <div className="panel-hd">
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
               <Activity size={18} />
               <div style={{ fontWeight: 600 }}>Raw Event Stream</div>
               {loading && <RefreshCw size={14} className="spinner" />}
            </div>
            <div style={{ display: 'flex', gap: 12 }}>
               <div style={{ position: 'relative', width: 200 }}>
                  <Search size={14} style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', color: 'var(--char6)' }} />
                  <input className="hc-input" placeholder="Filter stream..." style={{ height: 32, fontSize: 11, paddingLeft: 32 }} />
               </div>
               <button className="btn-outline" style={{ height: 32, fontSize: 11, padding: '0 12px', display: 'flex', alignItems: 'center', gap: 6, color: 'var(--char)' }}>
                  <Filter size={14} /> All Levels
               </button>
            </div>
         </div>
         <div style={{ flex: 1, background: 'var(--char)', overflowY: 'auto', padding: '12px 0' }}>
            {events.length === 0 ? (
              <div style={{ padding: 60, textAlign: 'center', color: 'var(--char5)', fontFamily: 'var(--mono)', fontSize: 12 }}>
                {loading ? 'Initializing stream...' : 'No events detected in the current buffer.'}
              </div>
            ) : (
              events.map((ev, i) => (
                <div key={ev.id} style={{ display: 'grid', gridTemplateColumns: '150px 120px 100px 1fr', gap: 12, padding: '6px 20px', fontFamily: 'var(--mono)', fontSize: 12, borderBottom: '1px solid rgba(255,255,255,0.05)', animation: i === 0 ? 'fade-in 0.5s ease' : 'none' }}>
                    <span style={{ color: 'var(--char6)' }}>[{new Date(ev.timestamp).toLocaleTimeString('en-GB', { hour12: false })}]</span>
                    <span style={{ color: 'var(--amber-l)', fontWeight: 600, overflow: 'hidden', textOverflow: 'ellipsis' }}>{ev.stage.toUpperCase()}</span>
                    <span style={{ 
                      color: getSeverityColor(ev.severity),
                      fontWeight: 700
                    }}>{(ev.severity || 'INFO').toUpperCase()}</span>
                    <span style={{ color: 'var(--cream-4)' }}>
                      <span style={{ color: 'var(--low)', fontWeight: 600 }}>{ev.action}</span> — {ev.detail}
                    </span>
                </div>
              ))
            )}
         </div>
         <div style={{ padding: '8px 20px', background: 'rgba(0,0,0,0.2)', borderTop: '1px solid var(--bdr)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div style={{ fontSize: 11, color: 'var(--char5)', display: 'flex', alignItems: 'center', gap: 8 }}>
               <div className="live-dot" style={{ background: events.length > 0 ? 'var(--low)' : 'var(--amber)' }} />
               {events.length} events in buffer
            </div>
            <div className="label" style={{ fontSize: 9 }}>UTF-8 Encoding · Buffer: {events.length * 2}KB</div>
         </div>
      </div>
    </div>
  );
}
