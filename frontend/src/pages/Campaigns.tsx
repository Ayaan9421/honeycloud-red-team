import React, { useEffect, useState, useRef } from 'react';
import {
  Target, Play, Shield, Clock, Users, ChevronRight,
  RefreshCw, AlertCircle, X, Activity, CheckCircle, AlertTriangle,
  Trash2,
} from 'lucide-react';
import { api } from '../api/client';


// ═══════════════════════════════════════════════════════════════════
// DETAIL PARSER
// Handles every format the backend actually produces:
//   fingerprint → JSON string  (honeypot_confidence, verdict, scores)
//   port_scan   → plain string "open ports: [22, 2222]"
//   banner_grab → plain string "SSH-2.0-OpenSSH_6.0p1\r\n"
//   ssh_brute   → plain string "tried=2 cred=root:password"
//   ssh_exec    → Python dict  str({"id": "root", "uname -a": "Linux..."})
//   exfil       → Python dict  str({"cat /etc/passwd": "root:x:0:..."})
//   nmap_scan   → JSON string  (NmapScanResult)
// ═══════════════════════════════════════════════════════════════════

function parsePythonDict(raw: string): Record<string, string> | null {
  // Python's str() on a dict uses single quotes. We normalise to JSON.
  // Step 1: replace single-quoted string boundaries carefully
  try {
    // Replace outer single quotes on keys/values with double quotes,
    // but only where they act as string delimiters (preceded by { , : or space)
    const jsonLike = raw
      .replace(/'/g, '"')          // naive first pass
    // Fix cases where a value contains an apostrophe that got double-quoted
    // e.g. "can"t" → not a problem in practice for command output
    return JSON.parse(jsonLike);
  } catch {
    return null;
  }
}

function tryParseJSON(raw: string): any | null {
  const t = raw.trim();
  if (!t.startsWith('{') && !t.startsWith('[')) return null;
  try { return JSON.parse(t); } catch { return null; }
}

function isNmapJson(raw: string): boolean {
  return (
    raw.includes('"scan_args"') ||
    raw.includes('"nmap_version"') ||
    raw.includes('"fallback_used"') ||
    (raw.includes('"hosts"') && raw.includes('"profile"'))
  );
}

// Single source of truth for nmap rendering — used by BOTH left and right panels.
// Returns a display string. Works with complete or truncated JSON.
function renderNmapDetail(raw: string): string {
  // Try full parse
  const json = tryParseJSON(raw);
  const data = json || {};

  // Error
  const err = data.error || raw.match(/"error":\s*"([^"]+)"/)?.[1] || null;
  if (err) return formatErrorString(err);

  // Meta fields — from parsed JSON or regex fallback
  const profile = data.profile || raw.match(/"profile":\s*"([^"]+)"/)?.[1] || '';
  const elapsedRaw = data.elapsed_s ?? raw.match(/"elapsed_s":\s*([\d.]+)/)?.[1] ?? null;
  const elapsed_s = elapsedRaw != null ? Number(elapsedRaw) : null;
  const fallback = data.fallback_used ?? raw.includes('"fallback_used": true');
  const target = data.target || raw.match(/"target":\s*"([^"]+)"/)?.[1] || '';

  // Extract open ports — walk hosts if parsed, else regex
  const openPorts: { port: number; service: string; product: string; version: string }[] = [];

  if (json?.hosts) {
    for (const host of json.hosts) {
      for (const p of (host.ports || [])) {
        if (p.state === 'open') {
          openPorts.push({
            port: p.port,
            service: p.service || '',
            product: p.product || '',
            version: p.version || '',
          });
        }
      }
    }
  } else {
    // Regex over raw string for truncated JSON
    // Port objects look like: {"port": 22, "protocol": "tcp", "state": "open", "service": "ssh", "product": "OpenSSH", "version": "9.6p1"}
    const portBlocks = raw.match(/\{[^}]*"port"[^}]*\}/g) || [];
    for (const block of portBlocks) {
      const stateM = block.match(/"state":\s*"([^"]+)"/);
      if (!stateM || stateM[1] !== 'open') continue;
      const portM = block.match(/"port":\s*(\d+)/);
      const serviceM = block.match(/"service":\s*"([^"]*)"/);
      const productM = block.match(/"product":\s*"([^"]*)"/);
      const versionM = block.match(/"version":\s*"([^"]*)"/);
      if (portM) {
        openPorts.push({
          port: parseInt(portM[1]),
          service: serviceM?.[1] || '',
          product: productM?.[1] || '',
          version: versionM?.[1] || '',
        });
      }
    }
  }

  const metaParts: string[] = [];
  if (profile) metaParts.push(profile + ' profile');
  if (elapsed_s != null) metaParts.push(`${elapsed_s.toFixed(1)}s`);
  if (fallback) metaParts.push('fallback TCP scan');
  const meta = metaParts.length ? ` [${metaParts.join(', ')}]` : '';

  if (!openPorts.length) {
    return `No open ports found${meta}.`;
  }

  const portLines = openPorts.map(p => {
    const svc = [p.service, p.product, p.version].filter(Boolean).join(' ');
    return `${p.port}/tcp${svc ? `  ${svc}` : ''}`;
  });

  const honeypot = openPorts.some(p => p.port === 2222 || p.port === 2223)
    ? '  ⚠ honeypot port' : '';

  return `${openPorts.length} open port${openPorts.length !== 1 ? 's' : ''}${meta}:\n${portLines.join('\n')}${honeypot}`;
}

function humanizeDetail(rawInput: any, stageName?: string): string {
  if (rawInput === null || rawInput === undefined || rawInput === '') return '';

  const raw = typeof rawInput === 'string' ? rawInput.trim() : rawInput;

  // ── Already a JS object (shouldn't happen but guard it) ──────────
  if (typeof raw === 'object') return formatObject(raw, stageName);

  // ── Plain string — try each known format in priority order ───────

  // 1. Nmap JSON string — detect before tryParseJSON, same function for both panels
  if (isNmapJson(raw)) return renderNmapDetail(raw);

  // 2. JSON object (fingerprint, or complete nmap)
  const json = tryParseJSON(raw);
  if (json) return formatObject(json, stageName);

  // 2. Python dict (ssh_exec, exfil)
  if (raw.startsWith("{'") || raw.startsWith('{"') || (raw.startsWith('{') && raw.includes(': '))) {
    const pd = parsePythonDict(raw);
    if (pd) return formatObject(pd, stageName);
  }

  // 3. SSH brute "tried=N cred=user:pass"
  const triedMatch = raw.match(/tried=(\d+)/);
  const credMatch = raw.match(/cred=(\S+)/);
  if (triedMatch) {
    const n = triedMatch[1];
    const cred = credMatch ? credMatch[1] : null;
    if (cred && cred !== 'none') {
      const [user, pass] = cred.split(':');
      return `Credential stuffing succeeded after ${n} attempt${n !== '1' ? 's' : ''} — gained access as "${user}" with password "${pass}".`;
    }
    return `Tried ${n} credential pair${n !== '1' ? 's' : ''} — no valid credentials found on this target.`;
  }

  // 4. Port scan "open ports: [22, 2222]"
  const portsMatch = raw.match(/open ports:\s*\[([^\]]*)\]/i);
  if (portsMatch) {
    const parts = portsMatch[1].split(',').map((p: string) => p.trim()).filter(Boolean);
    return parts.length
      ? `Discovered ${parts.length} open port${parts.length !== 1 ? 's' : ''}: ${parts.join(', ')}.`
      : 'No open ports found on target.';
  }

  // 5. Banner string — strip CRLF, trim
  if (raw.startsWith('SSH-')) {
    const banner = raw.replace(/[\r\n]+/g, ' ').trim();
    return `SSH banner: ${banner}`;
  }

  // 6. Error string from exception
  if (raw.toLowerCase().startsWith('exception:') || raw.toLowerCase().startsWith('error:')) {
    return formatErrorString(raw);
  }

  // 7. Fallback — return cleaned string
  return raw.replace(/[\r\n]+/g, ' ');
}

function formatErrorString(msg: string): string {
  const m = msg.toLowerCase();
  if (m.includes('channel closed')) return 'SSH channel closed by target — session ended.';
  if (m.includes('authentication')) return 'Authentication rejected by target.';
  if (m.includes('timed out') || m.includes('timeout')) return 'Connection timed out.';
  if (m.includes('connection refused')) return 'Target refused the connection.';
  if (m.includes('no existing session')) return 'Session incomplete — target may have closed the channel (common with Cowrie).';
  if (m.includes('no route to host')) return 'No route to host — target may be offline.';
  return msg.replace(/^exception:\s*/i, 'Error: ').slice(0, 200);
}

function formatObject(data: Record<string, any>, stageName?: string): string {

  // ── Error key ─────────────────────────────────────────────
  if (data.error) return formatErrorString(String(data.error));

  // ── Fingerprint ───────────────────────────────────────────
  if ('honeypot_confidence' in data || 'verdict' in data) {
    const verdict = (data.verdict || 'UNKNOWN').toUpperCase();
    const confidence = data.honeypot_confidence != null
      ? `${(Number(data.honeypot_confidence) * 100).toFixed(1)}%`
      : null;

    const verdictLabel =
      verdict === 'HONEYPOT' ? 'Target identified as a honeypot' :
        verdict === 'REAL' ? 'Target appears to be a real system' :
          'Target classification is uncertain';

    const signals: string[] = [];
    if (data.banner_score > 0) signals.push(`banner match (${pct(data.banner_score)})`);
    if (data.timing_score > 0) signals.push(`timing anomaly (${pct(data.timing_score)})`);
    if (data.filesystem_score > 0) signals.push(`filesystem tell (${pct(data.filesystem_score)})`);
    if (data.protocol_depth_score > 0) signals.push(`protocol depth (${pct(data.protocol_depth_score)})`);

    const sigStr = signals.length ? ` via ${signals.join(', ')}` : '';
    const confStr = confidence ? ` — ${confidence} confidence` : '';
    return `${verdictLabel}${sigStr}${confStr}.`;
  }

  // ── Nmap scan ─────────────────────────────────────────────
  if ('scan_args' in data || ('hosts' in data && 'profile' in data)) {
    // Re-serialize to string so renderNmapDetail handles it consistently
    try { return renderNmapDetail(JSON.stringify(data)); } catch { return 'nmap scan completed.'; }
  }

  // ── SSH exec / Exfil — keys are shell commands ────────────
  const CMD_KEYS = ['id', 'whoami', 'pwd', 'uname -a', 'uname', 'ifconfig'];
  const cmdKeys = Object.keys(data).filter(k =>
    CMD_KEYS.includes(k) ||
    k.startsWith('cat ') || k.startsWith('ls ') ||
    k.startsWith('echo ') || k.startsWith('ss ') ||
    k.startsWith('ip ') || k.startsWith('netstat')
  );

  if (cmdKeys.length > 0) {
    const lines: string[] = [];
    for (const cmd of cmdKeys) {
      const out = String(data[cmd] || '').trim();
      if (!out || out.toLowerCase().startsWith('error')) continue;

      if (cmd === 'id' || cmd === 'whoami') {
        lines.push(`Shell identity: ${out.split(' ')[0]}`);
      } else if (cmd === 'uname -a' || cmd === 'uname') {
        const parts = out.split(' ');
        lines.push(`OS: ${parts[0]} ${parts[2] || ''}`.trim());
      } else if (cmd === 'pwd') {
        lines.push(`Working directory: ${out}`);
      } else if (cmd.startsWith('cat /etc/passwd')) {
        const count = out.split('\n').filter(Boolean).length;
        lines.push(`Read ${count} system user${count !== 1 ? 's' : ''} from /etc/passwd`);
      } else if (cmd.startsWith('cat /etc/shadow')) {
        if (out.includes('permission denied')) {
          lines.push('Shadow file: access denied');
        } else {
          const hashes = out.split('\n').filter(l => l.includes(':$')).length;
          lines.push(`Exfiltrated ${hashes} password hash${hashes !== 1 ? 'es' : ''} from /etc/shadow`);
        }
      } else if (cmd.startsWith('cat /etc/hostname')) {
        lines.push(`Hostname: ${out}`);
      } else if (cmd === 'ifconfig' || cmd.startsWith('ip addr')) {
        const ip = out.match(/inet\s+(\d+\.\d+\.\d+\.\d+)/);
        lines.push(ip ? `Network IP: ${ip[1]}` : 'Network interfaces retrieved');
      } else if (cmd.startsWith('ss ') || cmd.startsWith('netstat')) {
        const n = out.split('\n').filter(Boolean).length;
        lines.push(`Found ${n} active listener${n !== 1 ? 's' : ''}`);
      }
    }
    if (lines.length > 0) return lines.join(' · ');
    // All commands errored
    return 'Commands executed — target returned empty or restricted output.';
  }

  // ── Generic key/value fallback ────────────────────────────
  const SKIP = new Set([
    'id', 'timestamp', 'status', 'module', 'action',
    'target_host', 'target_port', 'raw_features_json', 'is_honeypot',
    'scan_args', 'started_at', 'nmap_version', 'raw_command',
  ]);
  const parts = Object.entries(data)
    .filter(([k, v]) => !SKIP.has(k) && v !== null && v !== '' && v !== undefined && !Array.isArray(v))
    .slice(0, 6)
    .map(([k, v]) => {
      const label = k.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
      const val = typeof v === 'number'
        ? (k.includes('score') || k.includes('rate') || k.includes('confidence')
          ? pct(v) : String(v))
        : String(v);
      return `${label}: ${val}`;
    });
  return parts.length ? parts.join(' · ') : 'Stage completed.';
}

function pct(v: number): string {
  return `${(Number(v) * 100).toFixed(1)}%`;
}


// ═══════════════════════════════════════════════════════════════════
// STAGE SUCCESS INFERENCE
//
// CampaignStage model fields (from DB):
//   stage_name, stage_order, status ("pending"|"running"|"done")
//   result_json (string — the ActionResult.detail stored truncated)
//
// There is NO boolean `success` field on the stage itself.
// We infer it from result_json content.
// ═══════════════════════════════════════════════════════════════════

function inferStageSuccess(stage: any): boolean {
  if (stage.status !== 'done') return false;

  const rj: string = stage.result_json || '';
  if (!rj) return true;

  // ssh_brute plain string
  if (rj.includes('cred=none')) return false;

  // Exception from orchestrator catch block
  if (rj.toLowerCase().startsWith('exception:')) return false;

  // Port scan plain string with no ports
  if (rj.includes('open ports: []')) return false;

  // Nmap — use same detection as display so success always matches what's shown
  if (isNmapJson(rj)) {
    const rendered = renderNmapDetail(rj);
    // Success = we found open ports (rendered string starts with a digit = port count)
    return /^\d+\s+open/.test(rendered);
  }

  const json = tryParseJSON(rj);
  if (json) {
    if (json.error) return false;
    return true;
  }

  // Python dict (ssh_exec / exfil)
  if (rj.startsWith('{')) {
    const pd = parsePythonDict(rj);
    if (pd && pd.error) return false;
    return true;
  }

  return true;
}


// ═══════════════════════════════════════════════════════════════════
// STAGE BADGES
// Rules (corrected):
//   pending  → grey PENDING
//   running  → amber spinner PROCESSING
//   done + inferred success=false → red FAILED
//   done + inferred success=true  + detected → green SUCCESS | amber DETECTED
//   done + inferred success=true  + !detected → green SUCCESS | green CLEAN
// ═══════════════════════════════════════════════════════════════════

function StageBadges({ stage }: { stage: any }) {
  if (stage.status === 'pending') {
    return (
      <span style={{ fontWeight: 600, letterSpacing: '0.05em', color: 'var(--char6)', fontSize: 11 }}>
        PENDING
      </span>
    );
  }

  if (stage.status === 'running') {
    return (
      <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
        <RefreshCw size={14} style={{ animation: 'spin 1.5s linear infinite', color: 'var(--amber)' }} />
        <span className="label" style={{ fontSize: 8, color: 'var(--amber)' }}>PROCESSING</span>
      </div>
    );
  }

  // status === 'done'
  const success = inferStageSuccess(stage);
  // `detected` comes from the AttackEvent, not the stage — but stages
  // don't carry it. We can only show it when we have event data.
  // For the stage pipeline view, show SUCCESS/FAILED only.
  if (!success) {
    return (
      <span style={{
        display: 'inline-flex', alignItems: 'center', gap: 6,
        color: 'var(--crit)', fontWeight: 700,
        padding: '2px 8px', background: 'var(--crit-bg)', borderRadius: 4, fontSize: 10,
      }}>
        <AlertCircle size={12} /> FAILED
      </span>
    );
  }

  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: 6,
      color: 'var(--low)', fontWeight: 700,
      padding: '2px 8px', background: 'var(--low-bg)', borderRadius: 4, fontSize: 10,
    }}>
      <CheckCircle size={12} /> SUCCESS
    </span>
  );
}


// ═══════════════════════════════════════════════════════════════════
// EVENT ROW — used in the live event stream
// Shows SUCCESS/FAILED + DETECTED/CLEAN based on AttackEvent fields
// (AttackEvent DOES have success + detected booleans)
// ═══════════════════════════════════════════════════════════════════

function EventStatusBadges({ ev }: { ev: any }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 4 }}>
      {/* Success / Failed */}
      <span style={{
        display: 'inline-flex', alignItems: 'center', gap: 4, fontSize: 10, fontWeight: 700,
        padding: '1px 7px', borderRadius: 3,
        background: ev.success ? 'var(--low-bg)' : 'var(--crit-bg)',
        color: ev.success ? 'var(--low)' : 'var(--crit)',
      }}>
        {ev.success ? <CheckCircle size={10} /> : <AlertCircle size={10} />}
        {ev.success ? 'SUCCESS' : 'FAILED'}
      </span>

      {/* Detected / Clean — only meaningful when success */}
      {ev.success && (
        <span style={{
          display: 'inline-flex', alignItems: 'center', gap: 4, fontSize: 10, fontWeight: 600,
          color: ev.detected ? 'var(--amber)' : 'var(--low)',
        }}>
          {ev.detected
            ? <><AlertTriangle size={10} /> DETECTED</>
            : <><Shield size={10} /> CLEAN</>}
        </span>
      )}
    </div>
  );
}


// ═══════════════════════════════════════════════════════════════════
// CAMPAIGN DETAILS MODAL
// ═══════════════════════════════════════════════════════════════════

function CampaignDetailsModal({ campaignId, onClose }: { campaignId: string; onClose: () => void }) {
  const [campaign, setCampaign] = useState<any>(null);
  const [events, setEvents] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const scrollRef = useRef<HTMLDivElement>(null);
  const wsRef = useRef<WebSocket | null>(null);

  const handleDelete = async () => {
    if (!campaign) return;

    const confirm = window.confirm(
      `Abort campaign "${campaign.name}"?\nThis cannot be undone.`
    );
    if (!confirm) return;

    try {
      await api.delete(`/campaigns/${campaign.id}`);
      onClose(); // close modal
    } catch (err: any) {
      alert(err?.message || 'Failed to abort campaign');
    }
  };

  const fetchDetails = async () => {
    try {
      const [cData, eData] = await Promise.all([
        api.get(`/campaigns/${campaignId}`),
        api.get(`/campaigns/${campaignId}/events`),
      ]);
      setCampaign(cData);
      setEvents(eData);
    } catch (err) {
      console.error('Failed to load campaign details', err);
    }
  };

  useEffect(() => {
    const init = async () => { setLoading(true); await fetchDetails(); setLoading(false); };
    init();

    const ws = new WebSocket(`ws://localhost:8000/api/ws/campaigns/${campaignId}`);
    wsRef.current = ws;
    ws.onmessage = () => { fetchDetails(); };
    return () => { wsRef.current?.close(); };
  }, [campaignId]);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [events]);

  if (loading) return (
    <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.5)', zIndex: 2000, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
      <div className="spinner" />
    </div>
  );

  return (
    <div style={{
      position: 'fixed', inset: 0,
      background: 'rgba(10,9,8,0.9)', backdropFilter: 'blur(12px)',
      zIndex: 1000, display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 20,
    }}>
      <div className="panel au" style={{
        width: '100%', maxWidth: 1200, height: '85vh',
        background: 'var(--surf)', display: 'flex', flexDirection: 'column',
        border: '1px solid var(--char3)',
        boxShadow: '0 24px 64px rgba(0,0,0,0.4)', borderRadius: 12, overflow: 'hidden',
      }}>

        {/* Header */}
        <div className="panel-hd" style={{ padding: '20px 28px', background: 'var(--char)', borderBottom: '1px solid var(--char3)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 20 }}>
            <div className={`live-dot ${campaign?.status === 'running' ? 'amber' : ''}`} style={{ width: 12, height: 12 }} />
            <div>
              <div style={{ fontWeight: 700, fontSize: 20, letterSpacing: '-0.02em', color: '#fff' }}>
                {campaign?.name}
              </div>
              <div className="label" style={{ color: 'var(--char6)', fontSize: 10, marginTop: 4, opacity: 0.8 }}>
                {campaign?.playbook_name?.toUpperCase()} · {campaign?.target_host}:{campaign?.target_port}
              </div>
            </div>
          </div>
          <button onClick={onClose} style={{
            background: 'rgba(255,255,255,0.08)', border: 'none', color: '#fff',
            cursor: 'pointer', padding: 10, borderRadius: 8,
            display: 'flex', alignItems: 'center', justifyContent: 'center',
          }}>
            <X size={20} />
          </button>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '340px 1fr', flex: 1, overflow: 'hidden' }}>

          {/* Left — stage pipeline */}
          <div style={{ borderRight: '1px solid var(--bdr)', background: 'var(--surf2)', padding: '32px 28px', overflowY: 'auto' }}>
            <div style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              marginBottom: 24,
            }}>
              <div className="label" style={{ fontSize: 11, color: 'var(--char5)' }}>
                Campaign Lifecycle
              </div>

              {/* DELETE BUTTON */}
              <button
                onClick={handleDelete}
                disabled={
                  !campaign ||
                  !['pending', 'running'].includes(campaign.status)
                }
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 6,
                  fontSize: 10,
                  fontWeight: 700,
                  padding: '6px 10px',
                  borderRadius: 6,
                  border: '1px solid rgba(248,113,113,0.3)',
                  background: 'rgba(248,113,113,0.08)',
                  color: '#F87171',
                  cursor: 'pointer',
                  opacity:
                    !campaign ||
                      !['pending', 'running'].includes(campaign.status)
                      ? 0.4
                      : 1,
                }}
              >
                <AlertCircle size={12} />
                ABORT
              </button>
              <button
                onClick={async () => {
                  const confirm = window.confirm(
                    `DELETE campaign "${campaign.name}" permanently?\nThis CANNOT be undone.`
                  );
                  if (!confirm) return;

                  try {
                    await api.delete(`/campaigns/${campaign.id}`);
                    onClose();
                  } catch (err: any) {
                    alert(err?.message || 'Delete failed');
                  }
                }}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 6,
                  fontSize: 10,
                  fontWeight: 700,
                  padding: '6px 10px',
                  borderRadius: 6,
                  border: '1px solid rgba(239,68,68,0.4)',
                  background: 'rgba(239,68,68,0.12)',
                  color: '#EF4444',
                  cursor: 'pointer',
                }}
              >
                <Trash2 size={12} />
                DELETE
              </button>
            </div>
            <div className="vtl" style={{ paddingLeft: 32 }}>
              {campaign?.stages?.map((s: any) => (
                <div key={s.id} className="vtl-item" style={{ marginBottom: 28 }}>
                  <div className="vtl-dot" style={{
                    left: -26, width: 12, height: 12,
                    background:
                      s.status === 'done'
                        ? (inferStageSuccess(s) ? 'var(--low)' : 'var(--crit)')
                        : s.status === 'running' ? 'var(--amber)' : 'var(--cream-4)',
                    boxShadow: s.status === 'running' ? '0 0 0 4px var(--amber-p)' : 'none',
                    border: '2px solid var(--surf)',
                  }} />

                  <div style={{
                    fontWeight: 700, fontSize: 14,
                    color: s.status === 'pending' ? 'var(--char6)' : 'var(--char)',
                    letterSpacing: '-0.01em', marginBottom: 8,
                  }}>
                    {s.stage_name.replace(/_/g, ' ').toUpperCase()}
                  </div>

                  <StageBadges stage={s} />

                  {/* Show humanised result_json if done */}
                  {s.status === 'done' && s.result_json && (
                    <div style={{
                      marginTop: 8, fontSize: 11,
                      color: 'var(--char5)', lineHeight: 1.6,
                      fontFamily: 'var(--sans)',
                      whiteSpace: 'pre-line',
                    }}>
                      {humanizeDetail(s.result_json, s.stage_name)}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>

          {/* Right — live event stream */}
          <div style={{ display: 'flex', flexDirection: 'column', background: '#0D0C0B', overflow: 'hidden' }}>
            <div style={{
              padding: '16px 24px', background: 'rgba(255,255,255,0.03)',
              borderBottom: '1px solid rgba(255,255,255,0.08)',
              display: 'flex', justifyContent: 'space-between', alignItems: 'center',
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <Activity size={16} color="var(--amber)" />
                <span className="label" style={{ color: '#fff', opacity: 0.9, letterSpacing: '0.18em', fontWeight: 700 }}>
                  Operational Intelligence
                </span>
              </div>
              {campaign?.status === 'running' && (
                <div style={{
                  display: 'flex', alignItems: 'center', gap: 8, fontSize: 11,
                  color: '#4ADE80', fontWeight: 700,
                  background: 'rgba(74,222,128,0.08)', padding: '5px 12px',
                  borderRadius: 5, border: '1px solid rgba(74,222,128,0.18)',
                }}>
                  <div className="live-dot" style={{ background: '#4ADE80', width: 7, height: 7 }} />
                  LIVE TELEMETRY
                </div>
              )}
            </div>

            <div ref={scrollRef} style={{ flex: 1, overflowY: 'auto', padding: '20px 0', scrollBehavior: 'smooth' }}>
              {events.length === 0 ? (
                <div style={{ padding: 80, textAlign: 'center' }}>
                  <RefreshCw size={36} style={{ animation: 'spin 2s linear infinite', color: 'var(--char4)', marginBottom: 16 }} />
                  <div style={{ color: 'var(--char5)', fontFamily: 'var(--mono)', fontSize: 13, lineHeight: 1.9 }}>
                    [SYSTEM] Initiating Red Team handshake...<br />
                    [SYSTEM] Awaiting telemetry from execution engine.
                  </div>
                </div>
              ) : (
                events.map(ev => (
                  <div key={ev.id} style={{
                    padding: '14px 28px',
                    borderBottom: '1px solid rgba(255,255,255,0.04)',
                    animation: 'ai .4s ease',
                  }}>
                    {/* Top row: timestamp + action */}
                    <div style={{ display: 'flex', alignItems: 'center', gap: 16, marginBottom: 6 }}>
                      <span style={{ fontFamily: 'var(--mono)', fontSize: 11, color: 'rgba(255,255,255,0.3)', flexShrink: 0 }}>
                        {new Date(ev.timestamp).toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                      </span>
                      <span style={{
                        fontFamily: 'var(--mono)', fontSize: 11, fontWeight: 700,
                        letterSpacing: '0.08em',
                        color: ev.success ? '#4ADE80' : '#F87171',
                        flexShrink: 0,
                      }}>
                        {(ev.action || ev.stage || '').replace(/_/g, ' ').toUpperCase()}
                      </span>
                      <EventStatusBadges ev={ev} />
                    </div>

                    {/* Detail line */}
                    <div style={{
                      fontFamily: 'var(--mono)', fontSize: 12,
                      color: 'rgba(243,244,246,0.85)',
                      lineHeight: 1.7,
                      wordBreak: 'break-word',
                      whiteSpace: 'pre-line',
                    }}>
                      {(() => {
                        const stage = campaign?.stages?.find(
                          (s: any) =>
                            s.stage_name?.toLowerCase() ===
                            (ev.stage || ev.action || '').toLowerCase()
                        );

                        const raw = stage?.result_json ?? ev.detail;
                        return humanizeDetail(raw, stage?.stage_name);
                      })()}
                    </div>
                  </div>
                ))
              )}

              {campaign?.status === 'completed' && (
                <div style={{
                  padding: '32px 28px',
                  color: '#4ADE80', fontFamily: 'var(--mono)', fontSize: 13,
                  borderTop: '1px solid rgba(255,255,255,0.06)',
                  background: 'rgba(74,222,128,0.03)',
                }}>
                  [SYSTEM] End of line. All stages executed. Composite score finalized.<br />
                  [SYSTEM] Session closed at {new Date(campaign.completed_at).toLocaleString()}
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}


// ═══════════════════════════════════════════════════════════════════
// MAIN COMPONENT
// ═══════════════════════════════════════════════════════════════════

export function Campaigns() {
  const [campaigns, setCampaigns] = useState<any[]>([]);
  const [playbooks, setPlaybooks] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showModal, setShowModal] = useState(false);
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const [name, setName] = useState('');
  const [target, setTarget] = useState('');
  const [port, setPort] = useState(22);
  const [playbook, setPlaybook] = useState('default_apt');
  const [launching, setLaunching] = useState(false);

  const fetchCampaigns = async () => {
    try {
      const data = await api.get('/campaigns');
      setCampaigns(data);
      setError(null);
    } catch (err: any) {
      setError('Failed to load campaigns');
    } finally {
      setLoading(false);
    }
  };

  const fetchPlaybooks = async () => {
    try {
      const data = await api.get('/playbooks');
      setPlaybooks(data.playbooks || []);
      if (data.playbooks?.length > 0) setPlaybook(data.playbooks[0].name);
    } catch { /* ignore */ }
  };

  useEffect(() => {
    fetchCampaigns();
    fetchPlaybooks();
    const t = setInterval(fetchCampaigns, 5000);
    return () => clearInterval(t);
  }, []);

  const handleLaunch = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name || !target) return;
    setLaunching(true);
    try {
      const nc = await api.post('/campaigns', {
        name, target_host: target, target_port: port, playbook_name: playbook,
      });
      setShowModal(false);
      fetchCampaigns();
      setName(''); setTarget('');
      setSelectedId(nc.id);
    } catch (err: any) {
      alert(err.message || 'Failed to launch campaign');
    } finally {
      setLaunching(false);
    }
  };

  return (
    <div className="page-body">
      {/* Page header */}
      <div style={{ display: 'flex', alignItems: 'flex-end', justifyContent: 'space-between', marginBottom: 8 }}>
        <div>
          <div className="label" style={{ marginBottom: 4 }}>APT Management</div>
          <h1 className="serif" style={{ fontSize: 32, margin: 0 }}>Attack Campaigns</h1>
        </div>
        <div style={{ display: 'flex', gap: 10 }}>
          <button
            className="btn-primary"
            style={{ height: 40, display: 'flex', alignItems: 'center', gap: 8, background: 'transparent', color: 'var(--char3)', border: '1px solid var(--bdr)' }}
            onClick={fetchCampaigns}
            disabled={loading}
          >
            <RefreshCw size={16} /> Refresh
          </button>
          <button
            className="btn-amber"
            style={{ height: 40, display: 'flex', alignItems: 'center', gap: 8 }}
            onClick={() => setShowModal(true)}
          >
            <Play size={16} /> New Campaign
          </button>
        </div>
      </div>

      {error && (
        <div style={{
          padding: 20, background: 'var(--crit-bg)', border: '1px solid var(--crit-b)',
          borderRadius: 8, color: 'var(--crit)', display: 'flex', alignItems: 'center', gap: 10, marginBottom: 20,
        }}>
          <AlertCircle size={20} /> {error}
        </div>
      )}

      {/* Campaign cards */}
      {loading && campaigns.length === 0 ? (
        <div style={{ display: 'flex', justifyContent: 'center', padding: 100 }}>
          <div className="spinner" />
        </div>
      ) : campaigns.length === 0 ? (
        <div className="panel" style={{ padding: 60, textAlign: 'center' }}>
          <Target size={48} color="var(--cream-4)" style={{ marginBottom: 16 }} />
          <h3 className="serif" style={{ fontSize: 20, marginBottom: 8 }}>No Campaigns Found</h3>
          <p style={{ color: 'var(--char5)', maxWidth: 400, margin: '0 auto 24px' }}>
            Launch your first adversarial simulation to start gathering honeypot intelligence.
          </p>
          <button className="btn-amber" onClick={() => setShowModal(true)}>
            Launch Initial Campaign
          </button>
        </div>
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(400px, 1fr))', gap: 20 }}>
          {campaigns.map(c => {
            const done = c.stages?.filter((s: any) => s.status === 'done').length || 0;
            const total = c.stages?.length || 0;
            const pct = total ? (done / total) * 100 : 0;

            return (
              <div
                key={c.id}
                className="panel row-hover"
                style={{ cursor: 'pointer' }}
                onClick={() => setSelectedId(c.id)}
              >
                <div className="panel-hd">
                  <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                    <Target size={18} color="var(--amber)" />
                    <div style={{ fontWeight: 600 }}>{c.name}</div>
                  </div>
                  <div className={`chip ${c.status === 'running' ? 'chip-high' :
                    c.status === 'completed' ? 'chip-low' :
                      c.status === 'aborted' ? 'chip-critical' :
                        'chip-medium'}`}>
                    {c.status.toUpperCase()}
                  </div>
                </div>

                <div style={{ padding: 20 }}>
                  <div style={{ display: 'flex', gap: 10, marginBottom: 16, flexWrap: 'wrap' }}>
                    <div className="mitre-badge">Target: {c.target_host}</div>
                    <div className="chip chip-medium" style={{ border: 'none', background: 'var(--cream-3)' }}>
                      {c.playbook_name}
                    </div>
                  </div>

                  <div style={{ marginBottom: 18 }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11, marginBottom: 6 }}>
                      <span className="label">Stages</span>
                      <span style={{ fontWeight: 600 }}>{done} / {total}</span>
                    </div>
                    <div className="bar-track" style={{ height: 4 }}>
                      <div className="bar-fill" style={{ width: `${pct}%`, background: 'var(--amber)' }} />
                    </div>
                  </div>

                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderTop: '1px solid var(--bdr)', paddingTop: 14 }}>
                    <div style={{ display: 'flex', gap: 16 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11, color: 'var(--char5)' }}>
                        <Users size={13} /> Port {c.target_port}
                      </div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11, color: 'var(--char5)' }}>
                        <Clock size={13} /> {new Date(c.created_at).toLocaleDateString()}
                      </div>
                    </div>
                    <ChevronRight size={16} color="var(--char6)" />
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Launch modal */}
      {showModal && (
        <div style={{
          position: 'fixed', inset: 0,
          background: 'rgba(26,18,9,0.7)', backdropFilter: 'blur(4px)',
          zIndex: 1000, display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 20,
        }}>
          <div className="panel au" style={{ width: '100%', maxWidth: 500, background: 'var(--surf)' }}>
            <div className="panel-hd">
              <div style={{ fontWeight: 600, display: 'flex', alignItems: 'center', gap: 10 }}>
                <Play size={18} color="var(--amber)" /> Launch New Campaign
              </div>
              <button onClick={() => setShowModal(false)} style={{ background: 'none', border: 'none', color: 'var(--char6)', cursor: 'pointer' }}>
                <X size={20} />
              </button>
            </div>
            <form onSubmit={handleLaunch} style={{ padding: 24 }}>
              <div style={{ marginBottom: 18 }}>
                <label className="label" style={{ display: 'block', marginBottom: 8 }}>Campaign Name</label>
                <input className="hc-input" placeholder="e.g. Operation Nightfall" required value={name} onChange={e => setName(e.target.value)} />
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: 14, marginBottom: 18 }}>
                <div>
                  <label className="label" style={{ display: 'block', marginBottom: 8 }}>Target Host</label>
                  <input className="hc-input" placeholder="192.168.1.50" required value={target} onChange={e => setTarget(e.target.value)} />
                </div>
                <div>
                  <label className="label" style={{ display: 'block', marginBottom: 8 }}>Port</label>
                  <input className="hc-input" type="number" value={port} onChange={e => setPort(parseInt(e.target.value) || 22)} />
                </div>
              </div>
              <div style={{ marginBottom: 24 }}>
                <label className="label" style={{ display: 'block', marginBottom: 8 }}>Attack Playbook</label>
                <select className="hc-input" value={playbook} onChange={e => setPlaybook(e.target.value)}>
                  {playbooks.map(p => (
                    <option key={p.name} value={p.name}>
                      {p.name.replace(/_/g, ' ').replace(/\b\w/g, (c: string) => c.toUpperCase())}
                    </option>
                  ))}
                </select>
                <p style={{ fontSize: 11, color: 'var(--char6)', marginTop: 7 }}>
                  Playbooks define the attack stage sequence and timing behaviour.
                </p>
              </div>
              <div style={{ display: 'flex', gap: 12, justifyContent: 'flex-end' }}>
                <button
                  type="button" className="btn-primary"
                  style={{ background: 'transparent', color: 'var(--char3)', border: '1px solid var(--bdr)' }}
                  onClick={() => setShowModal(false)}
                >
                  Cancel
                </button>
                <button
                  type="submit" className="btn-amber" disabled={launching}
                  style={{ display: 'flex', alignItems: 'center', gap: 8 }}
                >
                  {launching ? <RefreshCw size={14} style={{ animation: 'spin 1s linear infinite' }} /> : <Play size={14} />}
                  {launching ? 'Launching...' : 'Commence Attack'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Details modal */}
      {selectedId && (
        <CampaignDetailsModal
          campaignId={selectedId}
          onClose={() => setSelectedId(null)}
        />
      )}
    </div>
  );
}