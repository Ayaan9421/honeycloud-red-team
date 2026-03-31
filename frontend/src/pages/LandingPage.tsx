import React, { useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Box, Brain, Zap, Globe, Link as LinkIcon, BarChart3,
  ArrowRight, Shield, ShieldCheck, Cpu, Fingerprint,
  Target, Activity, Layers, Search, Code, Lock
} from 'lucide-react';

import logo from '../assets/honeycloud.png';

const TAGLINES = [
  'Modern attackers don’t just break systems — they study them.',
  'Reverse the dynamic. Attack your own defenses.',
  'Fingerprint. Scan. Exploit. Evaluate.',
  'The ultimate testing ground for adversarial honeypots.'
];

const LOAD_LABELS = [
  'Initializing research core...',
  'Mapping honeypot topology...',
  'Loading exploit databases...',
  'Adversarial Engine Ready.'
];

const PROBLEM_STATEMENT = {
  headline: "Modern attackers don’t just break systems — they study them.",
  description: "Traditional honeypots are no longer enough. Sophisticated attackers can now detect decoys, avoid traps, and adapt their behavior in real-time. This system reverses this dynamic: it actively attacks honeypots to test their resilience."
};

const PIPELINE = [
  { step: 'Fingerprint', desc: 'Identify whether a system is a real service or a decoy.', icon: <Fingerprint size={24} /> },
  { step: 'Scan', desc: 'Analyze service behavior, ports, and responses.', icon: <Search size={24} /> },
  { step: 'Exploit', desc: 'Trigger vulnerabilities to test honeypot depth.', icon: <Code size={24} /> },
  { step: 'Trigger', desc: 'Simulate high-fidelity APT-style interactions.', icon: <Zap size={24} /> },
  { step: 'Evaluate', desc: 'Measure detection rate and deception quality.', icon: <BarChart3 size={24} /> }
];

const OBJECTIVES = [
  {
    title: 'Honeypot Detection & Fingerprinting',
    desc: 'Identify whether a system is a real service or a decoy by analyzing service behavior, ports, and responses.',
    icon: <Fingerprint size={32} />
  },
  {
    title: 'Evasive Attack Strategies',
    desc: 'Simulate attackers that avoid honeypot traps using stealth scanning and adaptive probing techniques.',
    icon: <Shield size={32} />
  },
  {
    title: 'Automated Attack Tool Testing',
    desc: 'Run tools like Nmap and exploit pipelines to measure how honeypots respond to real-world attack tools.',
    icon: <Cpu size={32} />
  },
  {
    title: 'APT Scenario Simulation',
    desc: 'Execute multi-stage attack flows from recon to persistence to mimic real-world attacker behavior.',
    icon: <Target size={32} />
  },
  {
    title: 'Honeypot Effectiveness Evaluation',
    desc: 'Measure detection rates and evaluate deception quality across different attack vectors using ML-driven scoring.',
    icon: <ShieldCheck size={32} />
  }
];

// ─── Canvas Rain (Reused from temp_landing) ───────────────────
function Rain() {
  const ref = useRef<HTMLCanvasElement>(null);
  useEffect(() => {
    const c = ref.current; if (!c) return;
    const ctx = c.getContext('2d')!;
    const resize = () => { c.width = c.offsetWidth; c.height = c.offsetHeight; };
    resize(); window.addEventListener('resize', resize);
    const cols = Math.floor(c.width / 22);
    const drops = Array.from({ length: cols }, () => Math.random() * -40);
    const chars = '01アイウエカキ∞∂◈⬡░▒';
    const id = setInterval(() => {
      ctx.fillStyle = 'rgba(253, 250, 243, 0.15)'; ctx.fillRect(0, 0, c.width, c.height);
      for (let i = 0; i < drops.length; i++) {
        const x = i * 22, y = drops[i] * 22;
        if (drops[i] > 0) {
          ctx.fillStyle = 'rgba(232,150,12,0.8)'; ctx.font = '11px DM Mono'; ctx.fillText(chars[Math.floor(Math.random() * chars.length)], x, y);
        }
        if (drops[i] > 3) {
          ctx.fillStyle = 'rgba(179,139,90,0.16)'; ctx.font = '10px DM Mono'; ctx.fillText(chars[Math.floor(Math.random() * chars.length)], x, y - 22);
        }
        if (y > c.height && Math.random() > 0.974) drops[i] = 0;
        drops[i] += 0.4;
      }
    }, 55);
    return () => { clearInterval(id); window.removeEventListener('resize', resize); };
  }, []);
  return <canvas ref={ref} style={{ position: 'absolute', inset: 0, width: '100%', height: '100%', opacity: .45, pointerEvents: 'none' }} />;
}

export function LandingPage() {
  const navigate = useNavigate();
  const [tagIdx, setIdx] = useState(0);
  const [tagVis, setVis] = useState(true);
  const [loaderDone, setLDone] = useState(false);
  const [loadStep, setLStep] = useState(0);

  useEffect(() => {
    const steps = [0, 1, 2, 3].map((i) =>
      setTimeout(() => setLStep(i), i * 480)
    );
    const done = setTimeout(() => {
      setLDone(true);
      const el = document.getElementById('page-loader');
      if (el) el.classList.add('done');
    }, 2000);
    return () => { steps.forEach(clearTimeout); clearTimeout(done); };
  }, []);

  useEffect(() => {
    const t = setInterval(() => {
      setVis(false);
      setTimeout(() => { setIdx(i => (i + 1) % TAGLINES.length); setVis(true); }, 350);
    }, 3200);
    return () => clearInterval(t);
  }, []);

  return (
    <>
      {/* ── Page loader ── */}
      <div id="page-loader">
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 16 }}>
          <div className="ld-hex">
            <img src={logo} style={{ width: 100, height: 100, objectFit: 'cover', animation: 'ld-spin 2s ease-in-out infinite' }} alt="HoneyCloud Logo" />
          </div>
          <div className="ld-word">HoneyCloud <span style={{ fontStyle: 'italic', color: 'red' }}>RedTeam</span></div>
          <div className="ld-sub">Adversarial Honeypot Framework</div>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 10 }}>
          <div className="ld-bar-wrap"><div className="ld-bar" /></div>
          <div className="ld-status">{LOAD_LABELS[loadStep]}</div>
        </div>
      </div>

      <div className="land-root" style={{ visibility: loaderDone ? 'visible' : 'hidden', background: 'var(--cream)', color: 'var(--char)' }}>

        {/* ── Sticky nav ── */}
        <nav style={{ position: 'sticky', top: 0, zIndex: 100, background: 'rgba(253, 250, 243, 0.92)', borderBottom: '1px solid var(--bdr)', backdropFilter: 'blur(16px)', height: 64, display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '0 48px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <img src={logo} style={{ width: 70, height: 70, objectFit: 'cover' }} alt="Logo" />
            <div style={{ fontFamily: 'var(--serif)', fontSize: 22, color: 'var(--char)', fontWeight: 600, letterSpacing: '-.01em' }}>
              HoneyCloud <span style={{ color: 'red', fontStyle: 'italic' }}>RedTeam</span>
            </div>
          </div>
          <div style={{ display: 'flex', gap: 10 }}>
            <button className="btn-outline" onClick={() => navigate('/dashboard')} style={{ padding: '8px 24px', fontSize: 13, borderColor: 'var(--bdr2)', color: 'var(--char)' }}>Dashboard</button>
            <button className="btn-amber" onClick={() => navigate('/dashboard')} style={{ padding: '8px 24px', fontSize: 13 }}>Launch Assessment <ArrowRight size={14} style={{ marginLeft: 4, display: 'inline' }} /></button>
          </div>
        </nav>

        {/* ── HERO ── */}
        <section className="land-section" style={{ minHeight: '90vh', display: 'flex', alignItems: 'center', overflow: 'hidden', position: 'relative' }}>
          <Rain />
          <div className="land-grid-bg" style={{ backgroundImage: 'linear-gradient(rgba(0,0,0,.03) 1px, transparent 1px), linear-gradient(90deg, rgba(0,0,0,.03) 1px, transparent 1px)' }} />

          <div style={{ position: 'relative', zIndex: 2, maxWidth: 1300, margin: '0 auto', width: '100%', padding: '80px 48px', display: 'grid', gridTemplateColumns: '1.2fr 1fr', gap: 80, alignItems: 'center' }}>
            <div className="au">
              <div style={{ display: 'inline-flex', alignItems: 'center', gap: 8, padding: '5px 14px', background: 'var(--amber-p)', border: '1px solid rgba(232,150,12,.2)', borderRadius: 99, marginBottom: 32 }}>
                <div className="live-dot amber" style={{ width: 5, height: 5 }} />
                <span style={{ fontFamily: 'var(--mono)', fontSize: 9, color: 'var(--amber)', fontWeight: 600, letterSpacing: '.2em' }}>ACTIVE RESEARCH PHASE</span>
              </div>

              <h1 style={{ fontFamily: 'var(--serif)', fontSize: 'clamp(52px, 6vw, 82px)', lineHeight: .97, letterSpacing: '-.02em', color: 'var(--char)', marginBottom: 12 }}>
                Attack your decoys.<br />
                <span style={{ fontStyle: 'italic', color: 'var(--amber)' }}>Verify your deception.</span>
              </h1>

              <div style={{ height: 26, overflow: 'hidden', marginBottom: 28 }}>
                <p style={{ fontFamily: 'var(--mono)', fontSize: 15, color: 'var(--char5)', margin: 0, letterSpacing: '.04em', opacity: tagVis ? 1 : 0, transform: `translateY(${tagVis ? 0 : -8}px)`, transition: 'opacity .3s, transform .3s' }}>
                  {TAGLINES[tagIdx]}
                </p>
              </div>

              <p style={{ fontFamily: 'var(--sans)', fontSize: 16, color: 'var(--char4)', lineHeight: 1.75, maxWidth: 520, marginBottom: 48, fontWeight: 400 }}>
                This platform launches controlled, intelligent attacks against honeypots to evaluate how well they deceive real attackers. Fingerprint services, find CVEs, and score detection quality.
              </p>

              <div style={{ display: 'flex', gap: 12 }}>
                <button className="btn-amber" onClick={() => navigate('/dashboard')} style={{ padding: '14px 32px', fontSize: 14 }}>
                  Enter Research Dashboard <ArrowRight size={16} style={{ marginLeft: 6, display: 'inline' }} />
                </button>
                <button className="btn-outline" style={{ padding: '13px 24px', fontSize: 14, borderColor: 'var(--bdr2)', color: 'var(--char)' }}>
                  Read Methodology
                </button>
              </div>
            </div>

            <div className="au d2" style={{ position: 'relative' }}>
              <div style={{ background: 'var(--char)', border: '1px solid var(--char2)', borderRadius: 12, overflow: 'hidden', boxShadow: '0 24px 48px rgba(0,0,0,.25)' }}>
                <div style={{ padding: '12px 16px', borderBottom: '1px solid rgba(255,255,255,.05)', display: 'flex', alignItems: 'center', justifyContent: 'space-between', background: 'rgba(255,255,255,.03)' }}>
                  <div style={{ display: 'flex', gap: 6 }}>
                    {['#FF5F57', '#FFBD2E', '#28C840'].map(c => <div key={c} style={{ width: 9, height: 9, borderRadius: '50%', background: c }} />)}
                  </div>
                  <span style={{ fontFamily: 'var(--mono)', fontSize: 9, color: 'var(--char5)' }}>adversarial-engine — evaluation-mode</span>
                  <div className="live-dot" />
                </div>
                <div style={{ padding: '20px', fontFamily: 'var(--mono)', fontSize: 12, color: 'var(--cream-4)', lineHeight: 1.5 }}>
                  <div style={{ color: 'var(--amber)' }}>[SYSTEM] Initiating scan: target=192.168.1.50</div>
                  <div>[SCAN] Fingerprinting service on port 22...</div>
                  <div style={{ color: 'var(--low)' }}>[RESULT] Service identified: OpenSSH 8.2p1 (Cowrie Decoy)</div>
                  <div>[EXPLOIT] Matching CVEs from NVD... Found 3 candidates.</div>
                  <div>[ATTACK] Launching CVE-2023-38408 simulation...</div>
                  <div style={{ color: 'var(--amber)' }}>[ALERT] Honeypot triggered. Logging detection response.</div>
                  <div style={{ color: 'var(--high)' }}>[SCORE] Deception Quality: 84% (High)</div>
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* ── WHY THIS SYSTEM EXISTS ── */}
        <section style={{ padding: '120px 48px', background: 'var(--surf2)', borderTop: '1px solid var(--bdr)' }}>
          <div style={{ maxWidth: 1000, margin: '0 auto' }}>
            <div className="au" style={{ textAlign: 'center', marginBottom: 60 }}>
              <div style={{ fontFamily: 'var(--mono)', fontSize: 10, color: 'var(--amber)', fontWeight: 600, letterSpacing: '.2em', textTransform: 'uppercase', marginBottom: 20 }}>Research Focus</div>
              <h2 style={{ fontFamily: 'var(--serif)', fontSize: 'clamp(32px, 4vw, 54px)', color: 'var(--char)', letterSpacing: '-.02em', lineHeight: 1.1 }}>
                {PROBLEM_STATEMENT.headline}
              </h2>
              <p style={{ fontFamily: 'var(--sans)', fontSize: 18, color: 'var(--char4)', lineHeight: 1.6, maxWidth: 800, margin: '32px auto 0' }}>
                {PROBLEM_STATEMENT.description}
              </p>
            </div>

            <div className="au d2" style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 24, marginTop: 80 }}>
              <div className="feature-card" style={{ background: 'var(--surf)' }}>
                <Lock size={28} color="var(--amber)" style={{ marginBottom: 16 }} />
                <div className="serif" style={{ fontSize: 20, marginBottom: 12, fontWeight: 600 }}>Decoy Detection</div>
                <div style={{ fontSize: 14, color: 'var(--char5)' }}>Attackers use sophisticated timing attacks to distinguish virtual honeypots from bare-metal servers.</div>
              </div>
              <div className="feature-card" style={{ background: 'var(--surf)' }}>
                <Activity size={28} color="var(--amber)" style={{ marginBottom: 16 }} />
                <div className="serif" style={{ fontSize: 20, marginBottom: 12, fontWeight: 600 }}>Adaptive Behavior</div>
                <div style={{ fontSize: 14, color: 'var(--char5)' }}>Modern malware probes honeypot depth. If the interaction is shallow, the attacker immediately disconnects.</div>
              </div>
              <div className="feature-card" style={{ background: 'var(--surf)' }}>
                <Globe size={28} color="var(--amber)" style={{ marginBottom: 16 }} />
                <div className="serif" style={{ fontSize: 20, marginBottom: 12, fontWeight: 600 }}>Anti-Honeypot Intel</div>
                <div style={{ fontSize: 14, color: 'var(--char5)' }}>Public databases list known honeypot IP ranges, making traditional static decoys useless in days.</div>
              </div>
            </div>
          </div>
        </section>

        {/* ── WHAT THIS PLATFORM DOES ── */}
        <section style={{ padding: '120px 48px', background: 'var(--cream)' }}>
          <div style={{ maxWidth: 1100, margin: '0 auto' }}>
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', textAlign: 'center' }}>
              <div style={{ fontFamily: 'var(--mono)', fontSize: 10, color: 'var(--amber)', fontWeight: 600, letterSpacing: '.2em', textTransform: 'uppercase', marginBottom: 20 }}>The Solution</div>
              <h2 style={{ fontFamily: 'var(--serif)', fontSize: 'clamp(28px, 3.5vw, 48px)', color: 'var(--char)', letterSpacing: '-.02em', marginBottom: 28 }}>
                Launch controlled, intelligent attacks to<br />
                <span style={{ fontStyle: 'italic', color: 'var(--amber)' }}>evaluate how well you deceive.</span>
              </h2>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 80, position: 'relative' }}>
              <div style={{ position: 'absolute', top: 40, left: 50, right: 50, height: 1, background: 'var(--bdr)', zIndex: 0 }} />
              {PIPELINE.map((p, i) => (
                <div key={p.step} className="au" style={{ animationDelay: `${i * 0.1}s`, width: 180, display: 'flex', flexDirection: 'column', alignItems: 'center', zIndex: 1 }}>
                  <div style={{ width: 80, height: 80, borderRadius: '50%', background: 'var(--surf)', border: '1px solid var(--bdr)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--amber)', marginBottom: 20, boxShadow: '0 4px 12px rgba(0,0,0,0.05)' }}>
                    {p.icon}
                  </div>
                  <div className="serif" style={{ fontSize: 18, fontWeight: 600, marginBottom: 8 }}>{p.step}</div>
                  <div style={{ fontSize: 12, color: 'var(--char5)', textAlign: 'center' }}>{p.desc}</div>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* ── KEY OBJECTIVES ── */}
        <section style={{ padding: '120px 48px', background: 'var(--surf2)', borderTop: '1px solid var(--bdr)' }}>
          <div style={{ maxWidth: 1200, margin: '0 auto' }}>
            <div style={{ marginBottom: 80 }}>
              <div style={{ fontFamily: 'var(--mono)', fontSize: 10, color: 'var(--amber)', fontWeight: 600, letterSpacing: '.2em', textTransform: 'uppercase', marginBottom: 20 }}>Research Objectives</div>
              <h2 style={{ fontFamily: 'var(--serif)', fontSize: 'clamp(28px, 3.5vw, 48px)', color: 'var(--char)', letterSpacing: '-.02em', lineHeight: 1.05 }}>
                Measuring Deception<br />
                <span style={{ fontStyle: 'italic', color: 'var(--amber)' }}>in an adversarial environment.</span>
              </h2>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(350px, 1fr))', gap: 24 }}>
              {OBJECTIVES.map((obj, i) => (
                <div key={obj.title} className="feature-card au" style={{ animationDelay: `${i * 0.1}s`, background: 'var(--surf)', border: '1px solid var(--bdr)', padding: 40 }}>
                  <div style={{ color: 'var(--amber)', marginBottom: 24 }}>{obj.icon}</div>
                  <div className="serif" style={{ fontSize: 24, color: 'var(--char)', marginBottom: 16, fontWeight: 600 }}>{obj.title}</div>
                  <p style={{ fontSize: 15, color: 'var(--char4)', lineHeight: 1.6 }}>{obj.desc}</p>
                  <div style={{ marginTop: 24, display: 'flex', gap: 8 }}>
                    <span className="chip chip-low" style={{ textTransform: 'uppercase' }}>Research Grade</span>
                    <span className="chip chip-medium" style={{ textTransform: 'uppercase' }}>APT Scenario</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* ── CTA ── */}
        <section style={{ padding: '140px 48px', textAlign: 'center', position: 'relative', overflow: 'hidden' }}>
          <div style={{ position: 'absolute', top: '50%', left: '50%', transform: 'translate(-50%,-50%)', width: 800, height: 400, background: 'radial-gradient(ellipse, rgba(232,150,12,.1) 0%, transparent 65%)', pointerEvents: 'none' }} />
          <div style={{ position: 'relative', zIndex: 1, maxWidth: 640, margin: '0 auto' }}>
            <div style={{ fontFamily: 'var(--mono)', fontSize: 10, color: 'var(--amber)', fontWeight: 600, letterSpacing: '.2em', textTransform: 'uppercase', marginBottom: 24 }}>Start Your Assessment</div>
            <h2 style={{ fontFamily: 'var(--serif)', fontSize: 'clamp(42px, 5.5vw, 68px)', color: 'var(--char)', letterSpacing: '-.02em', marginBottom: 28, lineHeight: 1.05 }}>
              Test your defenses<br />
              <span style={{ fontStyle: 'italic', color: 'var(--amber)' }}>at scale.</span>
            </h2>
            <div style={{ display: 'flex', gap: 16, justifyContent: 'center', marginTop: 40 }}>
              <button className="btn-amber" onClick={() => navigate('/dashboard')} style={{ padding: '16px 48px', fontSize: 15 }}>Enter the Platform <ArrowRight size={18} style={{ marginLeft: 8, display: 'inline' }} /></button>
            </div>
          </div>
        </section>

        {/* ── Footer ── */}
        <footer style={{ borderTop: '1px solid var(--bdr)', padding: '32px 48px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: 'var(--surf)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
            <img src={logo} style={{ width: 80, height: 80, objectFit: 'cover' }} alt="Logo" />
            <span style={{ fontFamily: 'var(--mono)', fontSize: 11, color: 'var(--char5)', fontWeight: 500 }}>HoneyCloud RedTeam — Adversarial Research Framework</span>
          </div>
          <span style={{ fontFamily: 'var(--mono)', fontSize: 11, color: 'var(--char5)', opacity: .7 }}>MITRE ATT&CK Alignment · NVD CVE Mapping · ML Deception Scoring</span>
        </footer>
      </div>
    </>
  );
}
