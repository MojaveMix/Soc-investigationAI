import React, { useMemo } from 'react';
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, Legend, RadialBarChart, RadialBar
} from 'recharts';
import { BarChart2, ShieldAlert, Activity, Target } from 'lucide-react';

// ─── Colour palettes ───────────────────────────────────────────────────────────
const IOC_COLORS = {
  IPv4:     '#38bdf8',
  Domain:   '#818cf8',
  URL:      '#f472b6',
  Hash:     '#fb923c',
  CVE:      '#a3e635',
  Registry: '#34d399',
  Other:    '#94a3b8',
};

const THREAT_COLORS = {
  Critical:   '#a855f7',
  Malicious:  '#f43f5e',
  'High Risk':'#f97316',
  Suspicious: '#eab308',
  Contextual: '#22d3ee',
  Unknown:    '#64748b',
};

const TACTIC_COLORS = [
  '#38bdf8','#818cf8','#f472b6','#fb923c','#a3e635',
  '#34d399','#f43f5e','#a855f7','#22d3ee','#eab308',
];

// ─── Tooltip styles ────────────────────────────────────────────────────────────
const TooltipBox = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null;
  return (
    <div className="bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs shadow-xl">
      {label && <p className="text-slate-400 font-mono mb-1">{label}</p>}
      {payload.map((p, i) => (
        <p key={i} style={{ color: p.color || p.fill }} className="font-semibold">
          {p.name}: {p.value}
        </p>
      ))}
    </div>
  );
};

// ─── Risk Gauge ────────────────────────────────────────────────────────────────
function RiskGauge({ score }) {
  const color = score >= 80 ? '#f43f5e' : score >= 60 ? '#f97316' : score >= 40 ? '#eab308' : '#22d3ee';
  const data = [
    { name: 'Risk', value: score, fill: color },
    { name: 'Safe', value: 100 - score, fill: '#1e293b' },
  ];
  return (
    <div className="flex flex-col items-center">
      <ResponsiveContainer width="100%" height={140}>
        <RadialBarChart
          cx="50%" cy="80%"
          innerRadius="60%" outerRadius="100%"
          startAngle={180} endAngle={0}
          data={data}
          barSize={18}
        >
          <RadialBar dataKey="value" cornerRadius={6} background={{ fill: '#1e293b' }} />
        </RadialBarChart>
      </ResponsiveContainer>
      <div className="-mt-10 text-center">
        <span className="text-3xl font-bold font-mono" style={{ color }}>{score}</span>
        <span className="block text-[10px] uppercase text-slate-400 tracking-widest mt-0.5">Risk Score</span>
      </div>
    </div>
  );
}

// ─── Main Panel ────────────────────────────────────────────────────────────────
export default function StatisticsPanel({ investigation }) {
  const { iocs_detected = [], mitre_techniques = [], risk_score = 0, severity } = investigation;

  // IOC type distribution
  const iocTypeData = useMemo(() => {
    const counts = {};
    iocs_detected.forEach(ioc => {
      const t = ioc.type || 'Other';
      counts[t] = (counts[t] || 0) + 1;
    });
    return Object.entries(counts).map(([name, value]) => ({ name, value }));
  }, [iocs_detected]);

  // Threat level distribution
  const threatData = useMemo(() => {
    const counts = {};
    iocs_detected.forEach(ioc => {
      const t = ioc.threat_level || 'Unknown';
      counts[t] = (counts[t] || 0) + 1;
    });
    return Object.entries(counts).map(([name, value]) => ({ name, value }));
  }, [iocs_detected]);

  // MITRE tactic frequency
  const tacticData = useMemo(() => {
    const counts = {};
    mitre_techniques.forEach(t => {
      const tactic = t.tactic || 'Unknown';
      counts[tactic] = (counts[tactic] || 0) + 1;
    });
    return Object.entries(counts)
      .map(([name, count]) => ({ name, count }))
      .sort((a, b) => b.count - a.count);
  }, [mitre_techniques]);

  const hasData = iocs_detected.length > 0 || mitre_techniques.length > 0;
  if (!hasData) return null;

  return (
    <div className="bg-[#111726] border border-slate-800 rounded-xl p-5 shadow-xl">
      {/* Header */}
      <div className="flex items-center space-x-2 pb-3 mb-5 border-b border-slate-800">
        <BarChart2 className="w-4 h-4 text-sky-400" />
        <h3 className="text-xs font-semibold text-white uppercase tracking-wider font-mono">
          Investigation Statistics &amp; Threat Analytics
        </h3>
        <span className="ml-auto text-[11px] text-slate-500">
          {iocs_detected.length} IOCs · {mitre_techniques.length} Techniques
        </span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-5">

        {/* 1 — Risk Gauge */}
        <div className="bg-slate-900/70 border border-slate-800 rounded-lg p-4 flex flex-col">
          <div className="flex items-center space-x-1.5 mb-2">
            <Activity className="w-3.5 h-3.5 text-rose-400" />
            <span className="text-[10px] uppercase tracking-widest font-mono text-slate-400">Risk Gauge</span>
          </div>
          <RiskGauge score={risk_score} />
          <div className="text-center mt-2">
            <span className={`text-[11px] font-bold px-2 py-0.5 rounded uppercase tracking-wide ${
              severity === 'CRITICAL' ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30' :
              severity === 'HIGH'     ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30' :
              severity === 'MEDIUM'   ? 'bg-yellow-500/20 text-yellow-300 border border-yellow-500/30' :
                                       'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
            }`}>{severity} Severity</span>
          </div>
        </div>

        {/* 2 — IOC Type Breakdown (Bar) */}
        {iocTypeData.length > 0 && (
          <div className="bg-slate-900/70 border border-slate-800 rounded-lg p-4 flex flex-col">
            <div className="flex items-center space-x-1.5 mb-3">
              <ShieldAlert className="w-3.5 h-3.5 text-amber-400" />
              <span className="text-[10px] uppercase tracking-widest font-mono text-slate-400">IOC Type Breakdown</span>
            </div>
            <ResponsiveContainer width="100%" height={170}>
              <BarChart data={iocTypeData} layout="vertical" margin={{ left: 0, right: 10 }}>
                <XAxis type="number" tick={{ fontSize: 10, fill: '#94a3b8' }} allowDecimals={false} />
                <YAxis type="category" dataKey="name" tick={{ fontSize: 10, fill: '#cbd5e1' }} width={68} />
                <Tooltip content={<TooltipBox />} />
                <Bar dataKey="value" radius={[0, 4, 4, 0]}>
                  {iocTypeData.map((entry, i) => (
                    <Cell key={i} fill={IOC_COLORS[entry.name] || '#94a3b8'} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        )}

        {/* 3 — Threat Level Donut */}
        {threatData.length > 0 && (
          <div className="bg-slate-900/70 border border-slate-800 rounded-lg p-4 flex flex-col">
            <div className="flex items-center space-x-1.5 mb-3">
              <Target className="w-3.5 h-3.5 text-rose-400" />
              <span className="text-[10px] uppercase tracking-widest font-mono text-slate-400">Threat Distribution</span>
            </div>
            <ResponsiveContainer width="100%" height={170}>
              <PieChart>
                <Pie
                  data={threatData}
                  dataKey="value"
                  nameKey="name"
                  cx="50%" cy="50%"
                  innerRadius="48%"
                  outerRadius="72%"
                  paddingAngle={3}
                >
                  {threatData.map((entry, i) => (
                    <Cell key={i} fill={THREAT_COLORS[entry.name] || TACTIC_COLORS[i % TACTIC_COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip content={<TooltipBox />} />
                <Legend
                  iconType="circle"
                  iconSize={8}
                  formatter={(val) => <span style={{ fontSize: 10, color: '#cbd5e1' }}>{val}</span>}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
        )}

        {/* 4 — MITRE Tactic Frequency */}
        {tacticData.length > 0 && (
          <div className="bg-slate-900/70 border border-slate-800 rounded-lg p-4 flex flex-col">
            <div className="flex items-center space-x-1.5 mb-3">
              <BarChart2 className="w-3.5 h-3.5 text-purple-400" />
              <span className="text-[10px] uppercase tracking-widest font-mono text-slate-400">MITRE Tactic Hits</span>
            </div>
            <ResponsiveContainer width="100%" height={170}>
              <BarChart data={tacticData} margin={{ left: -10, right: 10, bottom: 30 }}>
                <XAxis
                  dataKey="name"
                  tick={{ fontSize: 9, fill: '#94a3b8' }}
                  angle={-35}
                  textAnchor="end"
                  interval={0}
                />
                <YAxis tick={{ fontSize: 10, fill: '#94a3b8' }} allowDecimals={false} />
                <Tooltip content={<TooltipBox />} />
                <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                  {tacticData.map((_, i) => (
                    <Cell key={i} fill={TACTIC_COLORS[i % TACTIC_COLORS.length]} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        )}

      </div>

      {/* Summary stat pills */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mt-5">
        {[
          { label: 'Total IOCs', value: iocs_detected.length, color: 'text-sky-400' },
          { label: 'Malicious / Critical', value: iocs_detected.filter(i => ['Malicious','Critical','High Risk'].includes(i.threat_level)).length, color: 'text-rose-400' },
          { label: 'MITRE Techniques', value: mitre_techniques.length, color: 'text-purple-400' },
          { label: 'ATT&CK Tactics', value: tacticData.length, color: 'text-amber-400' },
        ].map((s, i) => (
          <div key={i} className="bg-slate-950/60 border border-slate-800 rounded-lg px-4 py-3 text-center">
            <div className={`text-2xl font-bold font-mono ${s.color}`}>{s.value}</div>
            <div className="text-[10px] uppercase tracking-wide text-slate-500 mt-0.5">{s.label}</div>
          </div>
        ))}
      </div>
    </div>
  );
}
