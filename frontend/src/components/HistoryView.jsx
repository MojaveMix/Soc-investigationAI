import React, { useState, useEffect } from 'react';
import { 
  History, 
  Search, 
  Trash2, 
  Eye, 
  RotateCw, 
  Calendar, 
  Cpu, 
  ShieldAlert,
  Flame
} from 'lucide-react';
import { api } from '../api';

export default function HistoryView({ onSelectInvestigation, refreshTrigger }) {
  const [investigations, setInvestigations] = useState([]);
  const [loading, setLoading] = useState(false);
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [search, setSearch] = useState('');
  const [total, setTotal] = useState(0);

  const fetchInvestigations = async () => {
    setLoading(true);
    try {
      const params = {};
      if (severityFilter !== 'ALL') params.severity = severityFilter;
      if (search) params.search = search;
      
      const res = await api.getInvestigations(params);
      setInvestigations(res.investigations || []);
      setTotal(res.total || 0);
    } catch (err) {
      console.error("Error loading investigations:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchInvestigations();
  }, [severityFilter, refreshTrigger]);

  const handleDelete = async (id, title) => {
    if (!window.confirm(`Delete investigation record "${title}"?`)) return;
    try {
      await api.deleteInvestigation(id);
      fetchInvestigations();
    } catch (err) {
      alert("Failed to delete: " + err.message);
    }
  };

  const getSeverityBadge = (severity) => {
    const s = (severity || 'MEDIUM').toUpperCase();
    switch (s) {
      case 'CRITICAL':
        return 'bg-rose-500/20 text-rose-400 border border-rose-500/40 danger-glow';
      case 'HIGH':
        return 'bg-amber-500/20 text-amber-400 border border-amber-500/40';
      case 'MEDIUM':
        return 'bg-yellow-500/20 text-yellow-300 border border-yellow-500/40';
      case 'LOW':
        return 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/40';
      default:
        return 'bg-sky-500/20 text-sky-400 border border-sky-500/40';
    }
  };

  return (
    <div className="space-y-6">
      
      <div className="bg-[#111726] border border-slate-800 rounded-xl p-5 shadow-xl">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 pb-3 mb-4 border-b border-slate-800">
          <div className="flex items-center space-x-2">
            <History className="w-5 h-5 text-sky-400" />
            <div>
              <h2 className="text-sm font-semibold text-white uppercase tracking-wider font-mono">
                Investigation Archive (MariaDB)
              </h2>
              <p className="text-xs text-slate-400">
                Persistent SOC triage cases and forensic reports ({total} total)
              </p>
            </div>
          </div>

          <button
            onClick={fetchInvestigations}
            disabled={loading}
            className="flex items-center space-x-1.5 text-xs text-slate-400 hover:text-slate-200 bg-slate-900 border border-slate-800 px-3 py-1.5 rounded-lg"
          >
            <RotateCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin text-sky-400' : ''}`} />
            <span>Refresh Archive</span>
          </button>
        </div>

        {/* Filter Controls */}
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 mb-4">
          <div className="relative">
            <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && fetchInvestigations()}
              placeholder="Search by title, attack summary, or log text..."
              className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-sky-500"
            />
          </div>

          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-300 focus:outline-none focus:border-sky-500"
          >
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">Critical Severity</option>
            <option value="HIGH">High Severity</option>
            <option value="MEDIUM">Medium Severity</option>
            <option value="LOW">Low Severity</option>
          </select>
        </div>

        {/* Investigations List */}
        {investigations.length > 0 ? (
          <div className="space-y-3">
            {investigations.map((inv) => (
              <div
                key={inv.id}
                className="bg-slate-900/80 border border-slate-800 hover:border-slate-700 rounded-xl p-4 transition-all flex flex-col md:flex-row items-start md:items-center justify-between gap-4"
              >
                <div className="space-y-1.5 flex-grow">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-xs font-mono font-bold text-sky-400">
                      #{inv.id}
                    </span>
                    <span className={`text-[10px] px-2 py-0.5 rounded font-bold uppercase tracking-wider ${getSeverityBadge(inv.severity)}`}>
                      {inv.severity}
                    </span>
                    <span className="text-[11px] font-mono text-slate-300 bg-slate-800 px-2 py-0.5 rounded">
                      Score: {inv.risk_score}/100
                    </span>
                    <span className="text-[11px] text-slate-400">
                      {inv.attack_stage || 'Execution'}
                    </span>
                    <span className="text-[11px] font-mono text-purple-400 bg-purple-950/40 px-2 py-0.5 rounded border border-purple-900/40">
                      {inv.model_used}
                    </span>
                  </div>

                  <h3 className="text-sm font-bold text-white hover:text-sky-300 cursor-pointer" onClick={() => onSelectInvestigation(inv)}>
                    {inv.title}
                  </h3>

                  <p className="text-xs text-slate-400 line-clamp-2">
                    {inv.summary || 'No summary available'}
                  </p>

                  <div className="flex items-center space-x-4 text-[11px] text-slate-500 pt-1 font-mono">
                    <span className="flex items-center space-x-1">
                      <Calendar className="w-3 h-3" />
                      <span>{new Date(inv.created_at).toLocaleString()}</span>
                    </span>
                    <span>
                      {inv.mitre_techniques?.length || 0} MITRE Techniques
                    </span>
                    <span>
                      {inv.iocs_detected?.length || 0} IOCs Extracted
                    </span>
                  </div>
                </div>

                <div className="flex items-center space-x-2 self-end md:self-auto flex-shrink-0">
                  <button
                    onClick={() => onSelectInvestigation(inv)}
                    className="flex items-center space-x-1.5 text-xs bg-sky-500/20 hover:bg-sky-500/30 text-sky-300 border border-sky-500/40 px-3 py-1.5 rounded-lg transition-colors font-medium"
                  >
                    <Eye className="w-3.5 h-3.5" />
                    <span>View Report</span>
                  </button>

                  <button
                    onClick={() => handleDelete(inv.id, inv.title)}
                    className="p-1.5 text-slate-500 hover:text-rose-400 bg-slate-800/80 hover:bg-slate-800 rounded-lg transition-colors"
                    title="Delete investigation"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="text-center py-12 text-slate-500 text-xs">
            No previous investigations found matching filters.
          </div>
        )}

      </div>

    </div>
  );
}
