import React, { useState, useEffect } from 'react';
import { 
  Search, 
  Copy, 
  Check, 
  Filter, 
  Database, 
  ExternalLink, 
  AlertTriangle,
  FileText,
  RotateCw,
  Globe,
  Hash,
  Shield,
  Key
} from 'lucide-react';
import { api } from '../api';

export default function IOCScannerView() {
  const [inputText, setInputText] = useState('');
  const [extractedIocs, setExtractedIocs] = useState([]);
  const [loading, setLoading] = useState(false);
  const [copiedIdx, setCopiedIdx] = useState(null);
  
  // Historical recorded IOCs from MariaDB
  const [recordedIocs, setRecordedIocs] = useState([]);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [filterType, setFilterType] = useState('ALL');
  const [filterThreat, setFilterThreat] = useState('ALL');
  const [searchHistory, setSearchHistory] = useState('');

  const handleExtract = async (e) => {
    if (e) e.preventDefault();
    if (!inputText.trim()) return;

    setLoading(true);
    try {
      const res = await api.extractIOCs(inputText);
      setExtractedIocs(res.iocs || []);
    } catch (err) {
      console.error("IOC Extraction error:", err);
    } finally {
      setLoading(false);
    }
  };

  const loadRecordedIocs = async () => {
    setHistoryLoading(true);
    try {
      const params = {};
      if (filterType !== 'ALL') params.type = filterType;
      if (filterThreat !== 'ALL') params.threat_level = filterThreat;
      if (searchHistory) params.search = searchHistory;

      const res = await api.getRecordedIOCs(params);
      setRecordedIocs(res.iocs || []);
    } catch (err) {
      console.error("Error loading recorded IOCs:", err);
    } finally {
      setHistoryLoading(false);
    }
  };

  useEffect(() => {
    loadRecordedIocs();
  }, [filterType, filterThreat]);

  const copyToClipboard = (text, idx) => {
    navigator.clipboard.writeText(text);
    setCopiedIdx(idx);
    setTimeout(() => setCopiedIdx(null), 2000);
  };

  const getThreatBadge = (threat) => {
    const t = (threat || 'Suspicious').toLowerCase();
    if (t.includes('malicious') || t.includes('high')) {
      return 'bg-rose-500/20 text-rose-400 border border-rose-500/30';
    }
    if (t.includes('critical')) {
      return 'bg-purple-500/20 text-purple-400 border border-purple-500/30';
    }
    if (t.includes('suspicious')) {
      return 'bg-amber-500/20 text-amber-400 border border-amber-500/30';
    }
    return 'bg-slate-800 text-slate-400 border border-slate-700';
  };

  return (
    <div className="space-y-6">
      
      {/* Quick Extractor Card */}
      <div className="bg-[#111726] border border-slate-800 rounded-xl p-5 shadow-xl">
        <div className="flex items-center justify-between pb-3 mb-4 border-b border-slate-800">
          <div className="flex items-center space-x-2">
            <Search className="w-5 h-5 text-sky-400" />
            <h2 className="text-sm font-semibold text-white uppercase tracking-wider font-mono">
              Direct IOC Extractor & Threat Parser
            </h2>
          </div>
          <span className="text-xs text-slate-400">
            Instant Regex & Artifact Classifier
          </span>
        </div>

        <form onSubmit={handleExtract} className="space-y-3">
          <div>
            <textarea
              rows={4}
              value={inputText}
              onChange={(e) => setInputText(e.target.value)}
              placeholder="Paste raw firewall logs, email headers, script snippets, or mixed IOC lists (IPs, URLs, Hashes, CVEs)..."
              className="w-full bg-slate-950 border border-slate-800 rounded-lg p-3 text-xs font-mono text-slate-200 focus:outline-none focus:border-sky-500/80"
            />
          </div>

          <div className="flex items-center justify-between">
            <button
              type="button"
              onClick={() => {
                setInputText(
                  "Incident involving remote C2 at 185.220.101.5 and backup domain update-service.xyz port 8443.\n" +
                  "Attacker used certutil.exe to download payload from http://malicious-gateway.top/svchost.exe\n" +
                  "SHA256: 8b1a9953c4611296a827abf8c47804d7ecd3ee19a2e6f47702bf92147ff3a339\n" +
                  "Exploited vulnerability CVE-2021-44228 on host 10.0.0.45, modified registry HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
                );
              }}
              className="text-xs text-slate-400 hover:text-slate-200"
            >
              Insert Sample Text
            </button>

            <button
              type="submit"
              disabled={loading || !inputText.trim()}
              className="flex items-center space-x-2 px-4 py-2 bg-sky-500 hover:bg-sky-400 disabled:bg-slate-800 disabled:text-slate-500 text-white rounded-lg text-xs font-semibold tracking-wide transition-all shadow-md shadow-sky-500/20"
            >
              {loading ? (
                <>
                  <RotateCw className="w-3.5 h-3.5 animate-spin text-sky-400" />
                  <span>Extracting...</span>
                </>
              ) : (
                <>
                  <Search className="w-3.5 h-3.5" />
                  <span>Extract & Classify IOCs</span>
                </>
              )}
            </button>
          </div>
        </form>

        {/* Extracted IOCs Table */}
        {extractedIocs.length > 0 && (
          <div className="mt-5 pt-4 border-t border-slate-800">
            <h3 className="text-xs font-semibold text-white uppercase tracking-wider font-mono mb-3">
              Identified Technical Artifacts ({extractedIocs.length})
            </h3>
            
            <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5">
              {extractedIocs.map((ioc, idx) => (
                <div
                  key={idx}
                  className="flex items-center justify-between p-2.5 bg-slate-900/90 border border-slate-800 rounded-lg text-xs"
                >
                  <div className="flex items-center space-x-2 overflow-hidden pr-2">
                    <span className="px-1.5 py-0.5 bg-slate-800 text-slate-300 text-[10px] font-mono rounded flex-shrink-0">
                      {ioc.type}
                    </span>
                    <div className="truncate">
                      <span className="font-mono text-slate-200 select-all block truncate">
                        {ioc.value}
                      </span>
                      <span className="text-[10px] text-slate-500 block truncate">
                        {ioc.context}
                      </span>
                    </div>
                  </div>

                  <div className="flex items-center space-x-2 flex-shrink-0">
                    <span className={`text-[10px] px-1.5 py-0.5 rounded font-semibold ${getThreatBadge(ioc.threat_level)}`}>
                      {ioc.threat_level}
                    </span>
                    <button
                      onClick={() => copyToClipboard(ioc.value, `ext_${idx}`)}
                      className="p-1 text-slate-400 hover:text-white bg-slate-800 rounded"
                    >
                      {copiedIdx === `ext_${idx}` ? (
                        <Check className="w-3.5 h-3.5 text-emerald-400" />
                      ) : (
                        <Copy className="w-3.5 h-3.5" />
                      )}
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Historical Recorded IOCs Database */}
      <div className="bg-[#111726] border border-slate-800 rounded-xl p-5 shadow-xl">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 pb-3 mb-4 border-b border-slate-800">
          <div className="flex items-center space-x-2">
            <Database className="w-5 h-5 text-emerald-400" />
            <div>
              <h2 className="text-sm font-semibold text-white uppercase tracking-wider font-mono">
                MariaDB Threat Intelligence Store
              </h2>
              <p className="text-xs text-slate-400">
                Persistent IOC records accumulated from all investigations
              </p>
            </div>
          </div>

          <button
            onClick={loadRecordedIocs}
            disabled={historyLoading}
            className="flex items-center space-x-1.5 text-xs text-slate-400 hover:text-slate-200 bg-slate-900 border border-slate-800 px-2.5 py-1.5 rounded-lg"
          >
            <RotateCw className={`w-3.5 h-3.5 ${historyLoading ? 'animate-spin text-sky-400' : ''}`} />
            <span>Refresh</span>
          </button>
        </div>

        {/* Filter Controls */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 mb-4">
          <input
            type="text"
            value={searchHistory}
            onChange={(e) => setSearchHistory(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && loadRecordedIocs()}
            placeholder="Search IOC value or notes..."
            className="bg-slate-900 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-sky-500"
          />

          <select
            value={filterType}
            onChange={(e) => setFilterType(e.target.value)}
            className="bg-slate-900 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-sky-500"
          >
            <option value="ALL">All Indicator Types</option>
            <option value="IPv4">IPv4 Addresses</option>
            <option value="Domain">Domains</option>
            <option value="URL">URLs</option>
            <option value="Hash">Hashes (SHA256/MD5)</option>
            <option value="CVE">CVEs</option>
            <option value="Registry">Registry Keys</option>
          </select>

          <select
            value={filterThreat}
            onChange={(e) => setFilterThreat(e.target.value)}
            className="bg-slate-900 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-sky-500"
          >
            <option value="ALL">All Threat Levels</option>
            <option value="Malicious">Malicious Only</option>
            <option value="Critical">Critical</option>
            <option value="Suspicious">Suspicious</option>
            <option value="Contextual">Contextual</option>
          </select>
        </div>

        {/* Table of IOC Records */}
        <div className="overflow-x-auto max-h-[400px] overflow-y-auto">
          {recordedIocs.length > 0 ? (
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-900/80 text-slate-400 font-mono uppercase text-[10px] sticky top-0 border-b border-slate-800">
                <tr>
                  <th className="py-2.5 px-3">Type</th>
                  <th className="py-2.5 px-3">Indicator Value</th>
                  <th className="py-2.5 px-3">Threat Assessment</th>
                  <th className="py-2.5 px-3">Investigation Reference</th>
                  <th className="py-2.5 px-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-mono">
                {recordedIocs.map((rec, idx) => (
                  <tr key={rec.id || idx} className="hover:bg-slate-800/30 transition-colors">
                    <td className="py-2.5 px-3">
                      <span className="px-1.5 py-0.5 bg-slate-800 text-slate-300 text-[10px] rounded border border-slate-700">
                        {rec.ioc_type}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 text-slate-200 select-all max-w-[240px] truncate">
                      {rec.value}
                    </td>
                    <td className="py-2.5 px-3">
                      <span className={`text-[10px] px-2 py-0.5 rounded font-semibold ${getThreatBadge(rec.threat_level)}`}>
                        {rec.threat_level}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 text-slate-400 text-[11px]">
                      {rec.investigation_id ? (
                        <span className="text-sky-400">Inv #{rec.investigation_id}</span>
                      ) : (
                        <span className="text-slate-500">Standalone</span>
                      )}
                    </td>
                    <td className="py-2.5 px-3 text-right">
                      <button
                        onClick={() => copyToClipboard(rec.value, `rec_${idx}`)}
                        className="p-1 text-slate-400 hover:text-white bg-slate-800 rounded inline-flex items-center"
                        title="Copy Indicator"
                      >
                        {copiedIdx === `rec_${idx}` ? (
                          <Check className="w-3.5 h-3.5 text-emerald-400" />
                        ) : (
                          <Copy className="w-3.5 h-3.5" />
                        )}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <div className="text-center py-10 text-slate-500 text-xs">
              No IOC records found in MariaDB. Run an investigation to automatically record indicators.
            </div>
          )}
        </div>
      </div>

    </div>
  );
}
