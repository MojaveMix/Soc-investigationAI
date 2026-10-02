import React, { useState, useEffect } from 'react';
import { 
  BookOpen, 
  Search, 
  Layers, 
  ExternalLink, 
  RotateCw, 
  PlusCircle, 
  Database, 
  ShieldCheck, 
  Cpu, 
  Check, 
  Sparkles,
  AlertCircle
} from 'lucide-react';
import { api } from '../api';

export default function KnowledgeExplorerView() {
  const [query, setQuery] = useState('');
  const [framework, setFramework] = useState('');
  const [results, setResults] = useState([]);
  const [loading, setLoading] = useState(false);
  const [stats, setStats] = useState(null);
  const [reindexing, setReindexing] = useState(false);
  const [showAddModal, setShowAddModal] = useState(false);
  
  // Custom knowledge form
  const [newFramework, setNewFramework] = useState('MITRE ATT&CK');
  const [newTechniqueId, setNewTechniqueId] = useState('');
  const [newName, setNewName] = useState('');
  const [newCategory, setNewCategory] = useState('');
  const [newDescription, setNewDescription] = useState('');
  const [newDetection, setNewDetection] = useState('');
  const [addSuccess, setAddSuccess] = useState(false);

  const fetchStats = () => {
    api.getKnowledgeStats()
      .then(data => setStats(data))
      .catch(err => console.error("Error loading RAG stats:", err));
  };

  const handleSearch = async (e) => {
    if (e) e.preventDefault();
    setLoading(true);
    try {
      const res = await api.searchKnowledge(query, framework || undefined, 12);
      setResults(res.results || []);
    } catch (err) {
      console.error("Knowledge search error:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchStats();
    handleSearch();
  }, [framework]);

  const handleReindex = async () => {
    if (!window.confirm("Do you want to re-embed and index all cybersecurity seed documents into ChromaDB?")) return;
    setReindexing(true);
    try {
      await api.reindexKnowledge();
      fetchStats();
      handleSearch();
    } catch (err) {
      alert("Reindex failed: " + err.message);
    } finally {
      setReindexing(false);
    }
  };

  const handleAddCustom = async (e) => {
    e.preventDefault();
    try {
      await api.addCustomKnowledge({
        framework: newFramework,
        technique_id: newTechniqueId,
        name: newName,
        category: newCategory,
        description: newDescription,
        detection_remediation: newDetection
      });
      setAddSuccess(true);
      setTimeout(() => {
        setAddSuccess(false);
        setShowAddModal(false);
        setNewTechniqueId('');
        setNewName('');
        setNewDescription('');
        setNewDetection('');
        fetchStats();
        handleSearch();
      }, 1200);
    } catch (err) {
      alert("Failed to add entry: " + err.message);
    }
  };

  return (
    <div className="space-y-6">
      
      {/* Top Telemetry & Search Card */}
      <div className="bg-[#111726] border border-slate-800 rounded-xl p-5 shadow-xl">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 pb-4 mb-4 border-b border-slate-800">
          <div className="flex items-center space-x-2">
            <Layers className="w-5 h-5 text-sky-400" />
            <div>
              <h2 className="text-sm font-semibold text-white uppercase tracking-wider font-mono">
                ChromaDB Vector Knowledge Base (RAG)
              </h2>
              <p className="text-xs text-slate-400">
                Vector-indexed MITRE ATT&CK techniques, OWASP Top 10, and high-impact CVEs
              </p>
            </div>
          </div>

          <div className="flex items-center space-x-2">
            <button
              onClick={() => setShowAddModal(true)}
              className="flex items-center space-x-1.5 text-xs bg-sky-500/20 hover:bg-sky-500/30 text-sky-300 border border-sky-500/40 px-3 py-1.5 rounded-lg transition-colors"
            >
              <PlusCircle className="w-3.5 h-3.5" />
              <span>Add Custom Rule</span>
            </button>

            <button
              onClick={handleReindex}
              disabled={reindexing}
              className="flex items-center space-x-1.5 text-xs bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-300 px-3 py-1.5 rounded-lg transition-colors"
              title="Force rebuild ChromaDB collection from seed dataset"
            >
              <RotateCw className={`w-3.5 h-3.5 ${reindexing ? 'animate-spin text-sky-400' : ''}`} />
              <span>{reindexing ? 'Re-indexing...' : 'Re-index RAG'}</span>
            </button>
          </div>
        </div>

        {/* Stats Row */}
        {stats && (
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-5">
            <div className="bg-slate-900/80 p-3 rounded-lg border border-slate-800/80">
              <span className="text-[10px] text-slate-400 uppercase tracking-wider block font-mono">Total Documents</span>
              <span className="text-lg font-bold text-sky-400 font-mono">{stats.total_documents}</span>
            </div>
            <div className="bg-slate-900/80 p-3 rounded-lg border border-slate-800/80">
              <span className="text-[10px] text-slate-400 uppercase tracking-wider block font-mono">MITRE ATT&CK</span>
              <span className="text-lg font-bold text-rose-400 font-mono">{stats.frameworks?.['MITRE ATT&CK'] || 0}</span>
            </div>
            <div className="bg-slate-900/80 p-3 rounded-lg border border-slate-800/80">
              <span className="text-[10px] text-slate-400 uppercase tracking-wider block font-mono">CVE Knowledge</span>
              <span className="text-lg font-bold text-purple-400 font-mono">{stats.frameworks?.['CVE Knowledge'] || 0}</span>
            </div>
            <div className="bg-slate-900/80 p-3 rounded-lg border border-slate-800/80">
              <span className="text-[10px] text-slate-400 uppercase tracking-wider block font-mono">Embedding Model</span>
              <span className="text-xs font-semibold text-emerald-400 font-mono block mt-1">{stats.embedding_model}</span>
            </div>
          </div>
        )}

        {/* Search Input Bar */}
        <form onSubmit={handleRunSearch => handleSearch()} className="flex flex-col sm:flex-row gap-2">
          <div className="relative flex-grow">
            <Search className="w-4 h-4 text-slate-500 absolute left-3 top-3" />
            <input
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Ask RAG (e.g., 'LSASS credential dumping', 'T1486 ransomware', 'Log4Shell JNDI exploit', 'SQL Injection')..."
              className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-4 py-2.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-sky-500"
            />
          </div>

          <div className="flex gap-2">
            <select
              value={framework}
              onChange={(e) => setFramework(e.target.value)}
              className="bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-300 focus:outline-none focus:border-sky-500"
            >
              <option value="">All Frameworks</option>
              <option value="MITRE ATT&CK">MITRE ATT&CK</option>
              <option value="OWASP Top 10">OWASP Top 10</option>
              <option value="CVE Knowledge">CVE Knowledge</option>
            </select>

            <button
              type="button"
              onClick={handleSearch}
              disabled={loading}
              className="px-4 py-2 bg-sky-500 hover:bg-sky-400 text-white rounded-lg text-xs font-semibold tracking-wide flex items-center space-x-1.5 shadow-md shadow-sky-500/20"
            >
              {loading ? (
                <RotateCw className="w-3.5 h-3.5 animate-spin" />
              ) : (
                <Search className="w-3.5 h-3.5" />
              )}
              <span>Query RAG</span>
            </button>
          </div>
        </form>
      </div>

      {/* Results Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {results.map((item, idx) => {
          const meta = item.metadata || {};
          const isMitre = meta.framework === 'MITRE ATT&CK';
          const isCve = meta.framework === 'CVE Knowledge';

          return (
            <div
              key={item.id || idx}
              className="bg-[#111726] border border-slate-800 hover:border-slate-700 rounded-xl p-4 shadow-lg flex flex-col justify-between transition-all"
            >
              <div>
                {/* Header */}
                <div className="flex items-center justify-between mb-2">
                  <span className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold border ${
                    isMitre 
                      ? 'bg-rose-500/20 text-rose-300 border-rose-500/30'
                      : isCve
                      ? 'bg-purple-500/20 text-purple-300 border-purple-500/30'
                      : 'bg-amber-500/20 text-amber-300 border-amber-500/30'
                  }`}>
                    {meta.technique_id || 'ID'}
                  </span>

                  {item.similarity_score !== undefined && (
                    <span className="text-[10px] font-mono text-emerald-400 bg-emerald-950/40 px-2 py-0.5 rounded border border-emerald-900/40">
                      {Math.round(item.similarity_score * 100)}% Match
                    </span>
                  )}
                </div>

                <h3 className="text-xs font-bold text-white mb-1">
                  {meta.name || 'Untitled Technique'}
                </h3>
                <span className="text-[10px] uppercase font-mono text-slate-400 block mb-2">
                  {meta.framework} • {meta.category || 'General'}
                </span>

                <p className="text-xs text-slate-300 leading-relaxed mb-3 line-clamp-4">
                  {item.content?.split('\nDescription: ')[1]?.split('\nDetection & Remediation:')[0] || item.content}
                </p>
              </div>

              {/* Footer / Links */}
              <div className="pt-2 border-t border-slate-800 flex items-center justify-between text-[11px]">
                {isMitre && (
                  <a
                    href={`https://attack.mitre.org/techniques/${meta.technique_id?.replace('.', '/')}`}
                    target="_blank"
                    rel="noreferrer"
                    className="text-sky-400 hover:text-sky-300 flex items-center space-x-1"
                  >
                    <span>View on MITRE</span>
                    <ExternalLink className="w-3 h-3" />
                  </a>
                )}
                {isCve && (
                  <a
                    href={`https://nvd.nist.gov/vuln/detail/${meta.technique_id}`}
                    target="_blank"
                    rel="noreferrer"
                    className="text-purple-400 hover:text-purple-300 flex items-center space-x-1"
                  >
                    <span>NVD Vulnerability</span>
                    <ExternalLink className="w-3 h-3" />
                  </a>
                )}
                <span className="text-[10px] text-slate-500 font-mono">
                  Vector Store: ChromaDB
                </span>
              </div>
            </div>
          );
        })}
      </div>

      {results.length === 0 && !loading && (
        <div className="bg-[#111726] border border-slate-800 rounded-xl p-12 text-center text-slate-500 text-xs">
          No matching knowledge items found in ChromaDB. Try searching for "PowerShell", "Ransomware", "CVE", or clear filters.
        </div>
      )}

      {/* Add Custom Rule Modal */}
      {showAddModal && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-[#111726] border border-slate-800 rounded-xl max-w-lg w-full p-6 shadow-2xl space-y-4">
            <h3 className="text-sm font-bold text-white font-mono uppercase tracking-wider">
              Add Custom SOC Knowledge / Playbook Rule
            </h3>

            {addSuccess ? (
              <div className="p-4 bg-emerald-500/10 border border-emerald-500/30 rounded-lg text-emerald-400 text-xs flex items-center space-x-2">
                <Check className="w-4 h-4" />
                <span>Successfully embedded & indexed into ChromaDB!</span>
              </div>
            ) : (
              <form onSubmit={handleAddCustom} className="space-y-3">
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="block text-[11px] text-slate-400 mb-1">Framework</label>
                    <select
                      value={newFramework}
                      onChange={(e) => setNewFramework(e.target.value)}
                      className="w-full bg-slate-900 border border-slate-800 rounded-lg p-2 text-xs text-white"
                    >
                      <option value="MITRE ATT&CK">MITRE ATT&CK</option>
                      <option value="OWASP Top 10">OWASP Top 10</option>
                      <option value="CVE Knowledge">CVE Knowledge</option>
                      <option value="Internal SOC Playbook">Internal SOC Playbook</option>
                    </select>
                  </div>

                  <div>
                    <label className="block text-[11px] text-slate-400 mb-1">ID (e.g. T1059.009 or PLAY-01)</label>
                    <input
                      type="text"
                      required
                      value={newTechniqueId}
                      onChange={(e) => setNewTechniqueId(e.target.value)}
                      placeholder="e.g., T1059.009"
                      className="w-full bg-slate-900 border border-slate-800 rounded-lg p-2 text-xs text-white"
                    />
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="block text-[11px] text-slate-400 mb-1">Rule / Technique Name</label>
                    <input
                      type="text"
                      required
                      value={newName}
                      onChange={(e) => setNewName(e.target.value)}
                      placeholder="e.g., Cloud Token Theft via IMDS"
                      className="w-full bg-slate-900 border border-slate-800 rounded-lg p-2 text-xs text-white"
                    />
                  </div>

                  <div>
                    <label className="block text-[11px] text-slate-400 mb-1">Category / Tactic</label>
                    <input
                      type="text"
                      value={newCategory}
                      onChange={(e) => setNewCategory(e.target.value)}
                      placeholder="e.g., Credential Access"
                      className="w-full bg-slate-900 border border-slate-800 rounded-lg p-2 text-xs text-white"
                    />
                  </div>
                </div>

                <div>
                  <label className="block text-[11px] text-slate-400 mb-1">Detailed Description</label>
                  <textarea
                    rows={3}
                    required
                    value={newDescription}
                    onChange={(e) => setNewDescription(e.target.value)}
                    placeholder="Adversary technique mechanisms, behaviors, and impact..."
                    className="w-full bg-slate-900 border border-slate-800 rounded-lg p-2 text-xs text-white font-mono"
                  />
                </div>

                <div>
                  <label className="block text-[11px] text-slate-400 mb-1">Detection Logic & Remediation Playbook</label>
                  <textarea
                    rows={3}
                    value={newDetection}
                    onChange={(e) => setNewDetection(e.target.value)}
                    placeholder="SIEM detection query, Event IDs, and recommended containment steps..."
                    className="w-full bg-slate-900 border border-slate-800 rounded-lg p-2 text-xs text-white font-mono"
                  />
                </div>

                <div className="flex justify-end space-x-2 pt-2">
                  <button
                    type="button"
                    onClick={() => setShowAddModal(false)}
                    className="px-3 py-1.5 text-xs text-slate-400 hover:text-white bg-slate-900 rounded-lg"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    className="px-4 py-1.5 text-xs font-semibold bg-sky-500 hover:bg-sky-400 text-white rounded-lg shadow-md shadow-sky-500/20"
                  >
                    Embed & Save to ChromaDB
                  </button>
                </div>
              </form>
            )}
          </div>
        </div>
      )}

    </div>
  );
}
