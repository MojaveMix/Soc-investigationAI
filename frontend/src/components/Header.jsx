import React from 'react';
import { 
  Shield, 
  Cpu, 
  Database, 
  Layers, 
  Search, 
  FileText, 
  History, 
  Activity,
  AlertTriangle,
  CheckCircle2,
  XCircle
} from 'lucide-react';

export default function Header({ 
  activeTab, 
  setActiveTab, 
  health, 
  models, 
  selectedModel, 
  setSelectedModel 
}) {
  const isDbOnline = health?.mariadb?.status === 'connected';
  const isOllamaOnline = health?.ollama?.available === true;
  const chromaCount = health?.chromadb?.total_documents ?? 0;

  return (
    <header className="bg-[#0f1422] border-b border-slate-800 sticky top-0 z-50 shadow-lg">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          
          {/* Logo & Platform Info */}
          <div className="flex items-center space-x-3">
            <div className="p-2 bg-sky-500/10 border border-sky-500/30 rounded-lg flex items-center justify-center text-sky-400 radar-glow">
              <Shield className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="font-bold text-lg text-white tracking-wide font-mono">SecuRAG AI</span>
                <span className="bg-sky-500/20 text-sky-300 text-[10px] font-semibold px-2 py-0.5 rounded border border-sky-500/30 tracking-wider">
                  SOC TIER-3
                </span>
              </div>
              <p className="text-xs text-slate-400 hidden sm:block">
                Local AI Cybersecurity Investigation & MITRE ATT&CK Mapping
              </p>
            </div>
          </div>

          {/* System Telemetry & Model Switcher */}
          <div className="flex items-center space-x-4">
            
            {/* Health Pills */}
            <div className="hidden lg:flex items-center space-x-2 bg-slate-900/80 px-3 py-1.5 rounded-lg border border-slate-800 text-xs font-mono">
              {/* MariaDB status */}
              <div className="flex items-center space-x-1.5" title="Database: MariaDB / MySQL">
                <Database className="w-3.5 h-3.5 text-slate-400" />
                <span className="text-slate-300">MariaDB:</span>
                {isDbOnline ? (
                  <span className="flex items-center text-emerald-400">
                    <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 mr-1 animate-pulse"></span>
                    Ready
                  </span>
                ) : (
                  <span className="text-rose-400 flex items-center">
                    <XCircle className="w-3 h-3 mr-0.5" /> Off
                  </span>
                )}
              </div>

              <span className="text-slate-700">|</span>

              {/* Ollama status */}
              <div className="flex items-center space-x-1.5" title="Local LLM: Ollama">
                <Cpu className="w-3.5 h-3.5 text-slate-400" />
                <span className="text-slate-300">Ollama:</span>
                {isOllamaOnline ? (
                  <span className="flex items-center text-emerald-400">
                    <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 mr-1 animate-pulse"></span>
                    Online
                  </span>
                ) : (
                  <span className="text-rose-400 flex items-center">
                    <XCircle className="w-3 h-3 mr-0.5" /> Off
                  </span>
                )}
              </div>

              <span className="text-slate-700">|</span>

              {/* ChromaDB RAG */}
              <div className="flex items-center space-x-1.5" title="ChromaDB RAG Vector Store">
                <Layers className="w-3.5 h-3.5 text-sky-400" />
                <span className="text-slate-300">RAG:</span>
                <span className="text-sky-300 font-semibold">{chromaCount} rules</span>
              </div>
            </div>

            {/* Model Selector Dropdown */}
            <div className="flex items-center space-x-2">
              <label htmlFor="model-select" className="text-xs text-slate-400 hidden md:block">
                AI Engine:
              </label>
              <select
                id="model-select"
                value={selectedModel}
                onChange={(e) => setSelectedModel(e.target.value)}
                className="bg-slate-900 border border-slate-700 text-sky-300 text-xs rounded-lg px-2.5 py-1.5 focus:ring-1 focus:ring-sky-500 focus:border-sky-500 outline-none font-mono"
              >
                <option value="qwen3.5:9b">qwen3.5:9b (Main Analysis)</option>
                <option value="Qwen3:8b">Qwen3:8b (Fast Triage)</option>
                <option value="gemma3:12b">gemma3:12b (Deep Report)</option>
              </select>
            </div>

          </div>
        </div>

        {/* Tab Navigation */}
        <div className="flex space-x-1 overflow-x-auto py-2 border-t border-slate-800/80">
          <button
            onClick={() => setActiveTab('investigation')}
            className={`flex items-center space-x-2 px-3.5 py-1.5 rounded-md text-xs font-medium transition-all ${
              activeTab === 'investigation'
                ? 'bg-sky-500/20 text-sky-300 border border-sky-500/40 shadow-sm'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
            }`}
          >
            <Shield className="w-3.5 h-3.5" />
            <span>Alert Triage & Investigation</span>
          </button>

          <button
            onClick={() => setActiveTab('ioc')}
            className={`flex items-center space-x-2 px-3.5 py-1.5 rounded-md text-xs font-medium transition-all ${
              activeTab === 'ioc'
                ? 'bg-sky-500/20 text-sky-300 border border-sky-500/40 shadow-sm'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
            }`}
          >
            <Search className="w-3.5 h-3.5" />
            <span>IOC Extractor & Threat Intel</span>
          </button>

          <button
            onClick={() => setActiveTab('knowledge')}
            className={`flex items-center space-x-2 px-3.5 py-1.5 rounded-md text-xs font-medium transition-all ${
              activeTab === 'knowledge'
                ? 'bg-sky-500/20 text-sky-300 border border-sky-500/40 shadow-sm'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
            }`}
          >
            <Layers className="w-3.5 h-3.5" />
            <span>MITRE ATT&CK & CVE Explorer (RAG)</span>
          </button>

          <button
            onClick={() => setActiveTab('history')}
            className={`flex items-center space-x-2 px-3.5 py-1.5 rounded-md text-xs font-medium transition-all ${
              activeTab === 'history'
                ? 'bg-sky-500/20 text-sky-300 border border-sky-500/40 shadow-sm'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
            }`}
          >
            <History className="w-3.5 h-3.5" />
            <span>Past Investigations</span>
            {health?.metrics?.total_investigations > 0 && (
              <span className="ml-1 px-1.5 py-0.2 bg-slate-800 text-slate-300 rounded text-[10px]">
                {health.metrics.total_investigations}
              </span>
            )}
          </button>
        </div>

      </div>
    </header>
  );
}
