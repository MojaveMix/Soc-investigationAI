import React, { useState, useEffect } from 'react';
import Header from './components/Header';
import InvestigationView from './components/InvestigationView';
import IOCScannerView from './components/IOCScannerView';
import KnowledgeExplorerView from './components/KnowledgeExplorerView';
import HistoryView from './components/HistoryView';
import { api } from './api';

export default function App() {
  const [activeTab, setActiveTab] = useState('investigation');
  const [health, setHealth] = useState(null);
  const [models, setModels] = useState([]);
  const [selectedModel, setSelectedModel] = useState('qwen3.5:9b');
  const [currentInvestigation, setCurrentInvestigation] = useState(null);
  const [historyRefreshKey, setHistoryRefreshKey] = useState(0);

  // Poll system health on mount and periodically
  const fetchSystemStatus = () => {
    api.getHealth()
      .then(data => setHealth(data))
      .catch(err => console.error("Health check error:", err));

    api.getModels()
      .then(data => {
        setModels(data.configured_profiles || []);
        if (data.default_model && !selectedModel) {
          setSelectedModel(data.default_model);
        }
      })
      .catch(err => console.error("Models fetch error:", err));
  };

  useEffect(() => {
    fetchSystemStatus();
    const interval = setInterval(fetchSystemStatus, 15000);
    return () => clearInterval(interval);
  }, []);

  const handleInvestigationCompleted = (newInvestigation) => {
    setCurrentInvestigation(newInvestigation);
    setHistoryRefreshKey(prev => prev + 1);
    fetchSystemStatus();
  };

  const handleSelectFromHistory = (inv) => {
    setCurrentInvestigation(inv);
    setActiveTab('investigation');
  };

  return (
    <div className="min-h-screen bg-[#0a0d14] text-slate-100 flex flex-col font-sans selection:bg-sky-500 selection:text-white">
      {/* Top Header */}
      <Header
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        health={health}
        models={models}
        selectedModel={selectedModel}
        setSelectedModel={setSelectedModel}
      />

      {/* Main Container */}
      <main className="flex-grow max-w-7xl mx-auto w-full px-4 sm:px-6 lg:px-8 py-6">
        {activeTab === 'investigation' && (
          <InvestigationView
            selectedModel={selectedModel}
            onInvestigationComplete={handleInvestigationCompleted}
            currentInvestigation={currentInvestigation}
            setCurrentInvestigation={setCurrentInvestigation}
          />
        )}

        {activeTab === 'ioc' && (
          <IOCScannerView />
        )}

        {activeTab === 'knowledge' && (
          <KnowledgeExplorerView />
        )}

        {activeTab === 'history' && (
          <HistoryView
            onSelectInvestigation={handleSelectFromHistory}
            refreshTrigger={historyRefreshKey}
          />
        )}
      </main>

      {/* Footer Bar */}
      <footer className="bg-[#0f1422] border-t border-slate-800/80 py-3 text-center text-xs text-slate-500 font-mono">
        <div className="max-w-7xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-2">
          <div className="flex items-center space-x-2">
            <span className="w-2 h-2 rounded-full bg-emerald-400"></span>
            <span>SecuRAG AI • Local Autonomous SOC Intelligence</span>
          </div>
          <div className="flex items-center space-x-4 text-[11px]">
            <span>ChromaDB Vector Store</span>
            <span>•</span>
            <span>Ollama (qwen3.5:9b / Qwen3:8b / gemma3:12b)</span>
            <span>•</span>
            <span>MariaDB (securag_db)</span>
          </div>
        </div>
      </footer>
    </div>
  );
}
