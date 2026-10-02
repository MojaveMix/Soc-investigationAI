import React, { useState, useEffect, useRef } from 'react';
import { 
  ShieldAlert, 
  Terminal, 
  Play, 
  RotateCw, 
  Copy, 
  Check, 
  Download, 
  ExternalLink, 
  AlertCircle, 
  CheckCircle2, 
  Flame, 
  Crosshair, 
  FileCode, 
  Cpu, 
  Sparkles,
  Search,
  ListFilter,
  Upload,
  FileUp,
  FileText,
  X
} from 'lucide-react';
import { api } from '../api';
import StatisticsPanel from './StatisticsPanel';
import { generateInvestigationPDF } from './pdfReportGenerator';

export default function InvestigationView({ 
  selectedModel, 
  onInvestigationComplete,
  currentInvestigation,
  setCurrentInvestigation 
}) {
  const [presets, setPresets] = useState([]);
  const [selectedPresetId, setSelectedPresetId] = useState('');
  const [title, setTitle] = useState('');
  const [alertType, setAlertType] = useState('Endpoint / EDR Alert');
  const [rawInput, setRawInput] = useState('');
  const [model, setModel] = useState(selectedModel);
  const [loading, setLoading] = useState(false);
  const [loadingStep, setLoadingStep] = useState('');
  const [error, setError] = useState(null);
  const [copiedQuery, setCopiedQuery] = useState(null);
  const [copiedIoc, setCopiedIoc] = useState(null);
  const [checkedActions, setCheckedActions] = useState({});
  const [activeHuntingTab, setActiveHuntingTab] = useState('kql');
  const [pdfLoading, setPdfLoading] = useState(false);

  // File Upload State
  const [uploadedFile, setUploadedFile] = useState(null);
  const [isDragging, setIsDragging] = useState(false);
  const fileInputRef = useRef(null);

  useEffect(() => {
    setModel(selectedModel);
  }, [selectedModel]);

  // Load presets on mount
  useEffect(() => {
    api.getPresets()
      .then(data => {
        setPresets(data);
        if (data.length > 0 && !rawInput && !currentInvestigation) {
          // Pre-load first preset as demo
          applyPreset(data[0]);
        }
      })
      .catch(err => console.error("Error loading presets:", err));
  }, []);

  const applyPreset = (preset) => {
    setSelectedPresetId(preset.id);
    setTitle(preset.title);
    setAlertType(preset.alert_type);
    setRawInput(preset.raw_input);
    setUploadedFile(null);
    if (preset.recommended_model) {
      setModel(preset.recommended_model);
    }
  };

  const handleFileProcess = (file) => {
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (e) => {
      const content = e.target.result;
      const lineCount = content.split('\n').length;

      setRawInput(content);
      setUploadedFile({
        name: file.name,
        size: file.size,
        lines: lineCount,
      });

      // Auto-populate Title if empty or default
      if (!title || title.startsWith("Log Investigation:")) {
        setTitle(`Log Investigation: ${file.name}`);
      }

      // Heuristic category detection from file name and content
      const lowerName = file.name.toLowerCase();
      const lowerContent = content.substring(0, 1000).toLowerCase();

      if (lowerName.endsWith('.json') || lowerContent.includes('"eventid"') || lowerContent.includes('"sysmon"')) {
        setAlertType('SIEM / Sysmon Detection');
      } else if (lowerName.includes('access') || lowerName.includes('nginx') || lowerName.includes('apache') || lowerName.includes('waf')) {
        setAlertType('WAF / Web Application');
      } else if (lowerName.includes('suricata') || lowerName.includes('snort') || lowerName.includes('firewall') || lowerName.includes('pcap')) {
        setAlertType('Network / Firewall Alert');
      } else if (lowerName.includes('mail') || lowerName.includes('phish') || lowerName.includes('eml')) {
        setAlertType('Email Gateway / Phishing');
      } else if (lowerName.includes('auth') || lowerName.includes('ad') || lowerName.includes('dc')) {
        setAlertType('Active Directory / Identity');
      }

      setError(null);
    };

    reader.onerror = () => {
      setError(`Failed to read file "${file.name}".`);
    };

    reader.readAsText(file);
  };

  const handleFileInputChange = (e) => {
    const file = e.target.files?.[0];
    if (file) {
      handleFileProcess(file);
    }
  };

  const handleDragOver = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(true);
  };

  const handleDragLeave = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
  };

  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);

    const file = e.dataTransfer.files?.[0];
    if (file) {
      handleFileProcess(file);
    }
  };

  const clearUploadedFile = () => {
    setUploadedFile(null);
    setRawInput('');
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  const handleRunInvestigation = async (e) => {
    if (e) e.preventDefault();
    if (!rawInput.trim()) {
      setError("Please paste a security alert, log extract, or IOC list.");
      return;
    }

    setLoading(true);
    setError(null);
    setCheckedActions({});

    try {
      setLoadingStep("Extracting IOC artifacts & network entities...");
      setTimeout(() => setLoadingStep("Querying ChromaDB RAG (MITRE ATT&CK & CVEs)..."), 700);
      setTimeout(() => setLoadingStep(`Synthesizing attack chain with ${model}...`), 1500);

      const res = await api.runInvestigation({
        raw_input: rawInput,
        model: model,
        alert_type: alertType,
        title: title || undefined
      });

      if (res.success && res.investigation) {
        setCurrentInvestigation(res.investigation);
        if (onInvestigationComplete) {
          onInvestigationComplete(res.investigation);
        }
      }
    } catch (err) {
      setError(err.message || "Investigation failed to execute.");
    } finally {
      setLoading(false);
      setLoadingStep('');
    }
  };

  const handleReanalyzeWithModel = async (targetModel) => {
    if (!currentInvestigation) return;
    setLoading(true);
    setError(null);
    try {
      setLoadingStep(`Re-analyzing forensic evidence with ${targetModel}...`);
      const res = await api.reanalyzeInvestigation(currentInvestigation.id, {
        model: targetModel
      });
      if (res.success && res.investigation) {
        setCurrentInvestigation(res.investigation);
        if (onInvestigationComplete) onInvestigationComplete(res.investigation);
      }
    } catch (err) {
      setError(err.message || "Re-analysis failed.");
    } finally {
      setLoading(false);
      setLoadingStep('');
    }
  };

  const copyToClipboard = (text, type, id) => {
    navigator.clipboard.writeText(text);
    if (type === 'query') {
      setCopiedQuery(id);
      setTimeout(() => setCopiedQuery(null), 2000);
    } else if (type === 'ioc') {
      setCopiedIoc(id);
      setTimeout(() => setCopiedIoc(null), 2000);
    }
  };

  const getSeverityBadge = (severity) => {
    const s = (severity || 'MEDIUM').toUpperCase();
    switch (s) {
      case 'CRITICAL':
        return 'bg-rose-500/20 text-rose-400 border border-rose-500/40 danger-glow';
      case 'HIGH':
        return 'bg-amber-500/20 text-amber-400 border border-amber-500/40 warning-glow';
      case 'MEDIUM':
        return 'bg-yellow-500/20 text-yellow-300 border border-yellow-500/40';
      case 'LOW':
        return 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/40';
      default:
        return 'bg-sky-500/20 text-sky-400 border border-sky-500/40';
    }
  };

  const getRiskScoreColor = (score) => {
    if (score >= 80) return 'text-rose-500 stroke-rose-500';
    if (score >= 60) return 'text-amber-500 stroke-amber-500';
    if (score >= 40) return 'text-yellow-400 stroke-yellow-400';
    return 'text-emerald-400 stroke-emerald-400';
  };

  const toggleAction = (idx) => {
    setCheckedActions(prev => ({
      ...prev,
      [idx]: !prev[idx]
    }));
  };

  const exportMarkdown = () => {
    if (!currentInvestigation) return;
    const element = document.createElement("a");
    const file = new Blob([currentInvestigation.full_report_markdown || currentInvestigation.summary], { type: 'text/markdown' });
    element.href = URL.createObjectURL(file);
    element.download = `SecuRAG-Report-${currentInvestigation.id || 'export'}.md`;
    document.body.appendChild(element);
    element.click();
    document.body.removeChild(element);
  };

  const exportPDF = async () => {
    if (!currentInvestigation) return;
    setPdfLoading(true);
    try {
      await generateInvestigationPDF(currentInvestigation);
    } catch (err) {
      console.error('PDF generation error:', err);
    } finally {
      setPdfLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      
      {/* Top Banner / Triage Input Bar */}
      <div className="bg-[#111726] border border-slate-800 rounded-xl p-5 shadow-xl">
        <div className="flex flex-wrap items-center justify-between gap-3 mb-4 pb-3 border-b border-slate-800/80">
          <div className="flex items-center space-x-2">
            <Terminal className="w-5 h-5 text-sky-400" />
            <h2 className="text-sm font-semibold text-white uppercase tracking-wider font-mono">
              Live Alert Triage & RAG Investigation
            </h2>
          </div>

          {/* Quick Preset Selector */}
          <div className="flex items-center space-x-2 text-xs">
            <span className="text-slate-400 hidden sm:inline">Scenario Preset:</span>
            <select
              value={selectedPresetId}
              onChange={(e) => {
                const found = presets.find(p => p.id === e.target.value);
                if (found) applyPreset(found);
              }}
              className="bg-slate-900 border border-slate-700 text-slate-200 text-xs rounded-lg px-2.5 py-1.5 focus:ring-1 focus:ring-sky-500 outline-none"
            >
              <option value="">-- Load Attack Scenario --</option>
              {presets.map(p => (
                <option key={p.id} value={p.id}>{p.title}</option>
              ))}
            </select>
          </div>
        </div>

        <form onSubmit={handleRunInvestigation} className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <div>
              <label className="block text-xs font-medium text-slate-400 mb-1">
                Investigation Title
              </label>
              <input
                type="text"
                value={title}
                onChange={(e) => setTitle(e.target.value)}
                placeholder="e.g., Suspicious PowerShell Download & LSASS Dump"
                className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-sky-500"
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-400 mb-1">
                Alert Source / Type
              </label>
              <select
                value={alertType}
                onChange={(e) => setAlertType(e.target.value)}
                className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-sky-500"
              >
                <option value="Endpoint / EDR Alert">Endpoint / EDR Alert</option>
                <option value="SIEM / Sysmon Detection">SIEM / Sysmon Detection</option>
                <option value="Network / Firewall Alert">Network / Firewall Alert</option>
                <option value="WAF / Web Application">WAF / Web Application</option>
                <option value="Email Gateway / Phishing">Email Gateway / Phishing</option>
                <option value="Active Directory / Identity">Active Directory / Identity</option>
                <option value="Threat Hunting Raw Logs">Threat Hunting Raw Logs</option>
              </select>
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-400 mb-1">
                Investigation AI Model
              </label>
              <select
                value={model}
                onChange={(e) => setModel(e.target.value)}
                className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs text-sky-300 font-mono focus:outline-none focus:border-sky-500"
              >
                <option value="qwen3.5:9b">qwen3.5:9b (Main SOC Tier-3)</option>
                <option value="Qwen3:8b">Qwen3:8b (Fast Triage)</option>
                <option value="gemma3:12b">gemma3:12b (Deep Forensic Report)</option>
              </select>
            </div>
          </div>

          {/* Hidden File Input */}
          <input
            type="file"
            ref={fileInputRef}
            onChange={handleFileInputChange}
            accept=".log,.txt,.json,.csv,.xml,.syslog,.evtx"
            className="hidden"
          />

          <div>
            <div className="flex flex-wrap justify-between items-center mb-1.5 gap-2">
              <label className="text-xs font-medium text-slate-400 flex items-center space-x-1.5">
                <span>Raw Alert Telemetry / SIEM Log / IOCs:</span>
              </label>

              <div className="flex items-center space-x-2">
                <button
                  type="button"
                  onClick={() => fileInputRef.current?.click()}
                  className="flex items-center space-x-1 px-2.5 py-1 bg-slate-900 hover:bg-slate-800 border border-slate-700 text-sky-400 hover:text-sky-300 rounded text-xs transition-colors"
                >
                  <FileUp className="w-3.5 h-3.5" />
                  <span>Upload Log File</span>
                </button>

                {(rawInput || uploadedFile) && (
                  <button
                    type="button"
                    onClick={clearUploadedFile}
                    className="text-[11px] text-slate-500 hover:text-slate-300"
                  >
                    Clear Input
                  </button>
                )}
              </div>
            </div>

            {/* Uploaded File Badge */}
            {uploadedFile && (
              <div className="mb-2 p-2.5 bg-sky-950/40 border border-sky-800/60 rounded-lg flex items-center justify-between text-xs">
                <div className="flex items-center space-x-2 overflow-hidden pr-2">
                  <div className="p-1 bg-sky-500/20 rounded text-sky-400">
                    <FileText className="w-4 h-4" />
                  </div>
                  <div className="truncate">
                    <span className="font-semibold text-white block truncate">
                      {uploadedFile.name}
                    </span>
                    <span className="text-[10px] text-sky-300 font-mono">
                      {(uploadedFile.size / 1024).toFixed(1)} KB • {uploadedFile.lines} lines loaded
                    </span>
                  </div>
                </div>

                <button
                  type="button"
                  onClick={clearUploadedFile}
                  className="p-1 text-slate-400 hover:text-rose-400 bg-slate-900 rounded transition-colors"
                  title="Remove loaded file"
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              </div>
            )}

            {/* Droppable Textarea */}
            <div
              onDragOver={handleDragOver}
              onDragLeave={handleDragLeave}
              onDrop={handleDrop}
              className={`relative rounded-lg transition-all ${
                isDragging
                  ? 'border-2 border-dashed border-sky-400 bg-sky-950/30'
                  : 'border border-slate-800 bg-slate-950'
              }`}
            >
              {isDragging && (
                <div className="absolute inset-0 z-10 flex flex-col items-center justify-center bg-slate-950/80 backdrop-blur-sm rounded-lg pointer-events-none">
                  <FileUp className="w-8 h-8 text-sky-400 animate-bounce mb-2" />
                  <span className="text-xs font-semibold text-white">
                    Drop your log file here (.log, .txt, .json, .csv, .xml)
                  </span>
                </div>
              )}

              <textarea
                rows={6}
                value={rawInput}
                onChange={(e) => setRawInput(e.target.value)}
                placeholder="Paste security alert JSON, Windows Sysmon Event, EDR notification, access log, or DRAG & DROP a log file here..."
                className="w-full bg-transparent p-3 text-xs font-mono text-slate-200 focus:outline-none focus:ring-1 focus:ring-sky-500/40 rounded-lg resize-y"
              />
            </div>
          </div>

          {error && (
            <div className="flex items-center space-x-2 p-3 bg-rose-500/10 border border-rose-500/30 rounded-lg text-rose-400 text-xs">
              <AlertCircle className="w-4 h-4 flex-shrink-0" />
              <span>{error}</span>
            </div>
          )}

          <div className="flex justify-between items-center pt-1">
            <span className="text-xs text-slate-500">
              ⚡ Local RAG: Retrieves MITRE ATT&CK, OWASP & CVE embeddings with Ollama
            </span>

            <button
              type="submit"
              disabled={loading}
              className={`flex items-center space-x-2 px-5 py-2.5 rounded-lg text-xs font-semibold text-white tracking-wide transition-all ${
                loading
                  ? 'bg-slate-800 cursor-not-allowed text-slate-400'
                  : 'bg-sky-500 hover:bg-sky-400 shadow-md shadow-sky-500/20'
              }`}
            >
              {loading ? (
                <>
                  <RotateCw className="w-4 h-4 animate-spin text-sky-400" />
                  <span>{loadingStep || "Analyzing..."}</span>
                </>
              ) : (
                <>
                  <Play className="w-4 h-4 fill-white" />
                  <span>Run SecuRAG Investigation</span>
                </>
              )}
            </button>
          </div>
        </form>
      </div>

      {/* Main Results View */}
      {currentInvestigation ? (
        <div className="space-y-6">
          
          {/* Header Card: Risk Score + Severity + Title */}
          <div className="bg-[#111726] border border-slate-800 rounded-xl p-6 shadow-xl">
            <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-4">
              
              <div className="flex items-start space-x-4">
                {/* Visual Risk Gauge */}
                <div className="relative w-16 h-16 flex-shrink-0 flex items-center justify-center bg-slate-900 border border-slate-800 rounded-full">
                  <div className="text-center">
                    <span className={`text-xl font-bold font-mono ${getRiskScoreColor(currentInvestigation.risk_score)}`}>
                      {currentInvestigation.risk_score}
                    </span>
                    <span className="block text-[9px] text-slate-400 -mt-1 font-semibold uppercase">
                      Risk
                    </span>
                  </div>
                </div>

                {/* Title & Badges */}
                <div>
                  <div className="flex flex-wrap items-center gap-2 mb-1.5">
                    <span className={`px-2.5 py-0.5 rounded text-xs font-bold uppercase tracking-wider ${getSeverityBadge(currentInvestigation.severity)}`}>
                      {currentInvestigation.severity} SEVERITY
                    </span>
                    <span className="bg-slate-800 text-slate-300 px-2.5 py-0.5 rounded text-xs font-medium border border-slate-700">
                      {currentInvestigation.attack_stage || 'Active Threat Execution'}
                    </span>
                    <span className="text-slate-400 text-xs font-mono">
                      Engine: <span className="text-sky-300 font-semibold">{currentInvestigation.model_used}</span>
                    </span>
                  </div>

                  <h1 className="text-lg font-bold text-white tracking-tight">
                    {currentInvestigation.title}
                  </h1>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Alert Source: {currentInvestigation.alert_type} • Analyzed on {new Date(currentInvestigation.created_at).toLocaleString()}
                  </p>
                </div>
              </div>

              {/* Action Buttons */}
              <div className="flex items-center space-x-2 self-end lg:self-auto">
                <button
                  onClick={exportPDF}
                  disabled={pdfLoading}
                  className="flex items-center space-x-1.5 bg-sky-600 hover:bg-sky-500 disabled:bg-slate-800 disabled:text-slate-500 text-white text-xs px-3 py-1.5 rounded-lg transition-colors shadow-md shadow-sky-500/20 font-semibold"
                  title="Download Professional PDF Report"
                >
                  {pdfLoading ? (
                    <>
                      <RotateCw className="w-3.5 h-3.5 animate-spin" />
                      <span>Generating...</span>
                    </>
                  ) : (
                    <>
                      <Download className="w-3.5 h-3.5" />
                      <span>Export PDF Report</span>
                    </>
                  )}
                </button>

                <button
                  onClick={exportMarkdown}
                  className="flex items-center space-x-1.5 bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-300 text-xs px-3 py-1.5 rounded-lg transition-colors"
                  title="Download Markdown Report"
                >
                  <FileText className="w-3.5 h-3.5" />
                  <span>.md</span>
                </button>

                {currentInvestigation.model_used !== 'gemma3:12b' && (
                  <button
                    onClick={() => handleReanalyzeWithModel('gemma3:12b')}
                    disabled={loading}
                    className="flex items-center space-x-1.5 bg-purple-500/20 hover:bg-purple-500/30 border border-purple-500/40 text-purple-300 text-xs px-3 py-1.5 rounded-lg transition-colors"
                    title="Generate in-depth forensic investigation with Gemma 3 12b"
                  >
                    <Sparkles className="w-3.5 h-3.5 text-purple-400" />
                    <span>Deep Report (Gemma 3:12b)</span>
                  </button>
                )}
              </div>

            </div>

            {/* Executive Summary */}
            <div className="mt-5 p-4 bg-slate-900/80 rounded-lg border border-slate-800">
              <h3 className="text-xs font-semibold text-sky-400 uppercase tracking-wider mb-1 flex items-center">
                <Flame className="w-3.5 h-3.5 mr-1 text-sky-400" />
                Executive Threat Summary
              </h3>
              <p className="text-xs text-slate-300 leading-relaxed">
                {currentInvestigation.summary}
              </p>
            </div>
          </div>

          {/* Statistics & Analytics Charts */}
          <StatisticsPanel investigation={currentInvestigation} />

          {/* Grid Layout: MITRE ATT&CK Mapping & Extracted IOCs */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            
            {/* MITRE ATT&CK Mapping */}
            <div className="bg-[#111726] border border-slate-800 rounded-xl p-5 shadow-xl space-y-3">
              <div className="flex items-center justify-between pb-2 border-b border-slate-800">
                <div className="flex items-center space-x-2">
                  <Crosshair className="w-4 h-4 text-rose-400" />
                  <h3 className="text-xs font-semibold text-white uppercase tracking-wider font-mono">
                    MITRE ATT&CK Matrix Mapping
                  </h3>
                </div>
                <span className="text-[11px] text-slate-400">
                  {currentInvestigation.mitre_techniques?.length || 0} Techniques Correlated
                </span>
              </div>

              {currentInvestigation.mitre_techniques && currentInvestigation.mitre_techniques.length > 0 ? (
                <div className="space-y-3">
                  {currentInvestigation.mitre_techniques.map((tech, idx) => (
                    <div 
                      key={idx}
                      className="p-3 bg-slate-900/90 border border-slate-800 rounded-lg hover:border-slate-700 transition-all"
                    >
                      <div className="flex items-center justify-between mb-1">
                        <div className="flex items-center space-x-2">
                          <a
                            href={`https://attack.mitre.org/techniques/${tech.id?.replace('.', '/')}`}
                            target="_blank"
                            rel="noreferrer"
                            className="bg-rose-500/20 text-rose-300 hover:text-white px-2 py-0.5 rounded text-xs font-mono font-bold border border-rose-500/30 flex items-center space-x-1"
                          >
                            <span>{tech.id}</span>
                            <ExternalLink className="w-2.5 h-2.5" />
                          </a>
                          <span className="text-xs font-semibold text-slate-200">
                            {tech.name}
                          </span>
                        </div>
                        <span className="text-[10px] uppercase font-mono px-2 py-0.5 bg-slate-800 text-slate-400 rounded">
                          {tech.tactic || 'Execution'}
                        </span>
                      </div>
                      
                      <p className="text-[11px] text-slate-300 mt-1.5 leading-snug">
                        {tech.description}
                      </p>

                      {tech.detection && (
                        <div className="mt-2 text-[11px] text-sky-400 bg-sky-950/40 p-2 rounded border border-sky-900/40">
                          <span className="font-semibold text-sky-300">Detection Logic: </span>
                          {tech.detection}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-xs text-slate-500 text-center py-6">
                  No specific MITRE techniques mapped for this event.
                </div>
              )}
            </div>

            {/* Extracted IOCs & Threat Indicators */}
            <div className="bg-[#111726] border border-slate-800 rounded-xl p-5 shadow-xl space-y-3">
              <div className="flex items-center justify-between pb-2 border-b border-slate-800">
                <div className="flex items-center space-x-2">
                  <Search className="w-4 h-4 text-amber-400" />
                  <h3 className="text-xs font-semibold text-white uppercase tracking-wider font-mono">
                    Extracted IOC Intelligence
                  </h3>
                </div>
                <span className="text-[11px] text-slate-400">
                  {currentInvestigation.iocs_detected?.length || 0} Indicators
                </span>
              </div>

              {currentInvestigation.iocs_detected && currentInvestigation.iocs_detected.length > 0 ? (
                <div className="overflow-x-auto max-h-[360px] overflow-y-auto space-y-2 pr-1">
                  {currentInvestigation.iocs_detected.map((ioc, idx) => (
                    <div 
                      key={idx}
                      className="flex items-center justify-between p-2.5 bg-slate-900/90 border border-slate-800 rounded-lg text-xs"
                    >
                      <div className="flex items-center space-x-2.5 overflow-hidden">
                        <span className="px-1.5 py-0.5 bg-slate-800 text-slate-300 text-[10px] font-mono rounded border border-slate-700 flex-shrink-0">
                          {ioc.type}
                        </span>
                        
                        <div className="truncate">
                          <span className="font-mono text-slate-200 select-all block truncate">
                            {ioc.value}
                          </span>
                          {ioc.context && (
                            <span className="text-[10px] text-slate-500 block truncate">
                              {ioc.context}
                            </span>
                          )}
                        </div>
                      </div>

                      <div className="flex items-center space-x-2 flex-shrink-0 ml-2">
                        <span className={`text-[10px] px-1.5 py-0.5 rounded font-semibold ${
                          ioc.threat_level === 'Malicious' || ioc.threat_level === 'High Risk'
                            ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                            : ioc.threat_level === 'Critical'
                            ? 'bg-purple-500/20 text-purple-400 border border-purple-500/30'
                            : 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                        }`}>
                          {ioc.threat_level || 'Suspicious'}
                        </span>

                        <button
                          onClick={() => copyToClipboard(ioc.value, 'ioc', idx)}
                          className="p-1 text-slate-400 hover:text-slate-200 bg-slate-800 rounded transition-colors"
                          title="Copy IOC value"
                        >
                          {copiedIoc === idx ? (
                            <Check className="w-3.5 h-3.5 text-emerald-400" />
                          ) : (
                            <Copy className="w-3.5 h-3.5" />
                          )}
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-xs text-slate-500 text-center py-6">
                  No technical IOCs extracted from raw telemetry.
                </div>
              )}
            </div>

          </div>

          {/* SOC Playbook: Containment & Remediation Checklist */}
          <div className="bg-[#111726] border border-slate-800 rounded-xl p-5 shadow-xl">
            <h3 className="text-xs font-semibold text-emerald-400 uppercase tracking-wider font-mono mb-4 flex items-center">
              <CheckCircle2 className="w-4 h-4 mr-1.5 text-emerald-400" />
              SOC Actionable Response Playbook & Containment
            </h3>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {/* Immediate Containment */}
              <div className="bg-slate-900/80 p-4 rounded-lg border border-slate-800">
                <h4 className="text-xs font-bold text-rose-400 uppercase tracking-wide mb-2">
                  Immediate Containment (Tier-1/2)
                </h4>
                <ul className="space-y-2">
                  {(currentInvestigation.recommended_actions?.immediate_containment || [
                    "Isolate suspected host from the corporate network.",
                    "Block reported external IPs and C2 domains at firewall.",
                    "Terminate rogue process execution tree."
                  ]).map((action, idx) => (
                    <li 
                      key={idx}
                      onClick={() => toggleAction(`imm_${idx}`)}
                      className="flex items-start space-x-2 text-xs text-slate-300 cursor-pointer group"
                    >
                      <input
                        type="checkbox"
                        checked={!!checkedActions[`imm_${idx}`]}
                        onChange={() => {}}
                        className="mt-0.5 rounded border-slate-700 bg-slate-800 text-sky-500 focus:ring-0 cursor-pointer"
                      />
                      <span className={checkedActions[`imm_${idx}`] ? 'line-through text-slate-500' : 'group-hover:text-white'}>
                        {action}
                      </span>
                    </li>
                  ))}
                </ul>
              </div>

              {/* Eradication & Remediation */}
              <div className="bg-slate-900/80 p-4 rounded-lg border border-slate-800">
                <h4 className="text-xs font-bold text-sky-400 uppercase tracking-wide mb-2">
                  Eradication & Long-Term Hardening
                </h4>
                <ul className="space-y-2">
                  {(currentInvestigation.recommended_actions?.eradication_remediation || [
                    "Perform credential rotation for affected Active Directory accounts.",
                    "Deploy security patches / updates for highlighted vulnerabilities.",
                    "Review Windows Event Logs (4688, 4104) and run full endpoint EDR scan."
                  ]).map((action, idx) => (
                    <li 
                      key={idx}
                      onClick={() => toggleAction(`rem_${idx}`)}
                      className="flex items-start space-x-2 text-xs text-slate-300 cursor-pointer group"
                    >
                      <input
                        type="checkbox"
                        checked={!!checkedActions[`rem_${idx}`]}
                        onChange={() => {}}
                        className="mt-0.5 rounded border-slate-700 bg-slate-800 text-sky-500 focus:ring-0 cursor-pointer"
                      />
                      <span className={checkedActions[`rem_${idx}`] ? 'line-through text-slate-500' : 'group-hover:text-white'}>
                        {action}
                      </span>
                    </li>
                  ))}
                </ul>
              </div>
            </div>

            {/* Threat Hunting Queries */}
            {currentInvestigation.recommended_actions?.hunting_queries && (
              <div className="mt-5 pt-4 border-t border-slate-800">
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center space-x-2">
                    <FileCode className="w-4 h-4 text-sky-400" />
                    <h4 className="text-xs font-semibold text-white uppercase tracking-wider font-mono">
                      Threat Hunting & SIEM Queries
                    </h4>
                  </div>

                  {/* Query Tabs */}
                  <div className="flex space-x-1 bg-slate-900 p-1 rounded-lg border border-slate-800 text-[11px] font-mono">
                    <button
                      onClick={() => setActiveHuntingTab('kql')}
                      className={`px-2.5 py-1 rounded transition-colors ${
                        activeHuntingTab === 'kql'
                          ? 'bg-sky-500 text-white font-bold'
                          : 'text-slate-400 hover:text-slate-200'
                      }`}
                    >
                      Microsoft KQL
                    </button>
                    <button
                      onClick={() => setActiveHuntingTab('splunk')}
                      className={`px-2.5 py-1 rounded transition-colors ${
                        activeHuntingTab === 'splunk'
                          ? 'bg-sky-500 text-white font-bold'
                          : 'text-slate-400 hover:text-slate-200'
                      }`}
                    >
                      Splunk SPL
                    </button>
                    <button
                      onClick={() => setActiveHuntingTab('sigma')}
                      className={`px-2.5 py-1 rounded transition-colors ${
                        activeHuntingTab === 'sigma'
                          ? 'bg-sky-500 text-white font-bold'
                          : 'text-slate-400 hover:text-slate-200'
                      }`}
                    >
                      Sigma Rule
                    </button>
                  </div>
                </div>

                {/* Query Display Block */}
                <div className="relative bg-slate-950 border border-slate-800 rounded-lg p-3 text-xs font-mono text-emerald-400 overflow-x-auto">
                  <div className="flex justify-between items-center mb-1 text-[10px] text-slate-500 border-b border-slate-900 pb-1">
                    <span>
                      {activeHuntingTab.toUpperCase()} SYNTAX:
                    </span>
                    <button
                      onClick={() => copyToClipboard(
                        currentInvestigation.recommended_actions.hunting_queries[activeHuntingTab] || '',
                        'query',
                        activeHuntingTab
                      )}
                      className="flex items-center space-x-1 text-slate-400 hover:text-white bg-slate-900 px-2 py-0.5 rounded border border-slate-800"
                    >
                      {copiedQuery === activeHuntingTab ? (
                        <>
                          <Check className="w-3 h-3 text-emerald-400" />
                          <span className="text-emerald-400 font-sans">Copied!</span>
                        </>
                      ) : (
                        <>
                          <Copy className="w-3 h-3" />
                          <span className="font-sans">Copy Query</span>
                        </>
                      )}
                    </button>
                  </div>

                  <pre className="whitespace-pre-wrap leading-relaxed">
                    {currentInvestigation.recommended_actions.hunting_queries[activeHuntingTab] || 
                     `// No specific ${activeHuntingTab.toUpperCase()} query generated for this event.`}
                  </pre>
                </div>
              </div>
            )}

          </div>

          {/* Full Markdown Forensic Report Accordion */}
          {currentInvestigation.full_report_markdown && (
            <div className="bg-[#111726] border border-slate-800 rounded-xl p-5 shadow-xl">
              <div className="flex items-center justify-between mb-3 pb-2 border-b border-slate-800">
                <h3 className="text-xs font-semibold text-white uppercase tracking-wider font-mono flex items-center">
                  <Terminal className="w-4 h-4 mr-1.5 text-purple-400" />
                  Full Forensic Investigation Report
                </h3>
                <button
                  onClick={exportMarkdown}
                  className="text-xs text-sky-400 hover:text-sky-300 flex items-center space-x-1"
                >
                  <Download className="w-3 h-3" />
                  <span>Download .md</span>
                </button>
              </div>

              <div className="bg-slate-950 p-4 rounded-lg border border-slate-800 font-mono text-xs text-slate-300 whitespace-pre-wrap leading-relaxed max-h-[500px] overflow-y-auto">
                {currentInvestigation.full_report_markdown}
              </div>
            </div>
          )}

        </div>
      ) : null}

    </div>
  );
}
