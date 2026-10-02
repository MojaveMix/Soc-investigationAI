const API_BASE = '/api';

export async function fetchJson(endpoint, options = {}) {
  const res = await fetch(`${API_BASE}${endpoint}`, {
    headers: {
      'Content-Type': 'application/json',
      ...options.headers,
    },
    ...options,
  });

  if (!res.ok) {
    let errorDetail = `HTTP ${res.status}`;
    try {
      const errorJson = await res.json();
      errorDetail = errorJson.error || errorDetail;
    } catch (_) {}
    throw new Error(errorDetail);
  }

  return res.json();
}

export const api = {
  // System Health & Config
  getHealth: () => fetchJson('/health'),
  getModels: () => fetchJson('/models'),
  getPresets: () => fetchJson('/presets'),

  // Investigations
  runInvestigation: (payload) =>
    fetchJson('/investigations/run', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  uploadAndInvestigate: async (formData) => {
    const res = await fetch('/api/investigations/upload', {
      method: 'POST',
      body: formData,
    });
    if (!res.ok) {
      let errText = `HTTP ${res.status}`;
      try {
        const data = await res.json();
        errText = data.error || errText;
      } catch (_) {}
      throw new Error(errText);
    }
    return res.json();
  },
  getInvestigations: (params = {}) => {
    const qs = new URLSearchParams(params).toString();
    return fetchJson(`/investigations?${qs}`);
  },
  getInvestigation: (id) => fetchJson(`/investigations/${id}`),
  deleteInvestigation: (id) =>
    fetchJson(`/investigations/${id}`, { method: 'DELETE' }),
  reanalyzeInvestigation: (id, payload) =>
    fetchJson(`/investigations/${id}/reanalyze`, {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  // IOC Intel
  extractIOCs: (text) =>
    fetchJson('/ioc/extract', {
      method: 'POST',
      body: JSON.stringify({ text }),
    }),
  getRecordedIOCs: (params = {}) => {
    const qs = new URLSearchParams(params).toString();
    return fetchJson(`/ioc/list?${qs}`);
  },

  // Knowledge Base & RAG
  searchKnowledge: (query, framework, topK = 6) =>
    fetchJson('/knowledge/search', {
      method: 'POST',
      body: JSON.stringify({ query, framework, top_k: topK }),
    }),
  getKnowledgeStats: () => fetchJson('/knowledge/stats'),
  reindexKnowledge: () =>
    fetchJson('/knowledge/reindex', { method: 'POST' }),
  addCustomKnowledge: (payload) =>
    fetchJson('/knowledge/custom', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
};
