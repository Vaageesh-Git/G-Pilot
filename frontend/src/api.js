const API_BASE = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';

async function request(path, options = {}) {
  const response = await fetch(`${API_BASE}${path}`, {
    headers: {
      'Content-Type': 'application/json',
      ...(options.headers || {})
    },
    ...options
  });
  if (!response.ok) {
    const payload = await response.json().catch(() => ({}));
    throw new Error(payload.detail || `Request failed: ${response.status}`);
  }
  return response.json();
}

export function startScan(payload) {
  return request('/scan-repo', {
    method: 'POST',
    body: JSON.stringify(payload)
  });
}

export function getStatus(id) {
  return request(`/status/${id}`);
}

export function getReport(id) {
  return request(`/report/${id}`);
}

export function retryJob(id) {
  return request(`/retry/${id}`, { method: 'POST' });
}

export { API_BASE };
