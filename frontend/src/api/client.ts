const API_BASE_URL = 'http://localhost:8000/api';

export async function fetchWithTimeout(resource: string, options: RequestInit & { timeout?: number } = {}) {
  const { timeout = 8000 } = options;
  
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeout);
  
  const response = await fetch(resource, {
    ...options,
    signal: controller.signal
  });
  clearTimeout(id);
  
  return response;
}

export const api = {
  get: async (path: string) => {
    const res = await fetchWithTimeout(`${API_BASE_URL}${path}`);
    if (!res.ok) throw new Error(`API Error: ${res.statusText}`);
    return res.json();
  },
  post: async (path: string, body: any) => {
    const res = await fetchWithTimeout(`${API_BASE_URL}${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (!res.ok) throw new Error(`API Error: ${res.statusText}`);
    return res.json();
  },
  delete: async (path: string) => {
    const res = await fetchWithTimeout(`${API_BASE_URL}${path}`, {
      method: 'DELETE',
    });
    if (!res.ok) throw new Error(`API Error: ${res.statusText}`);
    return res.status === 204 ? null : res.json();
  }
};
