import { useState, useEffect } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { api } from '@/utils/api';
import toast from 'react-hot-toast';
import { cn } from '@/utils/cn';
import { Plus, Trash2, TestTube, Loader2, CheckCircle, XCircle, Server, Shield, Key } from 'lucide-react';

export function SettingsView() {
  const queryClient = useQueryClient();
  const { data: providers, isLoading } = useQuery({ queryKey: ['llm-providers'], queryFn: api.listProviders });

  const [editing, setEditing] = useState<any>(null);
  const [testResult, setTestResult] = useState<any>(null);
  const [testing, setTesting] = useState(false);

  const createMutation = useMutation({
    mutationFn: api.createProvider,
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ['llm-providers'] }); toast.success('Provider created'); },
    onError: (err: any) => { toast.error(`Failed to create provider: ${err.message || 'Unknown error'}`); console.error('Create provider error:', err); },
  });

  const updateMutation = useMutation({
    mutationFn: (data: any) => api.updateProvider(data.id, data),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ['llm-providers'] }); toast.success('Provider updated'); setEditing(null); },
    onError: (err: any) => { toast.error(`Failed to update provider: ${err.message || 'Unknown error'}`); console.error('Update provider error:', err); },
  });

  const deleteMutation = useMutation({
    mutationFn: api.deleteProvider,
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ['llm-providers'] }); toast.success('Provider deleted'); },
    onError: (err: any) => { toast.error(`Failed to delete provider: ${err.message || 'Unknown error'}`); console.error('Delete provider error:', err); },
  });

  const handleTest = async (id: string) => {
    setTesting(true);
    setTestResult(null);
    try {
      const result = await api.testProvider(id);
      setTestResult(result);
      queryClient.invalidateQueries({ queryKey: ['llm-providers'] });
      if (result.status === 'success') {
        toast.success('Connection successful');
      } else {
        toast.error(result.message || 'Connection failed');
      }
    } catch (e: any) {
      toast.error(e.message);
    } finally {
      setTesting(false);
    }
  };

  return (
    <div className="h-full overflow-auto p-6">
      <div className="max-w-3xl mx-auto space-y-6">
        <div>
          <h1 className="text-xl font-bold">Settings</h1>
          <p className="text-sm text-muted-foreground mt-1">Configure LLM providers and application preferences</p>
        </div>

        {/* LLM Provider Configuration */}
        <div className="border rounded-lg bg-card">
          <div className="flex items-center justify-between px-4 py-3 border-b">
            <div className="flex items-center gap-2">
              <Server size={16} />
              <h2 className="font-semibold text-sm">LLM Provider Configuration</h2>
            </div>
            <button
              onClick={() => createMutation.mutate({ name: 'New Provider', base_url: 'http://localhost:11434/v1', model: '' })}
              disabled={createMutation.isPending}
              className="flex items-center gap-1 px-3 py-1.5 text-xs rounded-md bg-primary text-primary-foreground hover:opacity-90 disabled:opacity-50"
            >
              {createMutation.isPending ? <Loader2 size={13} className="animate-spin" /> : <Plus size={13} />}
              {createMutation.isPending ? 'Adding...' : 'Add Provider'}
            </button>
          </div>

          <div className="p-4 space-y-4">
            <div className="p-3 rounded-lg bg-muted/50 text-xs text-muted-foreground">
              <p><strong>OpenAI API Compatible:</strong> Configure any local LLM endpoint that supports the OpenAI chat completions API format (e.g., Ollama, LM Studio, vLLM, text-generation-webui).</p>
              <p className="mt-1"><strong>Security:</strong> API keys are encrypted at rest. TLS certificate verification is enabled by default. All LLM requests are made server-side — secrets never reach the browser.</p>
            </div>

            {isLoading ? (
              <div className="text-center py-4 text-muted-foreground">Loading...</div>
            ) : !providers?.length ? (
              <div className="text-center py-8 text-muted-foreground">
                No LLM providers configured. Add one to enable AI assistance.
              </div>
            ) : (
              providers.map((p: any) => (
                <ProviderCard
                  key={p.id}
                  provider={p}
                  editing={editing?.id === p.id}
                  onEdit={() => setEditing(editing?.id === p.id ? null : { ...p, api_key: '' })}
                  onSave={(data: any) => updateMutation.mutate({ id: p.id, ...data })}
                  onDelete={() => { if (confirm('Delete this provider?')) deleteMutation.mutate(p.id); }}
                  onTest={() => handleTest(p.id)}
                  testing={testing}
                  testResult={testResult}
                  editingData={editing?.id === p.id ? editing : null}
                  setEditingData={setEditing}
                />
              ))
            )}
          </div>
        </div>

        {/* Application Info */}
        <div className="border rounded-lg bg-card p-4">
          <h3 className="font-semibold text-sm mb-3">Application Info</h3>
          <div className="space-y-1 text-xs text-muted-foreground">
            <p><strong>Version:</strong> 1.0.0</p>
            <p><strong>Mode:</strong> Local / Single-user</p>
            <p><strong>Storage:</strong> SQLite</p>
            <p><strong>Telemetry:</strong> Disabled</p>
            <p><strong>Network:</strong> Offline-capable (LLM features require configured endpoint)</p>
          </div>
        </div>
      </div>
    </div>
  );
}

function ProviderCard({ provider, editing, onEdit, onSave, onDelete, onTest, testing, testResult, editingData, setEditingData }: any) {
  const updateField = (field: string, value: any) => {
    setEditingData((prev: any) => ({ ...prev, [field]: value }));
  };

  return (
    <div className="border rounded-lg p-4 space-y-3">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <div className={cn('w-2 h-2 rounded-full', provider.last_test_result === 'success' ? 'bg-green-500' : provider.last_test_result === 'error' ? 'bg-red-500' : 'bg-gray-300')} />
          <span className="font-semibold text-sm">{provider.name}</span>
          <span className="text-xs text-muted-foreground">{provider.model || 'No model set'}</span>
        </div>
        <div className="flex items-center gap-1">
          <button onClick={onTest} disabled={testing} className="flex items-center gap-1 px-2 py-1 text-xs rounded border hover:bg-accent disabled:opacity-50">
            {testing ? <Loader2 size={12} className="animate-spin" /> : <TestTube size={12} />}
            Test
          </button>
          <button onClick={onEdit} className="px-2 py-1 text-xs rounded border hover:bg-accent">
            {editing ? 'Cancel' : 'Edit'}
          </button>
          <button onClick={onDelete} className="p-1 rounded hover:bg-destructive/10 text-destructive">
            <Trash2 size={13} />
          </button>
        </div>
      </div>

      {!editing && (
        <div className="text-xs text-muted-foreground space-y-1">
          <p><strong>URL:</strong> {provider.base_url}</p>
          <p><strong>API Key:</strong> {provider.has_api_key ? '●●●●●●●● (set)' : 'Not set'}</p>
          <p><strong>TLS Verify:</strong> {provider.tls_verify ? 'Enabled ✓' : 'Disabled ⚠️'}</p>
          {provider.last_tested_at && (
            <p>
              <strong>Last test:</strong>{' '}
              {provider.last_test_result === 'success' ? <span className="text-success">✓ Success</span> : <span className="text-risk-critical">✗ {provider.last_test_message}</span>}
              {' · '}{new Date(provider.last_tested_at).toLocaleString()}
            </p>
          )}
        </div>
      )}

      {editing && editingData && (
        <div className="space-y-3 pt-2 border-t">
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-[10px] font-medium uppercase text-muted-foreground">Display Name</label>
              <input value={editingData.name || ''} onChange={(e) => updateField('name', e.target.value)} className="input-field mt-1 !text-xs" />
            </div>
            <div>
              <label className="text-[10px] font-medium uppercase text-muted-foreground">Model Name</label>
              <input value={editingData.model || ''} onChange={(e) => updateField('model', e.target.value)} className="input-field mt-1 !text-xs" placeholder="e.g., llama3, gpt-4" />
            </div>
          </div>
          <div>
            <label className="text-[10px] font-medium uppercase text-muted-foreground">Base URL / Endpoint</label>
            <input value={editingData.base_url || ''} onChange={(e) => updateField('base_url', e.target.value)} className="input-field mt-1 !text-xs" placeholder="http://localhost:11434/v1" />
          </div>
          <div>
            <label className="text-[10px] font-medium uppercase text-muted-foreground flex items-center gap-1"><Key size={10} /> API Key (leave blank to keep existing)</label>
            <input type="password" value={editingData.api_key || ''} onChange={(e) => updateField('api_key', e.target.value)} className="input-field mt-1 !text-xs" placeholder="sk-..." />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-[10px] font-medium uppercase text-muted-foreground">Timeout (seconds)</label>
              <input type="number" value={editingData.timeout || 120} onChange={(e) => updateField('timeout', Number(e.target.value))} className="input-field mt-1 !text-xs" />
            </div>
            <div className="flex items-end gap-3 pb-1">
              <label className="flex items-center gap-2 text-xs">
                <input type="checkbox" checked={editingData.tls_verify ?? true} onChange={(e) => updateField('tls_verify', e.target.checked)} />
                TLS Verify
              </label>
            </div>
          </div>
          <div>
            <label className="text-[10px] font-medium uppercase text-muted-foreground flex items-center gap-1"><Shield size={10} /> CA Bundle Path (optional)</label>
            <input value={editingData.ca_bundle_path || ''} onChange={(e) => updateField('ca_bundle_path', e.target.value)} className="input-field mt-1 !text-xs" placeholder="/path/to/ca-bundle.crt" />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-[10px] font-medium uppercase text-muted-foreground">Client Cert Path</label>
              <input value={editingData.client_cert_path || ''} onChange={(e) => updateField('client_cert_path', e.target.value)} className="input-field mt-1 !text-xs" />
            </div>
            <div>
              <label className="text-[10px] font-medium uppercase text-muted-foreground">Client Key Path</label>
              <input value={editingData.client_key_path || ''} onChange={(e) => updateField('client_key_path', e.target.value)} className="input-field mt-1 !text-xs" />
            </div>
          </div>
          <div className="flex justify-end">
            <button onClick={() => onSave(editingData)} className="px-4 py-1.5 text-xs rounded-md bg-primary text-primary-foreground hover:opacity-90">
              Save Provider
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
