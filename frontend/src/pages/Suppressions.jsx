import { useState, useEffect, useMemo, useCallback } from "react";
import {
  ShieldOff, Plus, Trash2, RefreshCw, Clock, AlertTriangle, XCircle,
} from "lucide-react";

const API = import.meta.env.VITE_API_URL || "";

const SCOPES = ["rule", "user", "host", "ip", "process", "tenant"];

export default function Suppressions({ token }) {
  const [list, setList] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // form state
  const [scope, setScope] = useState("rule");
  const [target, setTarget] = useState("");
  const [reason, setReason] = useState("");
  const [duration, setDuration] = useState(24);
  const [submitting, setSubmitting] = useState(false);

  const headers = useMemo(
    () => ({ "Content-Type": "application/json", Authorization: `Bearer ${token}` }),
    [token]
  );

  const fetchList = useCallback(async () => {
    setLoading(true); setError(null);
    try {
      const r = await fetch(`${API}/api/suppressions`, { headers });
      const data = await r.json();
      if (!r.ok) throw new Error(data.detail || `HTTP ${r.status}`);
      setList(data.suppressions || []);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }, [headers]);

  useEffect(() => { fetchList(); }, [fetchList]);

  const create = async () => {
    setSubmitting(true); setError(null);
    try {
      const r = await fetch(`${API}/api/suppressions`, {
        method: "POST", headers,
        body: JSON.stringify({
          scope, target, reason, duration_hours: duration,
        }),
      });
      const data = await r.json();
      if (!r.ok) throw new Error(data.detail || `HTTP ${r.status}`);
      setTarget(""); setReason("");
      await fetchList();
    } catch (e) {
      setError(String(e));
    } finally {
      setSubmitting(false);
    }
  };

  const remove = async (id) => {
    try {
      const r = await fetch(`${API}/api/suppressions/${id}`, { method: "DELETE", headers });
      if (!r.ok) {
        const data = await r.json().catch(() => ({}));
        throw new Error(data.detail || `HTTP ${r.status}`);
      }
      await fetchList();
    } catch (e) {
      setError(String(e));
    }
  };

  const formValid = target.length > 0 && reason.length >= 5 && duration > 0;

  return (
    <div className="p-6 space-y-4 max-w-5xl mx-auto">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <ShieldOff className="w-7 h-7 text-orange-400" />
            Alert Suppressions
          </h1>
          <p className="text-sm text-gray-400 mt-1">
            Silence known false positives — every suppression MUST expire (no permanent bypass)
          </p>
        </div>
        <button onClick={fetchList}
                className="flex items-center gap-2 px-4 py-2 rounded-lg bg-gray-800 hover:bg-gray-700 text-sm">
          <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} />
          Refresh
        </button>
      </div>

      {error && (
        <div className="card p-3 border-red-500/30 bg-red-500/5 text-sm text-red-300 flex items-center gap-2">
          <XCircle className="w-4 h-4" /> {error}
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Form */}
        <div className="card p-5">
          <h3 className="text-sm font-semibold mb-3 flex items-center gap-2">
            <Plus className="w-4 h-4 text-orange-400" />
            New suppression
          </h3>
          <div className="grid grid-cols-2 gap-2">
            <div>
              <label className="text-[10px] uppercase text-gray-500">Scope</label>
              <select value={scope} onChange={(e) => setScope(e.target.value)}
                      className="w-full px-2 py-1.5 rounded bg-gray-800 border border-gray-700 text-sm">
                {SCOPES.map(s => <option key={s}>{s}</option>)}
              </select>
            </div>
            <div>
              <label className="text-[10px] uppercase text-gray-500">Duration (h)</label>
              <input type="number" value={duration} min={1}
                     onChange={(e) => setDuration(parseInt(e.target.value) || 1)}
                     className="w-full px-2 py-1.5 rounded bg-gray-800 border border-gray-700 text-sm" />
            </div>
          </div>
          <div className="mt-2">
            <label className="text-[10px] uppercase text-gray-500">Target</label>
            <input value={target} onChange={(e) => setTarget(e.target.value)}
                   placeholder="RULE-001 / username / 10.0.0.5 / ..."
                   className="w-full px-2 py-1.5 rounded bg-gray-800 border border-gray-700 text-sm" />
          </div>
          <div className="mt-2">
            <label className="text-[10px] uppercase text-gray-500">Reason (min 5 chars)</label>
            <textarea value={reason} onChange={(e) => setReason(e.target.value)}
                      rows={2}
                      placeholder="Audit-friendly justification"
                      className="w-full px-2 py-1.5 rounded bg-gray-800 border border-gray-700 text-sm" />
          </div>
          <button onClick={create} disabled={!formValid || submitting}
                  className="w-full mt-3 px-3 py-2 rounded-lg bg-orange-500/20 hover:bg-orange-500/30 text-orange-200 text-sm font-medium disabled:opacity-50 disabled:cursor-not-allowed">
            {submitting ? "Creating..." : "Create suppression"}
          </button>
          <p className="text-[10px] text-gray-500 mt-2">
            <AlertTriangle className="w-3 h-3 inline mr-1 text-yellow-500" />
            Admin role required. Action is audited.
          </p>
        </div>

        {/* List */}
        <div className="card p-5">
          <h3 className="text-sm font-semibold mb-3">
            Active suppressions ({list.length})
          </h3>
          {list.length === 0 ? (
            <div className="text-center py-8 text-gray-500 text-sm">
              No active suppressions
            </div>
          ) : (
            <div className="space-y-2 max-h-[400px] overflow-y-auto pr-1">
              {list.map(s => (
                <div key={s.suppression_id} className="rounded-lg border border-gray-700 bg-gray-800/40 p-3">
                  <div className="flex items-start justify-between gap-2">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="text-[10px] uppercase font-bold rounded bg-gray-700 px-1.5 py-0.5">
                          {s.scope}
                        </span>
                        <code className="text-xs font-mono text-orange-300 truncate">{s.target}</code>
                      </div>
                      <div className="text-[11px] text-gray-400 mt-1 truncate">{s.reason}</div>
                      <div className="flex items-center gap-2 text-[10px] text-gray-500 mt-1">
                        <Clock className="w-3 h-3" />
                        Expires {s.expires_at?.slice(0, 16)}
                        <span>·</span>
                        by {s.created_by}
                      </div>
                    </div>
                    <button onClick={() => remove(s.suppression_id)}
                            title="Delete suppression"
                            className="p-1 rounded hover:bg-red-500/20 text-red-400">
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
