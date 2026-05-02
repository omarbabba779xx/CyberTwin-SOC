import { useState, useEffect, useMemo, useCallback } from "react";
import {
  AlertTriangle, CheckCircle2, XCircle, Filter, RefreshCw, Send,
  ShieldAlert, Activity, ChevronRight,
} from "lucide-react";
import { API_BASE } from "../utils/api";

const API = API_BASE;

const VERDICT_OPTIONS = [
  { value: "true_positive",   label: "True Positive",   color: "red" },
  { value: "false_positive",  label: "False Positive",  color: "yellow" },
  { value: "benign_positive", label: "Benign",          color: "blue" },
  { value: "duplicate",       label: "Duplicate",       color: "gray" },
  { value: "needs_more_data", label: "Needs Data",      color: "purple" },
  { value: "escalated",       label: "Escalated",       color: "orange" },
  { value: "closed",          label: "Closed",          color: "emerald" },
];

const VERDICT_COLOR = {
  red: "bg-red-500/20 text-red-300 border-red-500/40",
  yellow: "bg-yellow-500/20 text-yellow-300 border-yellow-500/40",
  blue: "bg-blue-500/20 text-blue-300 border-blue-500/40",
  gray: "bg-gray-500/20 text-gray-300 border-gray-500/40",
  purple: "bg-purple-500/20 text-purple-300 border-purple-500/40",
  orange: "bg-orange-500/20 text-orange-300 border-orange-500/40",
  emerald: "bg-emerald-500/20 text-emerald-300 border-emerald-500/40",
};

const SEV_COLOR = {
  critical: "bg-red-500/20 text-red-300",
  high:     "bg-orange-500/20 text-orange-300",
  medium:   "bg-yellow-500/20 text-yellow-300",
  low:      "bg-blue-500/20 text-blue-300",
  info:     "bg-gray-500/20 text-gray-300",
};

export default function AlertQueue({ token, simResult }) {
  const [filter, setFilter] = useState("all");
  const [feedbackSummary, setFeedbackSummary] = useState(null);
  const [noisyRules, setNoisyRules] = useState([]);
  const [submitting, setSubmitting] = useState(null);
  const [error, setError] = useState(null);

  const headers = useMemo(
    () => ({ "Content-Type": "application/json", Authorization: `Bearer ${token}` }),
    [token]
  );

  const alerts = simResult?.alerts || [];

  const filteredAlerts = useMemo(() => {
    if (filter === "all") return alerts;
    return alerts.filter(a => a.severity === filter);
  }, [alerts, filter]);

  const fetchSummary = useCallback(async () => {
    try {
      const [s, n] = await Promise.all([
        fetch(`${API}/api/alerts/feedback/summary`, { headers }).then(r => r.json()),
        fetch(`${API}/api/alerts/feedback/noisy-rules`, { headers }).then(r => r.json()),
      ]);
      setFeedbackSummary(s);
      setNoisyRules(n.rules || []);
    } catch (e) {
      setError(String(e));
    }
  }, [headers]);

  useEffect(() => { fetchSummary(); }, [fetchSummary]);

  const sendFeedback = async (alert, verdict) => {
    setSubmitting(alert.alert_id); setError(null);
    try {
      const r = await fetch(`${API}/api/alerts/${alert.alert_id}/feedback`, {
        method: "POST", headers,
        body: JSON.stringify({
          rule_id: alert.rule_id, verdict, reason: "",
        }),
      });
      if (!r.ok) {
        const data = await r.json().catch(() => ({}));
        throw new Error(data.detail || `HTTP ${r.status}`);
      }
      await fetchSummary();
    } catch (e) {
      setError(String(e));
    } finally {
      setSubmitting(null);
    }
  };

  return (
    <div className="p-6 space-y-4 max-w-7xl mx-auto">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <AlertTriangle className="w-7 h-7 text-yellow-400" />
            Alert Queue
          </h1>
          <p className="text-sm text-gray-400 mt-1">
            Triage SOC alerts — every verdict is logged and feeds the rule-noise calculator
          </p>
        </div>
        <button onClick={fetchSummary}
                className="flex items-center gap-2 px-4 py-2 rounded-lg bg-gray-800 hover:bg-gray-700 text-sm">
          <RefreshCw className="w-4 h-4" />
          Refresh
        </button>
      </div>

      {/* Summary cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <div className="card p-4">
          <div className="text-[10px] uppercase tracking-wide text-gray-500">Open alerts</div>
          <div className="text-2xl font-bold mt-1">{alerts.length}</div>
        </div>
        <div className="card p-4">
          <div className="text-[10px] uppercase tracking-wide text-gray-500">Total feedback</div>
          <div className="text-2xl font-bold mt-1 text-blue-300">
            {feedbackSummary?.total_feedback ?? 0}
          </div>
        </div>
        <div className="card p-4">
          <div className="text-[10px] uppercase tracking-wide text-gray-500">FP rate</div>
          <div className="text-2xl font-bold mt-1 text-yellow-300">
            {feedbackSummary ? `${(feedbackSummary.false_positive_rate * 100).toFixed(0)}%` : "—"}
          </div>
        </div>
        <div className="card p-4">
          <div className="text-[10px] uppercase tracking-wide text-gray-500">Noisy rules</div>
          <div className="text-2xl font-bold mt-1 text-orange-300">{noisyRules.length}</div>
        </div>
      </div>

      {error && (
        <div className="card p-3 border-red-500/30 bg-red-500/5 text-sm text-red-300 flex items-center gap-2">
          <XCircle className="w-4 h-4" /> {error}
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Alerts list */}
        <div className="lg:col-span-2 card p-5">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-semibold flex items-center gap-2">
              <Activity className="w-4 h-4 text-purple-400" />
              Alerts {filter !== "all" && <span className="text-xs text-gray-500">({filter})</span>}
            </h3>
            <div className="flex items-center gap-1 text-xs">
              {["all", "critical", "high", "medium", "low"].map(s => (
                <button key={s} onClick={() => setFilter(s)}
                        className={`px-2 py-1 rounded ${filter === s ? "bg-purple-500/30 text-purple-200" : "text-gray-400 hover:text-gray-200"}`}>
                  {s}
                </button>
              ))}
            </div>
          </div>

          {filteredAlerts.length === 0 ? (
            <div className="text-center py-12 text-gray-500 text-sm">
              <CheckCircle2 className="w-10 h-10 mx-auto mb-2 text-emerald-500" />
              No alerts to triage. Run a simulation to generate some.
            </div>
          ) : (
            <div className="space-y-3 max-h-[600px] overflow-y-auto pr-1">
              {filteredAlerts.map(a => (
                <div key={a.alert_id} className="rounded-lg border border-gray-700 bg-gray-800/40 p-3">
                  <div className="flex items-start gap-3">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <code className="text-[11px] font-mono text-purple-300">{a.alert_id}</code>
                        <span className={`text-[10px] uppercase font-bold rounded-full px-2 py-0.5 ${SEV_COLOR[a.severity]}`}>
                          {a.severity}
                        </span>
                        <span className="text-xs text-gray-500">{a.rule_id}</span>
                      </div>
                      <div className="text-sm font-medium mt-1">{a.rule_name}</div>
                      <div className="text-xs text-gray-400 mt-0.5">
                        {a.affected_host || a.affected_user || "—"}{" "}
                        {a.technique_id && `· ${a.technique_id}`}
                      </div>
                    </div>
                  </div>
                  <div className="flex flex-wrap gap-1 mt-2">
                    {VERDICT_OPTIONS.slice(0, 4).map(v => (
                      <button
                        key={v.value}
                        disabled={submitting === a.alert_id}
                        onClick={() => sendFeedback(a, v.value)}
                        className={`text-[10px] px-2 py-1 rounded border transition ${VERDICT_COLOR[v.color]} hover:opacity-80 disabled:opacity-50`}
                      >
                        {v.label}
                      </button>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Right column: noisy rules */}
        <div className="card p-5">
          <h3 className="text-sm font-semibold mb-3 flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 text-orange-400" />
            Noisy rules ({noisyRules.length})
          </h3>
          {noisyRules.length === 0 ? (
            <div className="text-xs text-gray-500 text-center py-6">
              No noisy rules detected (need at least 3 feedback rows).
            </div>
          ) : (
            <div className="space-y-2 max-h-[600px] overflow-y-auto pr-1">
              {noisyRules.map(r => (
                <div key={r.rule_id} className="rounded-lg bg-gray-800/60 p-2.5 border border-orange-500/20">
                  <div className="flex items-center justify-between">
                    <code className="text-[11px] font-mono text-orange-300">{r.rule_id}</code>
                    <span className="text-xs text-orange-300 font-bold">
                      {(r.noise_rate * 100).toFixed(0)}%
                    </span>
                  </div>
                  <div className="text-[10px] text-gray-500 mt-1">
                    {r.total_feedback} feedback · {r.false_positive} FP · {r.benign_positive} benign
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
