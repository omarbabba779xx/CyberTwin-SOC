import { useState, useEffect, useMemo, useCallback } from "react";
import {
  Upload, Activity, RefreshCw, FileText, Zap, Database, CheckCircle2,
  XCircle, ChevronRight, Trash2,
} from "lucide-react";
import { API_BASE } from "../utils/api";

const API = API_BASE;

const SOURCE_TYPES = [
  { value: "json",          label: "Generic JSON" },
  { value: "windows_event", label: "Windows EventLog" },
  { value: "sysmon",        label: "Sysmon" },
  { value: "syslog",        label: "Syslog (RFC3164/5424)" },
  { value: "cloudtrail",    label: "AWS CloudTrail" },
];

const SAMPLE_EVENT = JSON.stringify({
  System: { EventID: 4625, Computer: "WS-001", TimeCreated: new Date().toISOString() },
  EventData: { TargetUserName: "alice", IpAddress: "10.0.0.42" },
}, null, 2);

const SAMPLE_SYSLOG = "Apr 26 09:30:11 web01 sshd[12345]: Failed password for invalid user bob from 203.0.113.5 port 51234 ssh2";

export default function Ingestion({ token }) {
  const [stats, setStats] = useState(null);
  const [sources, setSources] = useState([]);
  const [tab, setTab] = useState("event");
  const [sourceType, setSourceType] = useState("windows_event");
  const [eventJson, setEventJson] = useState(SAMPLE_EVENT);
  const [syslogText, setSyslogText] = useState(SAMPLE_SYSLOG);
  const [batchJson, setBatchJson] = useState("[]");
  const [submitting, setSubmitting] = useState(false);
  const [feedback, setFeedback] = useState(null);
  const [error, setError] = useState(null);
  const [detectResult, setDetectResult] = useState(null);

  const headers = useMemo(
    () => ({ "Content-Type": "application/json", Authorization: `Bearer ${token}` }),
    [token]
  );

  const refresh = useCallback(async () => {
    try {
      const [s, src] = await Promise.all([
        fetch(`${API}/api/ingest/stats`, { headers }).then(r => r.json()),
        fetch(`${API}/api/ingest/sources`, { headers }).then(r => r.json()),
      ]);
      setStats(s);
      setSources(src.supported || []);
    } catch (e) {
      setError(String(e));
    }
  }, [headers]);

  useEffect(() => {
    refresh();
    const t = setInterval(refresh, 15000);
    return () => clearInterval(t);
  }, [refresh]);

  const submit = async (path, body) => {
    setSubmitting(true); setError(null); setFeedback(null);
    try {
      const r = await fetch(`${API}${path}`, {
        method: "POST", headers, body: JSON.stringify(body),
      });
      const data = await r.json();
      if (!r.ok) throw new Error(data.detail || `HTTP ${r.status}`);
      setFeedback(data);
      await refresh();
    } catch (e) {
      setError(String(e));
    } finally {
      setSubmitting(false);
    }
  };

  const submitEvent = () => {
    try {
      const evt = JSON.parse(eventJson);
      submit("/api/ingest/event", { event: evt, source_type: sourceType });
    } catch (e) {
      setError(`Invalid JSON: ${e}`);
    }
  };

  const submitBatch = () => {
    try {
      const events = JSON.parse(batchJson);
      if (!Array.isArray(events)) throw new Error("Batch must be a JSON array");
      submit("/api/ingest/batch", { events, source_type: sourceType });
    } catch (e) {
      setError(`Invalid JSON: ${e}`);
    }
  };

  const submitSyslog = () => {
    const lines = syslogText.split("\n").map(l => l.trim()).filter(Boolean);
    submit("/api/ingest/syslog", { lines });
  };

  const runDetect = async () => {
    setSubmitting(true); setError(null);
    try {
      const r = await fetch(`${API}/api/ingest/detect`, { method: "POST", headers });
      const data = await r.json();
      if (!r.ok) throw new Error(data.detail || `HTTP ${r.status}`);
      setDetectResult(data);
    } catch (e) {
      setError(String(e));
    } finally {
      setSubmitting(false);
    }
  };

  const clearBuffer = async () => {
    setSubmitting(true);
    try {
      await fetch(`${API}/api/ingest/buffer`, { method: "DELETE", headers });
      await refresh();
      setDetectResult(null);
    } finally {
      setSubmitting(false);
    }
  };

  const bySrc = stats?.by_source_type || {};
  const byCat = stats?.by_category || {};

  return (
    <div className="p-6 space-y-4 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Upload className="w-7 h-7 text-emerald-400" />
            Live Log Ingestion
          </h1>
          <p className="text-sm text-gray-400 mt-1">
            Send real logs (Windows EventLog, Sysmon, syslog, CloudTrail, JSON) — normalised to OCSF and detected
          </p>
        </div>
        <div className="flex gap-2">
          <button onClick={refresh}
                  className="flex items-center gap-2 px-3 py-2 rounded-lg bg-gray-800 hover:bg-gray-700 text-sm">
            <RefreshCw className="w-3.5 h-3.5" /> Refresh
          </button>
          <button onClick={clearBuffer} disabled={submitting}
                  className="flex items-center gap-2 px-3 py-2 rounded-lg bg-red-500/10 hover:bg-red-500/20 text-red-300 text-sm">
            <Trash2 className="w-3.5 h-3.5" /> Clear buffer
          </button>
        </div>
      </div>

      {/* Stat cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <div className="card p-4">
          <div className="text-[10px] uppercase tracking-wide text-gray-500">Buffered</div>
          <div className="text-2xl font-bold mt-1 text-emerald-400">{stats?.buffer_size ?? "—"}</div>
        </div>
        <div className="card p-4">
          <div className="text-[10px] uppercase tracking-wide text-gray-500">Total received</div>
          <div className="text-2xl font-bold mt-1">{stats?.total_events_received ?? 0}</div>
        </div>
        <div className="card p-4">
          <div className="text-[10px] uppercase tracking-wide text-gray-500">Drops</div>
          <div className="text-2xl font-bold mt-1 text-red-400">{stats?.total_events_dropped ?? 0}</div>
        </div>
        <div className="card p-4">
          <div className="text-[10px] uppercase tracking-wide text-gray-500">Alerts generated</div>
          <div className="text-2xl font-bold mt-1 text-yellow-300">{stats?.total_alerts_generated ?? 0}</div>
        </div>
      </div>

      {error && (
        <div className="card p-3 border-red-500/30 bg-red-500/5 text-sm text-red-300 flex items-center gap-2">
          <XCircle className="w-4 h-4 flex-shrink-0" /> {error}
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Submit forms */}
        <div className="lg:col-span-2 card p-5">
          <div className="flex gap-1 border-b border-gray-700 mb-4">
            {[
              { id: "event",  label: "Single event"  },
              { id: "batch",  label: "Batch"         },
              { id: "syslog", label: "Syslog text"   },
            ].map(t => (
              <button key={t.id} onClick={() => setTab(t.id)}
                      className={`px-3 py-2 text-sm border-b-2 transition-colors ${
                        tab === t.id ? "border-emerald-400 text-emerald-300 font-medium"
                                     : "border-transparent text-gray-400 hover:text-gray-200"
                      }`}>
                {t.label}
              </button>
            ))}
          </div>

          {tab !== "syslog" && (
            <div className="mb-3">
              <label className="text-[10px] uppercase text-gray-500">Source type</label>
              <select value={sourceType} onChange={(e) => setSourceType(e.target.value)}
                      className="w-full px-3 py-2 rounded-lg bg-gray-800 border border-gray-700 text-sm">
                {SOURCE_TYPES.map(s => <option key={s.value} value={s.value}>{s.label}</option>)}
              </select>
            </div>
          )}

          {tab === "event" && (
            <div>
              <label className="text-[10px] uppercase text-gray-500">Event JSON</label>
              <textarea value={eventJson} onChange={(e) => setEventJson(e.target.value)}
                        rows={14}
                        spellCheck={false}
                        className="w-full px-3 py-2 rounded-lg bg-gray-900 border border-gray-700 text-xs font-mono focus:outline-none focus:border-emerald-500" />
              <button onClick={submitEvent} disabled={submitting}
                      className="mt-3 w-full px-3 py-2 rounded-lg bg-emerald-500/20 hover:bg-emerald-500/30 text-emerald-200 text-sm font-medium disabled:opacity-50">
                {submitting ? "Submitting..." : "Submit event"}
              </button>
            </div>
          )}

          {tab === "batch" && (
            <div>
              <label className="text-[10px] uppercase text-gray-500">JSON array (max 5000)</label>
              <textarea value={batchJson} onChange={(e) => setBatchJson(e.target.value)}
                        rows={14}
                        spellCheck={false}
                        placeholder='[{"event_id":"e1","user":"alice"}, {...}]'
                        className="w-full px-3 py-2 rounded-lg bg-gray-900 border border-gray-700 text-xs font-mono" />
              <button onClick={submitBatch} disabled={submitting}
                      className="mt-3 w-full px-3 py-2 rounded-lg bg-emerald-500/20 hover:bg-emerald-500/30 text-emerald-200 text-sm font-medium disabled:opacity-50">
                {submitting ? "Submitting..." : "Submit batch"}
              </button>
            </div>
          )}

          {tab === "syslog" && (
            <div>
              <label className="text-[10px] uppercase text-gray-500">Syslog lines (one per line)</label>
              <textarea value={syslogText} onChange={(e) => setSyslogText(e.target.value)}
                        rows={14}
                        spellCheck={false}
                        className="w-full px-3 py-2 rounded-lg bg-gray-900 border border-gray-700 text-xs font-mono" />
              <button onClick={submitSyslog} disabled={submitting}
                      className="mt-3 w-full px-3 py-2 rounded-lg bg-emerald-500/20 hover:bg-emerald-500/30 text-emerald-200 text-sm font-medium disabled:opacity-50">
                {submitting ? "Submitting..." : "Ingest syslog"}
              </button>
            </div>
          )}

          {feedback && (
            <div className="mt-3 rounded-lg bg-emerald-500/10 border border-emerald-500/30 p-2 text-xs">
              <CheckCircle2 className="w-3.5 h-3.5 inline mr-1 text-emerald-400" />
              <code className="text-gray-200">{JSON.stringify(feedback, null, 0).slice(0, 200)}</code>
            </div>
          )}
        </div>

        {/* Right column: detection + breakdown */}
        <div className="space-y-4">
          <div className="card p-5">
            <h3 className="text-sm font-semibold mb-3 flex items-center gap-2">
              <Zap className="w-4 h-4 text-yellow-400" />
              Run detection on buffer
            </h3>
            <button onClick={runDetect} disabled={submitting || !stats?.buffer_size}
                    className="w-full px-3 py-2 rounded-lg bg-yellow-500/20 hover:bg-yellow-500/30 text-yellow-200 text-sm font-medium disabled:opacity-50">
              {submitting ? "Running..." : `Detect on ${stats?.buffer_size || 0} events`}
            </button>
            {detectResult && (
              <div className="mt-3 text-xs space-y-1 border-t border-gray-700 pt-3">
                <div>Events analysed: <span className="font-mono text-gray-300">{detectResult.events_analysed}</span></div>
                <div>Alerts: <span className="font-mono text-yellow-300">{detectResult.alerts?.length || 0}</span></div>
                <div>Incidents: <span className="font-mono text-red-300">{detectResult.incidents?.length || 0}</span></div>
              </div>
            )}
          </div>

          <div className="card p-5">
            <h3 className="text-sm font-semibold mb-3 flex items-center gap-2">
              <Database className="w-4 h-4 text-purple-400" />
              By source type
            </h3>
            {Object.keys(bySrc).length === 0 ? (
              <div className="text-xs text-gray-500 text-center py-4">No events yet</div>
            ) : (
              <div className="space-y-1.5 text-xs">
                {Object.entries(bySrc).map(([k, v]) => (
                  <div key={k} className="flex items-center justify-between">
                    <code className="font-mono text-gray-300">{k}</code>
                    <span className="font-mono text-purple-300">{v}</span>
                  </div>
                ))}
              </div>
            )}
          </div>

          <div className="card p-5">
            <h3 className="text-sm font-semibold mb-3">By category</h3>
            {Object.keys(byCat).length === 0 ? (
              <div className="text-xs text-gray-500 text-center py-4">—</div>
            ) : (
              <div className="space-y-1.5 text-xs">
                {Object.entries(byCat).map(([k, v]) => (
                  <div key={k} className="flex items-center justify-between">
                    <span className="text-gray-400">{k}</span>
                    <span className="font-mono">{v}</span>
                  </div>
                ))}
              </div>
            )}
          </div>

          <div className="card p-5">
            <h3 className="text-sm font-semibold mb-2 flex items-center gap-2">
              <FileText className="w-4 h-4 text-gray-400" />
              Supported sources ({sources.length})
            </h3>
            <div className="flex flex-wrap gap-1">
              {sources.map(s => (
                <code key={s} className="text-[10px] font-mono bg-gray-800 text-gray-300 px-1.5 py-0.5 rounded">{s}</code>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
