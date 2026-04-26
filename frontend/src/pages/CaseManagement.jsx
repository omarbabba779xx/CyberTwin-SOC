import { useState, useEffect, useMemo, useCallback } from "react";
import {
  Briefcase, Plus, RefreshCw, User, Calendar, Tag, MessageSquare,
  Paperclip, CheckCircle2, XCircle, Clock, AlertTriangle, ChevronRight,
} from "lucide-react";

const API = import.meta.env.VITE_API_URL || "";

const SEV_COLOR = {
  critical: "bg-red-500/20 text-red-300 border-red-500/30",
  high:     "bg-orange-500/20 text-orange-300 border-orange-500/30",
  medium:   "bg-yellow-500/20 text-yellow-300 border-yellow-500/30",
  low:      "bg-blue-500/20 text-blue-300 border-blue-500/30",
};

const STATUS_COLOR = {
  new:             "text-purple-300",
  open:            "text-blue-300",
  in_progress:     "text-yellow-300",
  pending:         "text-gray-300",
  resolved:        "text-emerald-300",
  closed:          "text-gray-500",
  false_positive:  "text-yellow-500",
};

function CaseCard({ c, onClick, active }) {
  return (
    <button
      onClick={onClick}
      className={`w-full text-left rounded-lg border p-3 transition-all ${
        active ? "border-purple-500/50 bg-purple-500/5" : "border-gray-700 bg-gray-800/40 hover:border-purple-500/30"
      }`}
    >
      <div className="flex items-center justify-between mb-1">
        <code className="text-[11px] font-mono text-purple-300">{c.case_id}</code>
        <span className={`text-[10px] uppercase font-bold rounded-full px-2 py-0.5 border ${SEV_COLOR[c.severity]}`}>
          {c.severity}
        </span>
      </div>
      <div className="text-sm font-medium truncate">{c.title}</div>
      <div className="flex items-center gap-3 text-[11px] text-gray-500 mt-1">
        <span className={STATUS_COLOR[c.status]}>{c.status}</span>
        {c.assignee && <span className="flex items-center gap-1"><User className="w-3 h-3" />{c.assignee}</span>}
      </div>
    </button>
  );
}

function NewCaseForm({ onCreated, simResult, headers }) {
  const [title, setTitle] = useState("");
  const [severity, setSeverity] = useState("medium");
  const [description, setDescription] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState(null);

  const submit = async () => {
    setSubmitting(true); setError(null);
    try {
      const r = await fetch(`${API}/api/cases`, {
        method: "POST", headers,
        body: JSON.stringify({
          title, severity, description,
          alert_ids: (simResult?.alerts || []).slice(0, 5).map(a => a.alert_id),
          mitre_techniques: Array.from(new Set(
            (simResult?.alerts || []).map(a => a.technique_id).filter(Boolean)
          )),
        }),
      });
      const data = await r.json();
      if (!r.ok) throw new Error(data.detail || `HTTP ${r.status}`);
      setTitle(""); setDescription("");
      onCreated?.(data);
    } catch (e) {
      setError(String(e));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="card p-4 space-y-3">
      <h3 className="text-sm font-semibold flex items-center gap-2">
        <Plus className="w-4 h-4 text-purple-400" />
        New Case
      </h3>
      <input
        value={title} onChange={(e) => setTitle(e.target.value)}
        placeholder="Case title (>= 3 chars)"
        className="w-full px-3 py-2 rounded-lg bg-gray-800 border border-gray-700 text-sm focus:outline-none focus:border-purple-500"
      />
      <select value={severity} onChange={(e) => setSeverity(e.target.value)}
              className="w-full px-3 py-2 rounded-lg bg-gray-800 border border-gray-700 text-sm">
        {["critical", "high", "medium", "low"].map(s => <option key={s}>{s}</option>)}
      </select>
      <textarea
        value={description} onChange={(e) => setDescription(e.target.value)}
        placeholder="Description"
        rows={3}
        className="w-full px-3 py-2 rounded-lg bg-gray-800 border border-gray-700 text-sm focus:outline-none focus:border-purple-500"
      />
      {error && <div className="text-xs text-red-300">{error}</div>}
      <button onClick={submit} disabled={submitting || title.length < 3}
              className="w-full px-3 py-2 rounded-lg bg-purple-500/20 hover:bg-purple-500/30 text-purple-200 text-sm font-medium disabled:opacity-50 disabled:cursor-not-allowed transition-colors">
        {submitting ? "Creating..." : "Create case"}
      </button>
    </div>
  );
}

function CaseDetail({ caseObj, headers, onChanged }) {
  const [comment, setComment] = useState("");
  const [closingReason, setClosingReason] = useState("");
  const [busy, setBusy] = useState(false);

  if (!caseObj) {
    return (
      <div className="card p-6 text-center text-gray-500 text-sm">
        <Briefcase className="w-10 h-10 mx-auto mb-2 text-gray-600" />
        Select a case to view its full timeline
      </div>
    );
  }

  const post = async (path, body, method = "POST") => {
    setBusy(true);
    try {
      const r = await fetch(`${API}/api/cases/${caseObj.case_id}${path}`, {
        method, headers, body: body ? JSON.stringify(body) : undefined,
      });
      if (r.ok) {
        const data = await r.json();
        onChanged?.(data);
      }
    } finally {
      setBusy(false);
    }
  };

  const addComment = async () => {
    if (!comment.trim()) return;
    await post("/comments", { body: comment });
    setComment("");
  };

  const closeCase = async () => {
    if (closingReason.length < 5) return;
    await post("/close", { closure_reason: closingReason, final_status: "closed" });
    setClosingReason("");
  };

  return (
    <div className="card p-5 space-y-4">
      <div className="flex items-start justify-between gap-3">
        <div className="flex-1 min-w-0">
          <code className="text-[11px] font-mono text-purple-300">{caseObj.case_id}</code>
          <h3 className="text-base font-semibold mt-1">{caseObj.title}</h3>
        </div>
        <div className="flex flex-col items-end gap-1 flex-shrink-0">
          <span className={`text-[10px] uppercase font-bold rounded-full px-2 py-0.5 border ${SEV_COLOR[caseObj.severity]}`}>
            {caseObj.severity}
          </span>
          <span className={`text-xs font-medium ${STATUS_COLOR[caseObj.status]}`}>
            {caseObj.status}
          </span>
        </div>
      </div>

      {caseObj.description && (
        <p className="text-sm text-gray-300 leading-relaxed">{caseObj.description}</p>
      )}

      <div className="grid grid-cols-2 gap-3 text-xs">
        <div><span className="text-gray-500">Assignee:</span> {caseObj.assignee || "unassigned"}</div>
        <div className="flex items-center gap-1">
          <Clock className="w-3 h-3 text-gray-500" />
          <span className="text-gray-500">SLA due:</span>
          <span className="text-gray-300 truncate">{caseObj.sla_due_at?.slice(0, 16) || "—"}</span>
        </div>
        <div className="col-span-2">
          <span className="text-gray-500">Alerts:</span>{" "}
          <span className="font-mono text-gray-300">
            {(caseObj.alert_ids || []).join(", ") || "—"}
          </span>
        </div>
        <div className="col-span-2">
          <span className="text-gray-500">MITRE:</span>{" "}
          {(caseObj.mitre_techniques || []).map(t => (
            <code key={t} className="text-[10px] font-mono mr-1 text-purple-300">{t}</code>
          )) || <span>—</span>}
        </div>
      </div>

      {/* Timeline: comments + evidence */}
      <div className="border-t border-gray-700 pt-3">
        <h4 className="text-xs font-semibold uppercase text-gray-400 mb-2 flex items-center gap-1">
          <MessageSquare className="w-3 h-3" />
          Comments ({caseObj.comments?.length || 0})
        </h4>
        <div className="space-y-2 max-h-[180px] overflow-y-auto pr-1">
          {(caseObj.comments || []).map(c => (
            <div key={c.comment_id} className="rounded bg-gray-800/60 p-2 text-xs">
              <div className="flex items-center gap-2 text-[10px] text-gray-500">
                <span className="font-medium text-gray-300">{c.author}</span>
                <span>·</span>
                <span>{c.timestamp?.slice(0, 16)}</span>
              </div>
              <div className="mt-1 text-gray-200">{c.body}</div>
            </div>
          ))}
        </div>
        <div className="flex gap-2 mt-2">
          <input
            value={comment} onChange={(e) => setComment(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && addComment()}
            placeholder="Add a comment..."
            className="flex-1 px-2 py-1.5 rounded bg-gray-800 border border-gray-700 text-xs"
          />
          <button onClick={addComment} disabled={busy || !comment.trim()}
                  className="px-3 py-1.5 rounded bg-purple-500/20 text-purple-200 text-xs disabled:opacity-50">
            Add
          </button>
        </div>
      </div>

      {/* Evidence */}
      {caseObj.evidence?.length > 0 && (
        <div className="border-t border-gray-700 pt-3">
          <h4 className="text-xs font-semibold uppercase text-gray-400 mb-2 flex items-center gap-1">
            <Paperclip className="w-3 h-3" />
            Evidence ({caseObj.evidence.length})
          </h4>
          <div className="space-y-1">
            {caseObj.evidence.map(e => (
              <div key={e.evidence_id} className="text-xs text-gray-300 rounded bg-gray-800/40 px-2 py-1.5">
                <span className="text-[10px] uppercase text-gray-500">{e.type}</span>{" "}
                <code className="font-mono text-blue-300">{e.reference}</code>
                {e.description && <span className="text-gray-400"> — {e.description}</span>}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Close */}
      {!["closed", "resolved", "false_positive"].includes(caseObj.status) && (
        <div className="border-t border-gray-700 pt-3">
          <h4 className="text-xs font-semibold uppercase text-gray-400 mb-2">Close case</h4>
          <input
            value={closingReason} onChange={(e) => setClosingReason(e.target.value)}
            placeholder="Closure reason (>= 5 chars)"
            className="w-full px-2 py-1.5 rounded bg-gray-800 border border-gray-700 text-xs mb-2"
          />
          <button onClick={closeCase} disabled={busy || closingReason.length < 5}
                  className="w-full px-3 py-1.5 rounded bg-red-500/20 hover:bg-red-500/30 text-red-200 text-xs disabled:opacity-50">
            Close case
          </button>
        </div>
      )}
    </div>
  );
}

export default function CaseManagement({ token, simResult }) {
  const [cases, setCases] = useState([]);
  const [selectedId, setSelectedId] = useState(null);
  const [selectedCase, setSelectedCase] = useState(null);
  const [loading, setLoading] = useState(true);

  const headers = useMemo(
    () => ({ "Content-Type": "application/json", Authorization: `Bearer ${token}` }),
    [token]
  );

  const fetchCases = useCallback(async () => {
    setLoading(true);
    try {
      const r = await fetch(`${API}/api/cases`, { headers });
      const data = await r.json();
      setCases(data.cases || []);
    } finally {
      setLoading(false);
    }
  }, [headers]);

  const fetchSelected = useCallback(async () => {
    if (!selectedId) return setSelectedCase(null);
    const r = await fetch(`${API}/api/cases/${selectedId}`, { headers });
    if (r.ok) setSelectedCase(await r.json());
  }, [selectedId, headers]);

  useEffect(() => { fetchCases(); }, [fetchCases]);
  useEffect(() => { fetchSelected(); }, [fetchSelected]);

  return (
    <div className="p-6 space-y-4 max-w-7xl mx-auto">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Briefcase className="w-7 h-7 text-purple-400" />
            Case Management
          </h1>
          <p className="text-sm text-gray-400 mt-1">
            Track investigations from alert to closure with audit-friendly timeline
          </p>
        </div>
        <button onClick={fetchCases}
                className="flex items-center gap-2 px-4 py-2 rounded-lg bg-gray-800 hover:bg-gray-700 text-sm">
          <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} />
          Refresh
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="space-y-3">
          <NewCaseForm
            simResult={simResult}
            headers={headers}
            onCreated={() => { fetchCases(); }}
          />
          <div className="card p-3">
            <h3 className="text-sm font-semibold mb-2">All cases ({cases.length})</h3>
            <div className="space-y-2 max-h-[500px] overflow-y-auto pr-1">
              {cases.length === 0 && (
                <div className="text-xs text-gray-500 text-center py-6">
                  No cases yet
                </div>
              )}
              {cases.map(c => (
                <CaseCard key={c.case_id} c={c}
                          active={selectedId === c.case_id}
                          onClick={() => setSelectedId(c.case_id)} />
              ))}
            </div>
          </div>
        </div>
        <div className="lg:col-span-2">
          <CaseDetail
            caseObj={selectedCase}
            headers={headers}
            onChanged={(updated) => {
              setSelectedCase(updated);
              fetchCases();
            }}
          />
        </div>
      </div>
    </div>
  );
}
