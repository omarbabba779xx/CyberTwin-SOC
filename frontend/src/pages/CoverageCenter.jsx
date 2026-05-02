import { useState, useEffect, useMemo, useCallback } from "react";
import {
  Shield, ShieldCheck, ShieldAlert, ShieldX, Target, AlertTriangle,
  CheckCircle2, XCircle, Clock, Database, RefreshCw, Filter, ChevronRight,
  TrendingUp, FileWarning,
} from "lucide-react";
import { API_BASE } from "../utils/api";

const API = API_BASE;

// ─── Status meta (color, icon, label) ────────────────────────────────────
const STATUS_META = {
  not_covered:           { color: "red",      icon: ShieldX,    label: "Not covered" },
  rule_exists:           { color: "yellow",   icon: Shield,     label: "Rule exists" },
  rule_exists_untested:  { color: "amber",    icon: Clock,      label: "Untested" },
  tested_and_detected:   { color: "emerald",  icon: ShieldCheck, label: "Validated" },
  tested_but_failed:     { color: "rose",     icon: XCircle,    label: "Failed" },
  noisy:                 { color: "orange",   icon: ShieldAlert, label: "Noisy" },
  needs_data_source:     { color: "purple",   icon: Database,   label: "Needs telemetry" },
  not_applicable:        { color: "gray",     icon: ChevronRight, label: "N/A" },
};

const COLOR_BG = {
  red:     "bg-red-500/10 text-red-400 border-red-500/30",
  yellow:  "bg-yellow-500/10 text-yellow-300 border-yellow-500/30",
  amber:   "bg-amber-500/10 text-amber-300 border-amber-500/30",
  emerald: "bg-emerald-500/10 text-emerald-400 border-emerald-500/30",
  rose:    "bg-rose-500/10 text-rose-400 border-rose-500/30",
  orange:  "bg-orange-500/10 text-orange-400 border-orange-500/30",
  purple:  "bg-purple-500/10 text-purple-400 border-purple-500/30",
  gray:    "bg-gray-500/10 text-gray-400 border-gray-500/30",
};

const RISK_COLOR = {
  critical: "text-red-400 bg-red-500/10",
  high:     "text-orange-400 bg-orange-500/10",
  medium:   "text-yellow-300 bg-yellow-500/10",
  low:      "text-blue-300 bg-blue-500/10",
};

// ─── ScoreBanner ─────────────────────────────────────────────────────────
function ScoreBanner({ summary }) {
  if (!summary) return null;
  const score = summary.global_score ?? 0;
  const scoreColor =
    score >= 70 ? "text-emerald-400" :
    score >= 40 ? "text-yellow-300" :
                  "text-red-400";

  const cards = [
    { label: "Catalog total",     value: summary.catalog_total,   tone: "neutral" },
    { label: "Validated",         value: summary.validated,       tone: "good" },
    { label: "Rule-mapped",       value: summary.rule_mapped,     tone: "neutral" },
    { label: "Tested",            value: summary.tested,          tone: "neutral" },
    { label: "Failed",            value: summary.failed,          tone: "bad" },
    { label: "Untested",          value: summary.untested,        tone: "warn" },
    { label: "Not covered",       value: summary.not_covered,     tone: "bad" },
    { label: "High-risk gaps",    value: summary.high_risk_gaps,  tone: "bad" },
  ];
  const toneClass = {
    good:    "text-emerald-400",
    bad:     "text-red-400",
    warn:    "text-yellow-300",
    neutral: "text-gray-200",
  };

  return (
    <div className="card p-6 mb-6">
      <div className="flex items-start justify-between gap-6 flex-wrap">
        <div className="flex items-center gap-4">
          <div className="p-3 rounded-xl bg-purple-500/15">
            <Target className="w-7 h-7 text-purple-400" />
          </div>
          <div>
            <h2 className="text-base font-semibold">Global Detection Coverage Score</h2>
            <p className="text-xs text-gray-400 mt-0.5">
              Honest weighted score (validated + rule-mapped) across the full MITRE catalog
            </p>
          </div>
        </div>
        <div className="text-right">
          <div className={`text-4xl font-bold tabular-nums ${scoreColor}`}>
            {score.toFixed(1)}
          </div>
          <div className="text-xs text-gray-500">/ 100</div>
        </div>
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mt-5">
        {cards.map((c) => (
          <div key={c.label} className="rounded-lg bg-gray-800/60 border border-gray-700 px-3 py-2.5">
            <div className="text-[10px] uppercase tracking-wide text-gray-500">{c.label}</div>
            <div className={`text-lg font-bold mt-0.5 tabular-nums ${toneClass[c.tone]}`}>
              {c.value ?? 0}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

// ─── StatusDistribution ──────────────────────────────────────────────────
function StatusDistribution({ summary }) {
  if (!summary?.by_status) return null;
  const total = summary.catalog_total || 1;
  const entries = Object.entries(summary.by_status)
    .filter(([_, n]) => n > 0)
    .sort((a, b) => b[1] - a[1]);

  return (
    <div className="card p-5 mb-6">
      <h3 className="text-sm font-semibold mb-4 flex items-center gap-2">
        <TrendingUp className="w-4 h-4 text-purple-400" />
        Status distribution
      </h3>
      <div className="flex h-3 rounded-full overflow-hidden border border-gray-700">
        {entries.map(([status, count]) => {
          const meta = STATUS_META[status] || STATUS_META.not_applicable;
          return (
            <div
              key={status}
              className={`${COLOR_BG[meta.color]?.split(" ")[0] || "bg-gray-700"}`}
              style={{ width: `${(count / total) * 100}%` }}
              title={`${meta.label}: ${count}`}
            />
          );
        })}
      </div>
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 mt-4">
        {entries.map(([status, count]) => {
          const meta = STATUS_META[status] || STATUS_META.not_applicable;
          const Icon = meta.icon;
          return (
            <div
              key={status}
              className={`flex items-center gap-2 rounded-lg border px-2.5 py-1.5 ${COLOR_BG[meta.color]}`}
            >
              <Icon className="w-3.5 h-3.5 flex-shrink-0" />
              <span className="text-[11px] font-medium truncate">{meta.label}</span>
              <span className="ml-auto text-xs font-mono">{count}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ─── TechniqueRow ────────────────────────────────────────────────────────
function TechniqueRow({ rec, onClick }) {
  const meta = STATUS_META[rec.status] || STATUS_META.not_applicable;
  const Icon = meta.icon;
  return (
    <button
      onClick={() => onClick(rec)}
      className="w-full text-left rounded-lg border border-gray-700 hover:border-purple-500/40 bg-gray-800/40 hover:bg-gray-800/70 transition-all p-3 flex items-center gap-3"
    >
      <div className={`p-1.5 rounded-md ${COLOR_BG[meta.color]} flex-shrink-0`}>
        <Icon className="w-4 h-4" />
      </div>
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <code className="text-xs font-mono text-purple-300">{rec.technique_id}</code>
          {rec.is_subtechnique && (
            <span className="text-[9px] uppercase text-gray-500 bg-gray-700/60 rounded px-1">sub</span>
          )}
          <span className="text-sm truncate">{rec.name}</span>
        </div>
        <div className="text-[11px] text-gray-500 mt-0.5">
          {rec.tactic_name} · {rec.rule_count} rule{rec.rule_count !== 1 ? "s" : ""} · {rec.scenario_count} scenario{rec.scenario_count !== 1 ? "s" : ""}
        </div>
      </div>
      <span className={`text-[10px] uppercase font-bold border rounded-full px-2 py-0.5 ${COLOR_BG[meta.color]}`}>
        {meta.label}
      </span>
    </button>
  );
}

// ─── TechniqueDetail (modal-like card) ───────────────────────────────────
function TechniqueDetail({ rec, onClose }) {
  if (!rec) return null;
  const meta = STATUS_META[rec.status] || STATUS_META.not_applicable;
  return (
    <div className="card p-5">
      <div className="flex items-start justify-between mb-3">
        <div>
          <code className="text-sm font-mono text-purple-300">{rec.technique_id}</code>
          <h3 className="text-base font-semibold mt-1">{rec.name}</h3>
          <p className="text-xs text-gray-400 mt-0.5">
            {rec.tactic_id} · {rec.tactic_name}
          </p>
        </div>
        <button onClick={onClose} className="text-gray-400 hover:text-white text-xs">close</button>
      </div>

      <div className={`inline-flex items-center gap-1.5 text-xs border rounded-full px-2.5 py-1 ${COLOR_BG[meta.color]} mb-4`}>
        <meta.icon className="w-3 h-3" /> {meta.label}
      </div>

      <div className="grid grid-cols-2 gap-3 text-xs">
        <div>
          <div className="text-gray-500 uppercase text-[10px]">Rules ({rec.rule_count})</div>
          <div className="font-mono text-gray-300 mt-1 break-all">
            {rec.rules?.length ? rec.rules.join(", ") : "—"}
          </div>
        </div>
        <div>
          <div className="text-gray-500 uppercase text-[10px]">Scenarios ({rec.scenario_count})</div>
          <div className="font-mono text-gray-300 mt-1 break-all">
            {rec.scenarios?.length ? rec.scenarios.join(", ") : "—"}
          </div>
        </div>
        <div>
          <div className="text-gray-500 uppercase text-[10px]">Confidence</div>
          <div className="font-mono text-gray-300 mt-1">{(rec.confidence * 100).toFixed(0)}%</div>
        </div>
        <div>
          <div className="text-gray-500 uppercase text-[10px]">Last simulation</div>
          <div className="font-mono text-gray-300 mt-1 truncate">
            {rec.last_simulation_at || "never"}
          </div>
        </div>
        <div className="col-span-2">
          <div className="text-gray-500 uppercase text-[10px]">Required logs</div>
          <div className="flex flex-wrap gap-1 mt-1">
            {rec.required_logs?.map(l => (
              <span
                key={l}
                className={`text-[10px] font-mono rounded px-1.5 py-0.5 ${
                  rec.missing_logs?.includes(l)
                    ? "bg-red-500/15 text-red-300"
                    : "bg-emerald-500/15 text-emerald-300"
                }`}
              >
                {l}
              </span>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

// ─── GapList ─────────────────────────────────────────────────────────────
function GapList({ gaps }) {
  if (!gaps?.length) return (
    <div className="text-center py-10 text-gray-500 text-sm">
      <ShieldCheck className="w-10 h-10 mx-auto mb-2 text-emerald-500" />
      No gaps to address right now
    </div>
  );
  return (
    <div className="space-y-3 max-h-[600px] overflow-y-auto pr-1">
      {gaps.map((g) => (
        <div key={g.technique_id} className="rounded-lg border border-gray-700 bg-gray-800/50 p-3">
          <div className="flex items-start justify-between gap-2 mb-2">
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 flex-wrap">
                <code className="text-xs font-mono text-purple-300">{g.technique_id}</code>
                <span className="text-sm font-medium truncate">{g.name}</span>
              </div>
              <div className="text-[11px] text-gray-500 mt-0.5">
                {g.tactic_name} · effort: {g.estimated_effort}
              </div>
            </div>
            <span className={`text-[10px] uppercase font-bold rounded-full px-2 py-0.5 ${RISK_COLOR[g.risk]}`}>
              {g.risk}
            </span>
          </div>
          {g.reasons?.length > 0 && (
            <ul className="text-xs text-gray-400 space-y-0.5 mb-2">
              {g.reasons.map((r, i) => (
                <li key={i} className="flex gap-1.5"><AlertTriangle className="w-3 h-3 mt-0.5 text-yellow-400 flex-shrink-0" /> {r}</li>
              ))}
            </ul>
          )}
          {g.recommended_actions?.length > 0 && (
            <ul className="text-xs text-emerald-300 space-y-0.5">
              {g.recommended_actions.slice(0, 4).map((r, i) => (
                <li key={i} className="flex gap-1.5"><CheckCircle2 className="w-3 h-3 mt-0.5 flex-shrink-0" /> {r}</li>
              ))}
            </ul>
          )}
        </div>
      ))}
    </div>
  );
}

// ─── Main page ───────────────────────────────────────────────────────────
export default function CoverageCenter({ token }) {
  const [summary, setSummary]   = useState(null);
  const [records, setRecords]   = useState([]);
  const [gaps, setGaps]         = useState([]);
  const [loading, setLoading]   = useState(true);
  const [error, setError]       = useState(null);
  const [filterStatus, setFilterStatus] = useState("");
  const [filterTactic, setFilterTactic] = useState("");
  const [search, setSearch]     = useState("");
  const [selected, setSelected] = useState(null);
  const [tab, setTab]           = useState("overview");  // overview | techniques | gaps

  const headers = useMemo(
    () => ({ "Content-Type": "application/json", Authorization: `Bearer ${token}` }),
    [token]
  );

  const fetchAll = useCallback(async () => {
    setLoading(true); setError(null);
    try {
      const [s, m, g] = await Promise.all([
        fetch(`${API}/api/coverage/summary`, { headers }).then(r => r.json()),
        fetch(`${API}/api/coverage/mitre`, { headers }).then(r => r.json()),
        fetch(`${API}/api/coverage/gaps?limit=100`, { headers }).then(r => r.json()),
      ]);
      setSummary(s);
      setRecords(m.records || []);
      setGaps(g.gaps || []);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }, [headers]);

  useEffect(() => { fetchAll(); }, [fetchAll]);

  const filteredRecords = useMemo(() => {
    let rs = records;
    if (filterStatus) rs = rs.filter(r => r.status === filterStatus);
    if (filterTactic) rs = rs.filter(r => r.tactic_id === filterTactic);
    if (search) {
      const q = search.toLowerCase();
      rs = rs.filter(r =>
        r.technique_id.toLowerCase().includes(q) ||
        r.name.toLowerCase().includes(q)
      );
    }
    return rs.slice(0, 200);  // cap to keep DOM lean
  }, [records, filterStatus, filterTactic, search]);

  const tactics = useMemo(() => {
    const m = new Map();
    records.forEach(r => m.set(r.tactic_id, r.tactic_name));
    return Array.from(m.entries()).sort();
  }, [records]);

  return (
    <div className="p-6 space-y-4 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Target className="w-7 h-7 text-purple-400" />
            Detection Coverage Center
          </h1>
          <p className="text-sm text-gray-400 mt-1">
            Honest, measurable MITRE ATT&CK coverage — built from rules, scenarios, and recent simulation evidence
          </p>
        </div>
        <button
          onClick={fetchAll}
          disabled={loading}
          className="flex items-center gap-2 px-4 py-2 rounded-lg bg-gray-800 hover:bg-gray-700 text-sm transition-colors disabled:opacity-50"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} />
          Refresh
        </button>
      </div>

      {error && (
        <div className="card p-3 border-red-500/30 bg-red-500/5 text-sm text-red-300 flex items-center gap-2">
          <XCircle className="w-4 h-4" /> {error}
        </div>
      )}

      {/* Tabs */}
      <div className="flex gap-1 border-b border-gray-700">
        {[
          { id: "overview",   label: "Overview" },
          { id: "techniques", label: `Techniques (${records.length})` },
          { id: "gaps",       label: `Gaps (${gaps.length})` },
        ].map(t => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            className={`px-4 py-2 text-sm border-b-2 transition-colors ${
              tab === t.id
                ? "border-purple-400 text-purple-300 font-medium"
                : "border-transparent text-gray-400 hover:text-gray-200"
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>

      {/* Overview tab */}
      {tab === "overview" && (
        <div>
          <ScoreBanner summary={summary} />
          <StatusDistribution summary={summary} />
          {/* Quick view of top gaps */}
          <div className="card p-5">
            <h3 className="text-sm font-semibold mb-4 flex items-center gap-2">
              <FileWarning className="w-4 h-4 text-orange-400" />
              Top {Math.min(5, gaps.length)} gaps to address first
            </h3>
            <GapList gaps={gaps.slice(0, 5)} />
          </div>
        </div>
      )}

      {/* Techniques tab */}
      {tab === "techniques" && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          <div className="lg:col-span-2 space-y-3">
            <div className="flex flex-wrap gap-2">
              <input
                type="text"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Search T1059, PowerShell..."
                className="flex-1 min-w-[200px] px-3 py-2 rounded-lg bg-gray-800 border border-gray-700 text-sm focus:outline-none focus:border-purple-500"
              />
              <select
                value={filterStatus}
                onChange={(e) => setFilterStatus(e.target.value)}
                className="px-3 py-2 rounded-lg bg-gray-800 border border-gray-700 text-sm"
              >
                <option value="">All status</option>
                {Object.entries(STATUS_META).map(([k, m]) => (
                  <option key={k} value={k}>{m.label}</option>
                ))}
              </select>
              <select
                value={filterTactic}
                onChange={(e) => setFilterTactic(e.target.value)}
                className="px-3 py-2 rounded-lg bg-gray-800 border border-gray-700 text-sm"
              >
                <option value="">All tactics</option>
                {tactics.map(([id, n]) => (
                  <option key={id} value={id}>{id} — {n}</option>
                ))}
              </select>
            </div>
            <div className="space-y-2 max-h-[700px] overflow-y-auto pr-1">
              {filteredRecords.map(r => (
                <TechniqueRow key={r.technique_id} rec={r} onClick={setSelected} />
              ))}
              {filteredRecords.length === 0 && (
                <div className="text-center py-8 text-gray-500 text-sm">
                  <Filter className="w-8 h-8 mx-auto mb-2" />
                  No technique matches the current filters.
                </div>
              )}
            </div>
          </div>
          <div className="lg:col-span-1">
            {selected ? (
              <TechniqueDetail rec={selected} onClose={() => setSelected(null)} />
            ) : (
              <div className="card p-5 text-center text-gray-500 text-sm">
                <Shield className="w-8 h-8 mx-auto mb-2 text-gray-600" />
                Click a technique to see details
              </div>
            )}
          </div>
        </div>
      )}

      {/* Gaps tab */}
      {tab === "gaps" && (
        <div className="card p-5">
          <h3 className="text-sm font-semibold mb-4 flex items-center gap-2">
            <FileWarning className="w-4 h-4 text-orange-400" />
            All gaps ({gaps.length})
          </h3>
          <GapList gaps={gaps} />
        </div>
      )}
    </div>
  );
}
