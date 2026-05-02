import { useState, useEffect, useCallback } from "react";
import {
  Shield, Zap, CheckCircle2, XCircle, AlertTriangle,
  Send, RefreshCw, Activity, Search, ExternalLink, ChevronRight,
} from "lucide-react";
import { API_BASE } from "../utils/api";

const API = API_BASE;

function badge(connected) {
  return connected
    ? <span className="flex items-center gap-1 text-xs text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded-full font-medium"><CheckCircle2 className="w-3 h-3" />Online</span>
    : <span className="flex items-center gap-1 text-xs text-red-400 bg-red-500/10 px-2 py-0.5 rounded-full font-medium"><XCircle className="w-3 h-3" />Offline</span>;
}

export default function SOAR({ token, simResult }) {
  const [status, setStatus]       = useState(null);
  const [loadingStatus, setLS]    = useState(false);
  const [pushResult, setPushRes]  = useState(null);
  const [pushing, setPushing]     = useState(false);
  const [iocJobs, setIocJobs]     = useState(null);
  const [analyzing, setAnalyzing] = useState(false);
  const [analyzers, setAnalyzers] = useState([]);
  const [error, setError]         = useState(null);

  const headers = { "Content-Type": "application/json", Authorization: `Bearer ${token}` };

  const fetchStatus = useCallback(async () => {
    setLS(true);
    setError(null);
    try {
      const r = await fetch(`${API}/api/soar/status`, { headers });
      setStatus(await r.json());
    } catch (e) {
      setError("Cannot reach backend SOAR endpoint.");
    } finally {
      setLS(false);
    }
  }, [token]);

  const fetchAnalyzers = useCallback(async () => {
    try {
      const r = await fetch(`${API}/api/soar/analyzers`, { headers });
      if (r.ok) setAnalyzers(await r.json());
    } catch (_) {}
  }, [token]);

  useEffect(() => { fetchStatus(); fetchAnalyzers(); }, [fetchStatus, fetchAnalyzers]);

  const pushToTheHive = async () => {
    if (!simResult?.scenario?.id) return;
    setPushing(true); setPushRes(null); setError(null);
    try {
      const r = await fetch(`${API}/api/soar/push/${simResult.scenario.id}`, {
        method: "POST", headers,
      });
      const data = await r.json();
      if (!r.ok) setError(data.detail || "Push failed");
      else setPushRes(data);
    } catch (e) {
      setError(String(e));
    } finally {
      setPushing(false);
    }
  };

  const analyzeIocs = async () => {
    if (!simResult?.scenario?.id) return;
    setAnalyzing(true); setIocJobs(null); setError(null);
    try {
      const r = await fetch(`${API}/api/soar/analyze-iocs/${simResult.scenario.id}`, {
        method: "POST", headers,
      });
      const data = await r.json();
      if (!r.ok) setError(data.detail || "Cortex analysis failed");
      else setIocJobs(data);
    } catch (e) {
      setError(String(e));
    } finally {
      setAnalyzing(false);
    }
  };

  const hasResult = Boolean(simResult?.scenario?.id);

  return (
    <div className="p-6 space-y-6 max-w-5xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Shield className="w-7 h-7 text-purple-400" />
            SOAR Integration
          </h1>
          <p className="text-sm text-gray-400 mt-1">
            TheHive v5 case management &amp; Cortex automated analysis
          </p>
        </div>
        <button
          onClick={fetchStatus}
          disabled={loadingStatus}
          className="flex items-center gap-2 px-4 py-2 rounded-lg bg-gray-800 hover:bg-gray-700 text-sm transition-colors disabled:opacity-50"
        >
          <RefreshCw className={`w-4 h-4 ${loadingStatus ? "animate-spin" : ""}`} />
          Refresh
        </button>
      </div>

      {/* Connection Status */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* TheHive */}
        <div className="card p-5">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2">
              <div className="p-2 rounded-lg bg-orange-500/10">
                <Shield className="w-5 h-5 text-orange-400" />
              </div>
              <div>
                <div className="font-semibold text-sm">TheHive 5</div>
                <div className="text-xs text-gray-500">Case Management</div>
              </div>
            </div>
            {status ? badge(status.thehive?.connected) : <span className="text-gray-500 text-xs">—</span>}
          </div>
          {status?.thehive && (
            <div className="text-xs text-gray-400 space-y-1 mt-2 border-t border-gray-700 pt-2">
              <div className="flex justify-between">
                <span>URL</span>
                <span className="font-mono text-gray-300">{status.thehive.url}</span>
              </div>
              {status.thehive.connected && (
                <div className="flex justify-between">
                  <span>Version</span>
                  <span className="font-mono text-gray-300">{status.thehive.version}</span>
                </div>
              )}
              {status.thehive.error && (
                <div className="text-red-400 text-[10px] mt-1">{status.thehive.error}</div>
              )}
            </div>
          )}
        </div>

        {/* Cortex */}
        <div className="card p-5">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2">
              <div className="p-2 rounded-lg bg-blue-500/10">
                <Zap className="w-5 h-5 text-blue-400" />
              </div>
              <div>
                <div className="font-semibold text-sm">Cortex 3</div>
                <div className="text-xs text-gray-500">Automated Analysis</div>
              </div>
            </div>
            {status ? badge(status.cortex?.connected) : <span className="text-gray-500 text-xs">—</span>}
          </div>
          {status?.cortex && (
            <div className="text-xs text-gray-400 space-y-1 mt-2 border-t border-gray-700 pt-2">
              <div className="flex justify-between">
                <span>URL</span>
                <span className="font-mono text-gray-300">{status.cortex.url}</span>
              </div>
              {status.cortex.connected && (
                <div className="flex justify-between">
                  <span>Version</span>
                  <span className="font-mono text-gray-300">{status.cortex.version}</span>
                </div>
              )}
              {status.cortex.error && (
                <div className="text-red-400 text-[10px] mt-1">{status.cortex.error}</div>
              )}
            </div>
          )}
        </div>
      </div>

      {/* Actions */}
      <div className="card p-5">
        <h2 className="text-base font-semibold mb-4 flex items-center gap-2">
          <Activity className="w-4 h-4 text-purple-400" />
          Actions
        </h2>

        {!hasResult && (
          <div className="text-sm text-gray-500 bg-gray-800/50 rounded-lg p-4 text-center">
            <AlertTriangle className="w-5 h-5 mx-auto mb-2 text-yellow-500" />
            Run a simulation first to enable SOAR actions
          </div>
        )}

        {hasResult && (
          <div className="space-y-3">
            {/* Push to TheHive */}
            <div className="flex items-center justify-between p-4 rounded-lg bg-gray-800/50 border border-gray-700">
              <div>
                <div className="font-medium text-sm flex items-center gap-2">
                  <Shield className="w-4 h-4 text-orange-400" />
                  Push to TheHive
                </div>
                <div className="text-xs text-gray-400 mt-0.5">
                  Create a case with IOCs and response tasks from the last simulation
                </div>
              </div>
              <button
                onClick={pushToTheHive}
                disabled={pushing || !status?.thehive?.connected}
                className="flex items-center gap-2 px-4 py-2 rounded-lg bg-orange-500/20 hover:bg-orange-500/30 text-orange-300 text-sm transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
              >
                {pushing ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Send className="w-3.5 h-3.5" />}
                {pushing ? "Pushing…" : "Push Case"}
              </button>
            </div>

            {/* Analyze IOCs */}
            <div className="flex items-center justify-between p-4 rounded-lg bg-gray-800/50 border border-gray-700">
              <div>
                <div className="font-medium text-sm flex items-center gap-2">
                  <Search className="w-4 h-4 text-blue-400" />
                  Analyze IOCs with Cortex
                </div>
                <div className="text-xs text-gray-400 mt-0.5">
                  Submit IOCs from the last simulation to Cortex analyzers (VirusTotal, AbuseIPDB…)
                </div>
              </div>
              <button
                onClick={analyzeIocs}
                disabled={analyzing || !status?.cortex?.connected}
                className="flex items-center gap-2 px-4 py-2 rounded-lg bg-blue-500/20 hover:bg-blue-500/30 text-blue-300 text-sm transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
              >
                {analyzing ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Zap className="w-3.5 h-3.5" />}
                {analyzing ? "Analyzing…" : "Run Analysis"}
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Error */}
      {error && (
        <div className="card p-4 border border-red-500/30 bg-red-500/5 flex items-start gap-3">
          <XCircle className="w-4 h-4 text-red-400 mt-0.5 flex-shrink-0" />
          <p className="text-sm text-red-300">{error}</p>
        </div>
      )}

      {/* TheHive Push Result */}
      {pushResult && (
        <div className="card p-5">
          <h3 className="text-sm font-semibold mb-3 flex items-center gap-2 text-emerald-400">
            <CheckCircle2 className="w-4 h-4" />
            Case Created Successfully
          </h3>
          <div className="space-y-2 text-sm">
            <div className="flex items-center justify-between">
              <span className="text-gray-400">Case Number</span>
              <span className="font-mono font-bold text-orange-300">#{pushResult.case_number}</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-gray-400">Observables (IOCs)</span>
              <span className="font-mono">{pushResult.observables_added}</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-gray-400">Response Tasks</span>
              <span className="font-mono">{pushResult.tasks_added}</span>
            </div>
            {pushResult.thehive_url && (
              <a
                href={pushResult.thehive_url}
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center gap-1.5 text-xs text-orange-400 hover:text-orange-300 mt-2"
              >
                <ExternalLink className="w-3 h-3" />
                Open in TheHive
              </a>
            )}
          </div>
        </div>
      )}

      {/* Cortex IOC Jobs */}
      {iocJobs && (
        <div className="card p-5">
          <h3 className="text-sm font-semibold mb-3 flex items-center gap-2 text-blue-400">
            <Zap className="w-4 h-4" />
            Cortex Analysis Jobs — {iocJobs.iocs_submitted} submitted
          </h3>
          <div className="space-y-2">
            {iocJobs.jobs?.map((job, i) => (
              <div key={i} className="flex items-center justify-between p-2.5 rounded-lg bg-gray-800/60 text-xs">
                <span className="font-mono text-gray-300 truncate max-w-[200px]">{job.ioc}</span>
                <div className="flex items-center gap-2">
                  {job.analyzer ? (
                    <>
                      <span className="text-blue-300">{job.analyzer}</span>
                      <ChevronRight className="w-3 h-3 text-gray-500" />
                      <span className="font-mono text-gray-400">{job.job_id?.slice(0, 8)}…</span>
                    </>
                  ) : (
                    <span className="text-yellow-400">No analyzer</span>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Cortex Analyzers List */}
      {analyzers.length > 0 && (
        <div className="card p-5">
          <h3 className="text-sm font-semibold mb-3 flex items-center gap-2">
            <Zap className="w-4 h-4 text-blue-400" />
            Available Cortex Analyzers ({analyzers.length})
          </h3>
          <div className="space-y-1.5 max-h-48 overflow-y-auto">
            {analyzers.map((a, i) => (
              <div key={i} className="flex items-center justify-between text-xs py-1.5 px-2 rounded bg-gray-800/50">
                <span className="font-mono text-blue-300">{a.name || a.id}</span>
                <span className="text-gray-500">{(a.dataTypeList || []).join(", ")}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
