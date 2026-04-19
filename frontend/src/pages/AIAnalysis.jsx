import React from 'react'
import { Brain, Shield, AlertTriangle, Target, FileSearch, Cpu, Lock } from 'lucide-react'

const SECTION_COLORS = {
  'red': '#f87171',
  'orange': '#fb923c',
  'yellow': '#fbbf24',
  'green': '#4ade80',
  '[#e63946]': '#e63946',
  '[#457b9d]': '#457b9d',
}

const Section = ({ title, icon: Icon, children, color = '[#e63946]' }) => (
  <div className="card p-6">
    <div className="flex items-center gap-3 mb-4">
      <Icon className="w-5 h-5" style={{ color: SECTION_COLORS[color] || '#e63946' }} />
      <h3 className="text-lg font-semibold">{title}</h3>
    </div>
    {children}
  </div>
)

export default function AIAnalysis({ analysis }) {
  if (!analysis) {
    return (
      <div className="flex flex-col items-center justify-center h-96 text-gray-500">
        <Brain className="w-16 h-16 mb-4 text-gray-700" />
        <h2 className="text-xl font-semibold text-gray-400 mb-2">AI Analyst</h2>
        <p>Run a simulation to generate an AI-powered incident analysis.</p>
      </div>
    )
  }

  return (
    <div className="space-y-6 max-w-4xl mx-auto">
      {/* Header */}
      <div className="flex items-center gap-4">
        <div className="p-3 bg-[#457b9d]/20 rounded-xl">
          <Brain className="w-8 h-8 text-[#457b9d]" />
        </div>
        <div>
          <h1 className="text-2xl font-bold">AI Incident Analysis</h1>
          <p className="text-gray-400 text-sm">Automated Level 3 SOC Analyst Report</p>
        </div>
        {analysis.analyst_confidence && (
          <div className="ml-auto text-right">
            <p className="text-xs text-gray-500">Confidence</p>
            <p className={`text-2xl font-bold ${
              analysis.analyst_confidence.score >= 80 ? 'text-green-400' :
              analysis.analyst_confidence.score >= 60 ? 'text-yellow-400' : 'text-red-400'
            }`}>{analysis.analyst_confidence.score}%</p>
          </div>
        )}
      </div>

      {/* Executive Narrative */}
      <Section title="Executive Narrative" icon={FileSearch}>
        <div className="prose prose-invert prose-sm max-w-none">
          {(analysis.executive_narrative || '').split('\n\n').map((para, i) => (
            <p key={i} className="text-gray-300 leading-relaxed mb-3">{para}</p>
          ))}
        </div>
      </Section>

      {/* Attack Chain */}
      <Section title="Attack Chain Summary" icon={Target} color="red">
        <div className="space-y-3">
          {(analysis.attack_chain_summary || []).map((step, i) => (
            <div key={i} className="flex gap-4 items-start">
              <div className="flex flex-col items-center">
                <div className={`w-8 h-8 rounded-full flex items-center justify-center text-sm font-bold ${
                  step.detected ? 'bg-green-600/20 text-green-400 border border-green-600/30'
                  : 'bg-red-600/20 text-red-400 border border-red-600/30'
                }`}>{i + 1}</div>
                {i < (analysis.attack_chain_summary || []).length - 1 && (
                  <div className="w-0.5 h-8 bg-gray-700 mt-1" />
                )}
              </div>
              <div className="flex-1 pb-2">
                <div className="flex items-center gap-2">
                  <span className="font-semibold text-sm">{step.phase || step.name}</span>
                  {step.technique_id && (
                    <span className="text-xs text-[#e63946] font-mono bg-[#e63946]/10 px-1.5 py-0.5 rounded">{step.technique_id}</span>
                  )}
                  <span className={`text-xs font-bold ${step.detected ? 'text-green-400' : 'text-red-400'}`}>
                    {step.detected ? '● DETECTED' : '○ MISSED'}
                  </span>
                </div>
                <p className="text-xs text-gray-400 mt-1">{step.description}</p>
              </div>
            </div>
          ))}
        </div>
      </Section>

      {/* Threat Assessment */}
      <Section title="Threat Assessment" icon={AlertTriangle} color="orange">
        <div className={`p-4 rounded-lg border ${
          analysis.threat_assessment?.level === 'Critical' ? 'bg-red-600/10 border-red-600/30' :
          analysis.threat_assessment?.level === 'High' ? 'bg-orange-600/10 border-orange-600/30' :
          'bg-yellow-600/10 border-yellow-600/30'
        }`}>
          <div className="flex items-center gap-3 mb-2">
            <span className="text-lg font-bold">{analysis.threat_assessment?.level}</span>
          </div>
          <p className="text-sm text-gray-300">{analysis.threat_assessment?.justification}</p>
        </div>
      </Section>

      {/* Detection Gaps */}
      {analysis.detection_gaps?.length > 0 && (
        <Section title="Detection Gaps" icon={Shield} color="red">
          <div className="space-y-2">
            {analysis.detection_gaps.map((gap, i) => (
              <div key={i} className="bg-red-600/5 border border-red-600/20 rounded-lg p-3">
                <p className="font-medium text-sm text-red-300">{gap.gap}</p>
                <p className="text-xs text-gray-400 mt-1">{gap.recommendation}</p>
              </div>
            ))}
          </div>
        </Section>
      )}

      {/* IOC Summary */}
      {analysis.ioc_summary && (
        <Section title="Indicators of Compromise (IOCs)" icon={Cpu} color="[#457b9d]">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {analysis.ioc_summary.malicious_ips?.length > 0 && (
              <div>
                <p className="text-xs text-gray-500 font-semibold uppercase mb-2">Malicious IPs</p>
                {analysis.ioc_summary.malicious_ips.map((ip, i) => (
                  <div key={i} className="text-sm font-mono text-red-400 bg-gray-800 rounded px-2 py-1 mb-1">{ip}</div>
                ))}
              </div>
            )}
            {analysis.ioc_summary.suspicious_domains?.length > 0 && (
              <div>
                <p className="text-xs text-gray-500 font-semibold uppercase mb-2">Suspicious Domains</p>
                {analysis.ioc_summary.suspicious_domains.map((d, i) => (
                  <div key={i} className="text-sm font-mono text-orange-400 bg-gray-800 rounded px-2 py-1 mb-1">{d}</div>
                ))}
              </div>
            )}
            {analysis.ioc_summary.compromised_accounts?.length > 0 && (
              <div>
                <p className="text-xs text-gray-500 font-semibold uppercase mb-2">Compromised Accounts</p>
                {analysis.ioc_summary.compromised_accounts.map((a, i) => (
                  <div key={i} className="text-sm font-mono text-yellow-400 bg-gray-800 rounded px-2 py-1 mb-1">{a}</div>
                ))}
              </div>
            )}
            {analysis.ioc_summary.affected_hosts?.length > 0 && (
              <div>
                <p className="text-xs text-gray-500 font-semibold uppercase mb-2">Affected Hosts</p>
                {analysis.ioc_summary.affected_hosts.map((h, i) => (
                  <div key={i} className="text-sm font-mono text-[#457b9d] bg-gray-800 rounded px-2 py-1 mb-1">{h}</div>
                ))}
              </div>
            )}
          </div>
        </Section>
      )}

      {/* Immediate Actions */}
      <Section title="Immediate Response Actions" icon={AlertTriangle} color="yellow">
        <div className="space-y-2">
          {(analysis.immediate_actions || []).map((action, i) => (
            <div key={i} className="flex items-start gap-3 p-3 bg-gray-800/50 rounded-lg">
              <span className={`px-2 py-0.5 rounded text-xs font-bold ${
                action.priority === 'critical' ? 'bg-red-600/20 text-red-400' :
                action.priority === 'high' ? 'bg-orange-600/20 text-orange-400' :
                'bg-yellow-600/20 text-yellow-400'
              }`}>{action.priority}</span>
              <div>
                <p className="font-medium text-sm">{action.action}</p>
                <p className="text-xs text-gray-500 mt-0.5">{action.detail}</p>
              </div>
            </div>
          ))}
        </div>
      </Section>

      {/* Strategic Recommendations */}
      <Section title="Strategic Recommendations" icon={Shield} color="green">
        <div className="space-y-2">
          {(analysis.strategic_recommendations || []).map((rec, i) => (
            <div key={i} className="p-3 border border-gray-700 rounded-lg">
              <p className="font-medium text-sm text-green-300">{rec.title}</p>
              <p className="text-xs text-gray-400 mt-1">{rec.description}</p>
              {rec.framework && <p className="text-xs text-gray-600 mt-1">Framework: {rec.framework}</p>}
            </div>
          ))}
        </div>
      </Section>

      {/* Compliance Impact */}
      {analysis.compliance_impact && (
        <Section title="Compliance Impact" icon={Lock} color="[#457b9d]">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            {Object.entries(analysis.compliance_impact).map(([framework, impact]) => (
              <div key={framework} className="bg-gray-800 rounded-lg p-4">
                <p className="font-bold text-sm mb-1">{framework.toUpperCase()}</p>
                <p className="text-xs text-gray-400">{typeof impact === 'string' ? impact : impact.description || impact.impact || JSON.stringify(impact)}</p>
              </div>
            ))}
          </div>
        </Section>
      )}
    </div>
  )
}
