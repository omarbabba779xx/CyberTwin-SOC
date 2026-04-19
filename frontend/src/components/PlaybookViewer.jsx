import React, { useState } from 'react'
import { BookOpen, X, Clock, CheckSquare, Square, ExternalLink, ChevronDown, ChevronRight, Shield, AlertTriangle, Wrench } from 'lucide-react'

const PLAYBOOKS = [
  {
    id: 'phishing',
    title: 'Phishing Response',
    techniqueId: 'T1566',
    techniqueName: 'Phishing',
    severity: 'high',
    estimatedTime: '30-45 min',
    description: 'Response playbook for phishing email incidents including spear-phishing attachments and links.',
    tools: ['Email Gateway', 'EDR Console', 'VirusTotal', 'URLScan.io', 'SIEM'],
    references: ['https://attack.mitre.org/techniques/T1566/'],
    steps: [
      { id: 1, text: 'Isolate the affected endpoint from the network', category: 'containment' },
      { id: 2, text: 'Identify and collect the phishing email (headers, body, attachments)', category: 'identification' },
      { id: 3, text: 'Analyze email headers for spoofed sender, relay path, and originating IP', category: 'analysis' },
      { id: 4, text: 'Submit attachments to sandbox for detonation analysis', category: 'analysis' },
      { id: 5, text: 'Check URL reputation and scan with URLScan.io', category: 'analysis' },
      { id: 6, text: 'Block sender domain and associated IPs at email gateway', category: 'containment' },
      { id: 7, text: 'Search mailboxes for similar emails sent to other users', category: 'identification' },
      { id: 8, text: 'Reset credentials if user clicked link or opened attachment', category: 'remediation' },
      { id: 9, text: 'Scan endpoint with EDR for indicators of compromise', category: 'analysis' },
      { id: 10, text: 'Update detection rules with new IOCs (hashes, domains, IPs)', category: 'remediation' },
      { id: 11, text: 'Document incident and notify affected users', category: 'documentation' },
    ],
  },
  {
    id: 'brute-force',
    title: 'Brute Force Response',
    techniqueId: 'T1110',
    techniqueName: 'Brute Force',
    severity: 'high',
    estimatedTime: '20-30 min',
    description: 'Response playbook for credential brute force attacks including password spraying and credential stuffing.',
    tools: ['SIEM', 'AD Console', 'Firewall', 'MFA Provider', 'IP Reputation DB'],
    references: ['https://attack.mitre.org/techniques/T1110/'],
    steps: [
      { id: 1, text: 'Lock the targeted account(s) to prevent unauthorized access', category: 'containment' },
      { id: 2, text: 'Check source IP against threat intelligence and reputation databases', category: 'analysis' },
      { id: 3, text: 'Block attacking source IPs at firewall/WAF', category: 'containment' },
      { id: 4, text: 'Review authentication logs for successful logins from attacker IPs', category: 'identification' },
      { id: 5, text: 'Enable or enforce MFA on targeted accounts', category: 'remediation' },
      { id: 6, text: 'Check for lateral movement from any compromised accounts', category: 'analysis' },
      { id: 7, text: 'Implement account lockout policies if not already configured', category: 'remediation' },
      { id: 8, text: 'Force password reset for any compromised accounts', category: 'remediation' },
      { id: 9, text: 'Update SIEM correlation rules for brute force detection', category: 'remediation' },
      { id: 10, text: 'Document findings and escalate if compromise confirmed', category: 'documentation' },
    ],
  },
  {
    id: 'lateral-movement',
    title: 'Lateral Movement Response',
    techniqueId: 'T1021',
    techniqueName: 'Remote Services',
    severity: 'critical',
    estimatedTime: '45-60 min',
    description: 'Response playbook for detected lateral movement using remote services (RDP, SMB, SSH, WinRM).',
    tools: ['EDR', 'SIEM', 'Network Monitor', 'AD Console', 'Firewall'],
    references: ['https://attack.mitre.org/techniques/T1021/'],
    steps: [
      { id: 1, text: 'Immediately isolate affected hosts from the network', category: 'containment' },
      { id: 2, text: 'Identify the initial compromise point and attack path', category: 'identification' },
      { id: 3, text: 'Reset credentials for all accounts used in lateral movement', category: 'remediation' },
      { id: 4, text: 'Check all accessed systems for persistence mechanisms', category: 'analysis' },
      { id: 5, text: 'Review network connections for unusual SMB/RDP/WinRM traffic', category: 'analysis' },
      { id: 6, text: 'Scan isolated hosts for malware and backdoors', category: 'analysis' },
      { id: 7, text: 'Review scheduled tasks, services, and registry for persistence', category: 'analysis' },
      { id: 8, text: 'Block unauthorized lateral protocols at network segmentation points', category: 'containment' },
      { id: 9, text: 'Verify AD integrity and check for golden/silver tickets', category: 'analysis' },
      { id: 10, text: 'Re-image compromised hosts if persistent backdoors found', category: 'remediation' },
      { id: 11, text: 'Update network segmentation rules and detection signatures', category: 'remediation' },
      { id: 12, text: 'Conduct post-incident review and update IR procedures', category: 'documentation' },
    ],
  },
  {
    id: 'data-exfiltration',
    title: 'Data Exfiltration Response',
    techniqueId: 'T1041',
    techniqueName: 'Exfiltration Over C2 Channel',
    severity: 'critical',
    estimatedTime: '60-90 min',
    description: 'Response playbook for detected data exfiltration attempts via command and control channels or alternative protocols.',
    tools: ['DLP', 'SIEM', 'Network Monitor', 'Firewall', 'Forensic Tools'],
    references: ['https://attack.mitre.org/techniques/T1041/'],
    steps: [
      { id: 1, text: 'Block destination IPs/domains at firewall immediately', category: 'containment' },
      { id: 2, text: 'Isolate source host to prevent further data loss', category: 'containment' },
      { id: 3, text: 'Quarantine any identified staging files or archives', category: 'containment' },
      { id: 4, text: 'Review DLP logs to determine scope and type of data exposed', category: 'analysis' },
      { id: 5, text: 'Analyze network flow data to quantify volume of exfiltrated data', category: 'analysis' },
      { id: 6, text: 'Preserve forensic evidence (memory dump, disk image)', category: 'documentation' },
      { id: 7, text: 'Identify all files accessed and transferred by the attacker', category: 'identification' },
      { id: 8, text: 'Check for data staging locations on compromised hosts', category: 'analysis' },
      { id: 9, text: 'Notify legal/compliance team if sensitive data confirmed exfiltrated', category: 'documentation' },
      { id: 10, text: 'Implement enhanced DLP rules for detected exfiltration method', category: 'remediation' },
      { id: 11, text: 'Conduct damage assessment and prepare breach notification if required', category: 'documentation' },
    ],
  },
  {
    id: 'credential-dumping',
    title: 'Credential Dumping Response',
    techniqueId: 'T1003',
    techniqueName: 'OS Credential Dumping',
    severity: 'critical',
    estimatedTime: '45-60 min',
    description: 'Response playbook for credential dumping attacks targeting LSASS, SAM, NTDS.dit, or cached credentials.',
    tools: ['EDR', 'AD Console', 'SIEM', 'Windows Defender Credential Guard', 'Mimikatz Detection'],
    references: ['https://attack.mitre.org/techniques/T1003/'],
    steps: [
      { id: 1, text: 'Isolate the host where credential dumping was detected', category: 'containment' },
      { id: 2, text: 'Force password reset for all potentially exposed accounts', category: 'remediation' },
      { id: 3, text: 'Check for golden ticket attacks (KRBTGT hash compromise)', category: 'analysis' },
      { id: 4, text: 'Review LSASS access logs and process injection events', category: 'analysis' },
      { id: 5, text: 'Check for tools like Mimikatz, ProcDump, or comsvcs.dll abuse', category: 'analysis' },
      { id: 6, text: 'Verify domain controller integrity and NTDS.dit access logs', category: 'analysis' },
      { id: 7, text: 'Enable Windows Credential Guard on affected systems', category: 'remediation' },
      { id: 8, text: 'Reset KRBTGT password twice if golden ticket suspected', category: 'remediation' },
      { id: 9, text: 'Audit privileged account usage across the domain', category: 'analysis' },
      { id: 10, text: 'Implement LSA protection and disable WDigest authentication', category: 'remediation' },
      { id: 11, text: 'Deploy enhanced LSASS monitoring rules in SIEM/EDR', category: 'remediation' },
      { id: 12, text: 'Document incident scope, compromised credentials, and remediation steps', category: 'documentation' },
    ],
  },
  {
    id: 'command-control',
    title: 'Command & Control Response',
    techniqueId: 'T1071',
    techniqueName: 'Application Layer Protocol',
    severity: 'high',
    estimatedTime: '30-45 min',
    description: 'Response playbook for detected C2 communication using application layer protocols (HTTP/S, DNS, SMTP).',
    tools: ['DNS Logs', 'SIEM', 'Firewall', 'EDR', 'Proxy Logs', 'Threat Intel Platform'],
    references: ['https://attack.mitre.org/techniques/T1071/'],
    steps: [
      { id: 1, text: 'Block C2 domain/IP at DNS sinkhole and firewall', category: 'containment' },
      { id: 2, text: 'Isolate the infected host from the network', category: 'containment' },
      { id: 3, text: 'Analyze DNS query logs for beaconing patterns and DGA domains', category: 'analysis' },
      { id: 4, text: 'Review proxy/firewall logs for C2 traffic patterns', category: 'analysis' },
      { id: 5, text: 'Identify the malware family via C2 protocol analysis', category: 'identification' },
      { id: 6, text: 'Scan host for backdoors, RATs, and persistence mechanisms', category: 'analysis' },
      { id: 7, text: 'Check for other hosts communicating with the same C2 infrastructure', category: 'identification' },
      { id: 8, text: 'Extract and analyze malware samples from the infected host', category: 'analysis' },
      { id: 9, text: 'Update threat intelligence platform with new C2 IOCs', category: 'remediation' },
      { id: 10, text: 'Deploy network-based detection for identified C2 protocol signatures', category: 'remediation' },
      { id: 11, text: 'Re-image infected host and restore from clean backup', category: 'remediation' },
      { id: 12, text: 'Conduct threat hunt for similar C2 patterns across the environment', category: 'documentation' },
    ],
  },
]

const severityConfig = {
  critical: { cls: 'badge-critical', label: 'Critical' },
  high: { cls: 'badge-high', label: 'High' },
  medium: { cls: 'badge-medium', label: 'Medium' },
  low: { cls: 'badge-low', label: 'Low' },
}

const categoryColors = {
  containment: 'text-red-400',
  identification: 'text-[#457b9d]',
  analysis: 'text-yellow-400',
  remediation: 'text-emerald-400',
  documentation: 'text-gray-400',
}

const categoryLabels = {
  containment: 'Containment',
  identification: 'Identification',
  analysis: 'Analysis',
  remediation: 'Remediation',
  documentation: 'Documentation',
}

export default function PlaybookViewer() {
  const [expandedPlaybook, setExpandedPlaybook] = useState(null)
  const [checkedSteps, setCheckedSteps] = useState({})

  const toggleStep = (playbookId, stepId) => {
    setCheckedSteps(prev => {
      const key = `${playbookId}-${stepId}`
      return { ...prev, [key]: !prev[key] }
    })
  }

  const getProgress = (playbook) => {
    const total = playbook.steps.length
    const checked = playbook.steps.filter(s => checkedSteps[`${playbook.id}-${s.id}`]).length
    return { checked, total, pct: Math.round((checked / total) * 100) }
  }

  return (
    <div className="space-y-6 animate-fade-in-up">
      {/* Header */}
      <div className="flex items-center gap-3">
        <div className="p-2.5 bg-gradient-to-br from-[#457b9d] to-[#e63946] rounded-xl shadow-lg shadow-[#e63946]/20">
          <BookOpen className="w-6 h-6 text-white" />
        </div>
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Response Playbooks</h1>
          <p className="text-gray-400 text-sm">
            SOC response procedures mapped to MITRE ATT&CK techniques
          </p>
        </div>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 stagger-children">
        <div className="card p-4">
          <p className="text-[10px] text-gray-400 uppercase tracking-wider mb-1">Total Playbooks</p>
          <span className="stat-number text-2xl text-white">{PLAYBOOKS.length}</span>
        </div>
        <div className="card p-4 border-l-2 border-l-red-500/60">
          <p className="text-[10px] text-gray-400 uppercase tracking-wider mb-1">Critical</p>
          <span className="stat-number text-2xl text-red-400">
            {PLAYBOOKS.filter(p => p.severity === 'critical').length}
          </span>
        </div>
        <div className="card p-4 border-l-2 border-l-orange-500/60">
          <p className="text-[10px] text-gray-400 uppercase tracking-wider mb-1">High</p>
          <span className="stat-number text-2xl text-orange-400">
            {PLAYBOOKS.filter(p => p.severity === 'high').length}
          </span>
        </div>
        <div className="card p-4 border-l-2 border-l-emerald-500/60">
          <p className="text-[10px] text-gray-400 uppercase tracking-wider mb-1">Techniques Covered</p>
          <span className="stat-number text-2xl text-emerald-400">{PLAYBOOKS.length}</span>
        </div>
      </div>

      {/* Playbook List */}
      <div className="space-y-3">
        {PLAYBOOKS.map(playbook => {
          const isExpanded = expandedPlaybook === playbook.id
          const progress = getProgress(playbook)
          const sevConfig = severityConfig[playbook.severity]

          return (
            <div key={playbook.id} className="card overflow-hidden">
              {/* Playbook Header */}
              <button
                onClick={() => setExpandedPlaybook(isExpanded ? null : playbook.id)}
                className="w-full text-left p-5 flex items-center gap-4 hover:bg-gray-800/30 transition-colors"
              >
                <div className="shrink-0">
                  {isExpanded
                    ? <ChevronDown className="w-5 h-5 text-gray-500" />
                    : <ChevronRight className="w-5 h-5 text-gray-500" />
                  }
                </div>

                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-3 mb-1">
                    <h3 className="text-base font-semibold text-gray-200">{playbook.title}</h3>
                    <span className={`px-2.5 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${sevConfig.cls}`}>
                      {sevConfig.label}
                    </span>
                    <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-[#e63946]/10 text-[#e63946] border border-[#e63946]/20">
                      {playbook.techniqueId}
                    </span>
                  </div>
                  <p className="text-xs text-gray-500 truncate">{playbook.description}</p>
                </div>

                <div className="shrink-0 flex items-center gap-4">
                  {/* Progress */}
                  <div className="text-right">
                    <p className="text-xs text-gray-500 mb-1">{progress.checked}/{progress.total} steps</p>
                    <div className="w-24 h-1.5 bg-gray-800 rounded-full overflow-hidden">
                      <div
                        className="h-full rounded-full transition-all duration-300"
                        style={{
                          width: `${progress.pct}%`,
                          backgroundColor: progress.pct === 100 ? '#3fb950' : '#e63946',
                        }}
                      />
                    </div>
                  </div>

                  {/* Time Estimate */}
                  <div className="flex items-center gap-1.5 text-xs text-gray-500">
                    <Clock className="w-3.5 h-3.5" />
                    <span>{playbook.estimatedTime}</span>
                  </div>
                </div>
              </button>

              {/* Expanded Content */}
              {isExpanded && (
                <div className="border-t border-[#21262d] bg-[#0d1117]/40">
                  {/* Info Bar */}
                  <div className="px-6 py-4 border-b border-[#21262d]/60 flex flex-wrap items-center gap-4">
                    <div className="flex items-center gap-2">
                      <Shield className="w-4 h-4 text-[#e63946]" />
                      <span className="text-xs text-gray-400">
                        MITRE: <span className="text-[#e63946] font-mono font-semibold">{playbook.techniqueId}</span>
                        {' '}<span className="text-gray-500">({playbook.techniqueName})</span>
                      </span>
                    </div>
                    <div className="h-4 w-px bg-gray-700/50" />
                    <div className="flex items-center gap-2">
                      <Clock className="w-4 h-4 text-[#457b9d]" />
                      <span className="text-xs text-gray-400">Est. {playbook.estimatedTime}</span>
                    </div>
                    <div className="h-4 w-px bg-gray-700/50" />
                    <div className="flex items-center gap-2">
                      <Wrench className="w-4 h-4 text-yellow-400" />
                      <span className="text-xs text-gray-400">
                        Tools: {playbook.tools.join(', ')}
                      </span>
                    </div>
                  </div>

                  {/* Category Legend */}
                  <div className="px-6 py-3 flex flex-wrap gap-3 border-b border-[#21262d]/40">
                    {Object.entries(categoryLabels).map(([key, label]) => (
                      <span key={key} className={`text-[10px] uppercase tracking-wider font-semibold ${categoryColors[key]}`}>
                        {label}
                      </span>
                    ))}
                  </div>

                  {/* Steps */}
                  <div className="px-6 py-4 space-y-2">
                    {playbook.steps.map(step => {
                      const isChecked = checkedSteps[`${playbook.id}-${step.id}`]
                      return (
                        <button
                          key={step.id}
                          onClick={(e) => { e.stopPropagation(); toggleStep(playbook.id, step.id) }}
                          className={`w-full text-left flex items-start gap-3 p-3 rounded-lg border transition-all ${
                            isChecked
                              ? 'border-emerald-500/20 bg-emerald-500/5'
                              : 'border-[#21262d] hover:border-gray-600 hover:bg-gray-800/30'
                          }`}
                        >
                          <div className="shrink-0 mt-0.5">
                            {isChecked
                              ? <CheckSquare className="w-4 h-4 text-emerald-400" />
                              : <Square className="w-4 h-4 text-gray-600" />
                            }
                          </div>
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2">
                              <span className="text-[10px] font-mono text-gray-600 bg-gray-800/60 px-1.5 py-0.5 rounded">
                                {String(step.id).padStart(2, '0')}
                              </span>
                              <span className={`text-[10px] uppercase tracking-wider font-semibold ${categoryColors[step.category]}`}>
                                {categoryLabels[step.category]}
                              </span>
                            </div>
                            <p className={`text-sm mt-1 ${isChecked ? 'text-gray-500 line-through' : 'text-gray-300'}`}>
                              {step.text}
                            </p>
                          </div>
                        </button>
                      )
                    })}
                  </div>

                  {/* Progress Footer */}
                  <div className="px-6 py-4 border-t border-[#21262d]/60 flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <div className="w-32 h-2 bg-gray-800 rounded-full overflow-hidden">
                        <div
                          className="h-full rounded-full transition-all duration-500"
                          style={{
                            width: `${progress.pct}%`,
                            backgroundColor: progress.pct === 100 ? '#3fb950' : '#e63946',
                          }}
                        />
                      </div>
                      <span className={`text-xs font-semibold ${progress.pct === 100 ? 'text-emerald-400' : 'text-gray-400'}`}>
                        {progress.pct}% Complete
                      </span>
                    </div>
                    {progress.pct === 100 && (
                      <span className="text-xs bg-emerald-500/10 text-emerald-400 px-3 py-1 rounded-full border border-emerald-500/20 font-semibold">
                        Playbook Complete
                      </span>
                    )}
                  </div>

                  {/* References */}
                  {playbook.references?.length > 0 && (
                    <div className="px-6 py-3 border-t border-[#21262d]/40 flex items-center gap-2">
                      <ExternalLink className="w-3.5 h-3.5 text-gray-600" />
                      {playbook.references.map((ref, i) => (
                        <a
                          key={i}
                          href={ref}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-xs text-[#457b9d] hover:text-[#e63946] transition-colors underline"
                        >
                          MITRE ATT&CK Reference
                        </a>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}
