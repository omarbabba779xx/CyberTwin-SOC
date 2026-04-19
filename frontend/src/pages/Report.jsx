import React, { useRef, useState } from 'react'
import { FileText, Download, Printer, Loader2 } from 'lucide-react'
import ScoreGauge from '../components/ScoreGauge'

export default function Report({ report, scores }) {
  const reportRef = useRef(null)
  const printRef = useRef(null)
  const [exporting, setExporting] = useState(false)

  if (!report) {
    return (
      <div className="flex flex-col items-center justify-center h-96 text-gray-500">
        <FileText className="w-12 h-12 mb-3 text-gray-700" />
        <p>No report available. Run a simulation first.</p>
      </div>
    )
  }

  const exec = report.executive_summary || {}
  const detection = report.detection_analysis || {}
  const mitre = report.mitre_attack_coverage || {}
  const recs = report.recommendations || []
  const risk = report.risk_assessment || {}

  const downloadJSON = () => {
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `cybertwin-report-${report.report_id || 'latest'}.json`
    a.click()
    URL.revokeObjectURL(url)
  }

  const getScoreColor = (score) => {
    if (score >= 80) return '#22c55e'
    if (score >= 60) return '#f59e0b'
    if (score >= 40) return '#f97316'
    return '#ef4444'
  }

  const getRiskBadge = (level) => {
    const colors = { Low: '#22c55e', Medium: '#f59e0b', High: '#f97316', Critical: '#ef4444' }
    return colors[level] || '#94a3b8'
  }

  const exportPDF = async () => {
    setExporting(true)
    try {
      const html2pdf = (await import('html2pdf.js')).default

      // Build the printable content
      const el = printRef.current
      el.style.display = 'block'

      const opt = {
        margin: [10, 10, 10, 10],
        filename: `CyberTwin_SOC_Rapport_${Date.now()}.pdf`,
        image: { type: 'jpeg', quality: 0.98 },
        html2canvas: { scale: 2, useCORS: true },
        jsPDF: { unit: 'mm', format: 'a4', orientation: 'portrait' },
      }

      await html2pdf().set(opt).from(el).save()
      el.style.display = 'none'
    } catch (err) {
      console.error('PDF export failed:', err)
    }
    setExporting(false)
  }

  const ScoreBar = ({ score, label, color }) => (
    <div className="flex items-center gap-3">
      <span className="text-xs text-gray-400 w-24">{label}</span>
      <div className="flex-1 h-4 bg-gray-800 rounded-full overflow-hidden">
        <div className="h-full rounded-full transition-all duration-700" style={{ width: `${score}%`, background: color }} />
      </div>
      <span className="text-sm font-bold w-12 text-right" style={{ color }}>{score}%</span>
    </div>
  )

  const generatedDate = new Date().toLocaleDateString('fr-FR', {
    weekday: 'long', year: 'numeric', month: 'long', day: 'numeric',
    hour: '2-digit', minute: '2-digit'
  })

  return (
    <div className="space-y-6 max-w-4xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Incident Report</h1>
          <p className="text-gray-400 text-sm mt-1">{report.title}</p>
        </div>
        <div className="flex gap-2">
          <button onClick={downloadJSON}
            className="flex items-center gap-2 px-4 py-2 bg-gray-800 hover:bg-gray-700 rounded-lg text-sm font-medium transition border border-gray-700">
            <Download className="w-4 h-4" /> JSON
          </button>
          <button onClick={exportPDF} disabled={exporting}
            className="btn-primary flex items-center gap-2 px-5 py-2.5 rounded-lg text-sm font-semibold transition shadow-lg disabled:opacity-50 text-white">
            {exporting ? <Loader2 className="w-4 h-4 animate-spin" /> : <Download className="w-4 h-4" />}
            {exporting ? 'Generation en cours...' : 'Telecharger le rapport PDF'}
          </button>
        </div>
      </div>

      {/* ================================================================== */}
      {/* PRINTABLE PDF DIV (hidden, used by html2pdf)                       */}
      {/* ================================================================== */}
      <div ref={printRef} style={{ display: 'none', fontFamily: 'Arial, Helvetica, sans-serif', color: '#1e293b', background: '#ffffff', padding: '30px', maxWidth: '210mm' }}>

        {/* PDF Header */}
        <div style={{ borderBottom: '3px solid #e63946', paddingBottom: '16px', marginBottom: '24px' }}>
          <h1 style={{ fontSize: '22px', fontWeight: 'bold', color: '#0f172a', margin: '0 0 4px 0' }}>
            RAPPORT DE SECURITE CONFIDENTIEL
          </h1>
          <p style={{ fontSize: '16px', color: '#e63946', margin: '0 0 12px 0', fontWeight: '600' }}>
            CyberTwin SOC - Jumeau Numerique de Cybersecurite
          </p>
          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '12px', color: '#64748b' }}>
            <span>Date de generation : {generatedDate}</span>
            <span>Classification : CONFIDENTIEL</span>
          </div>
        </div>

        {/* Scenario Info */}
        <div style={{ background: '#f1f5f9', border: '1px solid #e2e8f0', borderRadius: '8px', padding: '16px', marginBottom: '20px' }}>
          <h2 style={{ fontSize: '16px', fontWeight: 'bold', color: '#0f172a', margin: '0 0 8px 0' }}>Scenario : {exec.scenario_name}</h2>
          <div style={{ display: 'flex', gap: '24px', fontSize: '13px', color: '#475569' }}>
            <span><strong>Severite :</strong> {exec.scenario_severity}</span>
            <span><strong>Phases d'attaque :</strong> {exec.total_attack_phases}</span>
            <span><strong>Alertes generees :</strong> {exec.total_alerts_generated}</span>
            <span><strong>Niveau de risque :</strong> <span style={{ color: getRiskBadge(exec.risk_level), fontWeight: 'bold' }}>{exec.risk_level}</span></span>
          </div>
        </div>

        {/* Executive Summary */}
        <div style={{ marginBottom: '20px' }}>
          <h2 style={{ fontSize: '15px', fontWeight: 'bold', color: '#e63946', borderBottom: '1px solid #e2e8f0', paddingBottom: '6px', marginBottom: '10px' }}>
            1. Resume Executif
          </h2>
          <p style={{ fontSize: '13px', lineHeight: '1.6', color: '#334155' }}>{exec.assessment}</p>
        </div>

        {/* Scores */}
        <div style={{ marginBottom: '20px' }}>
          <h2 style={{ fontSize: '15px', fontWeight: 'bold', color: '#e63946', borderBottom: '1px solid #e2e8f0', paddingBottom: '6px', marginBottom: '10px' }}>
            2. Scores de Posture de Securite
          </h2>

          <div style={{ display: 'flex', justifyContent: 'center', marginBottom: '16px' }}>
            <div style={{ textAlign: 'center', padding: '16px 32px', background: '#f8fafc', border: '2px solid #e2e8f0', borderRadius: '12px' }}>
              <div style={{ fontSize: '36px', fontWeight: 'bold', color: getScoreColor(scores?.overall_score || 0) }}>
                {scores?.overall_score || 0}%
              </div>
              <div style={{ fontSize: '12px', color: '#64748b', fontWeight: '600' }}>SCORE GLOBAL</div>
              <div style={{ fontSize: '11px', color: '#94a3b8', marginTop: '4px' }}>Maturite : {scores?.maturity_level}</div>
            </div>
          </div>

          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '13px' }}>
            <thead>
              <tr style={{ background: '#f1f5f9' }}>
                <th style={{ textAlign: 'left', padding: '8px 12px', borderBottom: '1px solid #e2e8f0' }}>Dimension</th>
                <th style={{ textAlign: 'center', padding: '8px 12px', borderBottom: '1px solid #e2e8f0' }}>Poids</th>
                <th style={{ textAlign: 'center', padding: '8px 12px', borderBottom: '1px solid #e2e8f0' }}>Score</th>
                <th style={{ textAlign: 'left', padding: '8px 12px', borderBottom: '1px solid #e2e8f0', width: '40%' }}>Barre</th>
              </tr>
            </thead>
            <tbody>
              {[
                { label: 'Detection', score: scores?.detection_score || 0, weight: '35%', color: '#e63946' },
                { label: 'Couverture MITRE', score: scores?.coverage_score || 0, weight: '30%', color: '#457b9d' },
                { label: 'Reponse', score: scores?.response_score || 0, weight: '15%', color: '#f59e0b' },
                { label: 'Visibilite', score: scores?.visibility_score || 0, weight: '20%', color: '#22c55e' },
              ].map((dim, i) => (
                <tr key={i}>
                  <td style={{ padding: '8px 12px', borderBottom: '1px solid #f1f5f9', fontWeight: '500' }}>{dim.label}</td>
                  <td style={{ padding: '8px 12px', borderBottom: '1px solid #f1f5f9', textAlign: 'center', color: '#64748b' }}>{dim.weight}</td>
                  <td style={{ padding: '8px 12px', borderBottom: '1px solid #f1f5f9', textAlign: 'center', fontWeight: 'bold', color: dim.color }}>{dim.score}%</td>
                  <td style={{ padding: '8px 12px', borderBottom: '1px solid #f1f5f9' }}>
                    <div style={{ height: '12px', background: '#e2e8f0', borderRadius: '6px', overflow: 'hidden' }}>
                      <div style={{ height: '100%', width: `${dim.score}%`, background: dim.color, borderRadius: '6px' }} />
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Detection Analysis */}
        <div style={{ marginBottom: '20px' }}>
          <h2 style={{ fontSize: '15px', fontWeight: 'bold', color: '#e63946', borderBottom: '1px solid #e2e8f0', paddingBottom: '6px', marginBottom: '10px' }}>
            3. Analyse de Detection
          </h2>
          <div style={{ display: 'flex', gap: '16px', marginBottom: '12px' }}>
            <div style={{ flex: 1, textAlign: 'center', padding: '12px', background: '#f0fdf4', border: '1px solid #bbf7d0', borderRadius: '8px' }}>
              <div style={{ fontSize: '24px', fontWeight: 'bold', color: '#16a34a' }}>{detection.phases_detected || 0}</div>
              <div style={{ fontSize: '11px', color: '#64748b' }}>Phases detectees</div>
            </div>
            <div style={{ flex: 1, textAlign: 'center', padding: '12px', background: '#fef2f2', border: '1px solid #fecaca', borderRadius: '8px' }}>
              <div style={{ fontSize: '24px', fontWeight: 'bold', color: '#dc2626' }}>{detection.phases_missed || 0}</div>
              <div style={{ fontSize: '11px', color: '#64748b' }}>Phases manquees</div>
            </div>
            <div style={{ flex: 1, textAlign: 'center', padding: '12px', background: '#ecfeff', border: '1px solid #a5f3fc', borderRadius: '8px' }}>
              <div style={{ fontSize: '24px', fontWeight: 'bold', color: '#e63946' }}>{detection.detection_rate || 0}%</div>
              <div style={{ fontSize: '11px', color: '#64748b' }}>Taux de detection</div>
            </div>
          </div>

          {detection.phase_by_phase && (
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px' }}>
              <thead>
                <tr style={{ background: '#f1f5f9' }}>
                  <th style={{ textAlign: 'left', padding: '6px 10px', borderBottom: '1px solid #e2e8f0' }}>Phase</th>
                  <th style={{ textAlign: 'left', padding: '6px 10px', borderBottom: '1px solid #e2e8f0' }}>Nom</th>
                  <th style={{ textAlign: 'left', padding: '6px 10px', borderBottom: '1px solid #e2e8f0' }}>Technique</th>
                  <th style={{ textAlign: 'center', padding: '6px 10px', borderBottom: '1px solid #e2e8f0' }}>Statut</th>
                </tr>
              </thead>
              <tbody>
                {detection.phase_by_phase.map((p, i) => (
                  <tr key={i} style={{ background: p.detected ? '#f0fdf4' : '#fef2f2' }}>
                    <td style={{ padding: '6px 10px', borderBottom: '1px solid #f1f5f9' }}>Phase {p.phase}</td>
                    <td style={{ padding: '6px 10px', borderBottom: '1px solid #f1f5f9' }}>{p.name}</td>
                    <td style={{ padding: '6px 10px', borderBottom: '1px solid #f1f5f9', color: '#64748b' }}>{p.technique_id}</td>
                    <td style={{ padding: '6px 10px', borderBottom: '1px solid #f1f5f9', textAlign: 'center', fontWeight: 'bold', color: p.detected ? '#16a34a' : '#dc2626' }}>
                      {p.detected ? `Detecte (${p.alert_count})` : 'MANQUE'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        {/* MITRE Coverage */}
        <div style={{ marginBottom: '20px' }}>
          <h2 style={{ fontSize: '15px', fontWeight: 'bold', color: '#e63946', borderBottom: '1px solid #e2e8f0', paddingBottom: '6px', marginBottom: '10px' }}>
            4. Couverture MITRE ATT&CK
          </h2>
          <div style={{ display: 'flex', gap: '24px', fontSize: '13px', color: '#475569', marginBottom: '8px' }}>
            <span><strong>Techniques attendues :</strong> {mitre.expected_techniques?.length || 0}</span>
            <span><strong style={{ color: '#16a34a' }}>Detectees :</strong> {mitre.detected_techniques?.length || 0}</span>
            <span><strong style={{ color: '#dc2626' }}>Manquees :</strong> {mitre.missed_techniques?.length || 0}</span>
            <span><strong style={{ color: '#e63946' }}>Couverture :</strong> {mitre.coverage_percentage || 0}%</span>
          </div>
          {mitre.detected_techniques && mitre.detected_techniques.length > 0 && (
            <p style={{ fontSize: '12px', color: '#64748b' }}>
              <strong>Techniques detectees :</strong> {mitre.detected_techniques.join(', ')}
            </p>
          )}
          {mitre.missed_techniques && mitre.missed_techniques.length > 0 && (
            <p style={{ fontSize: '12px', color: '#dc2626' }}>
              <strong>Techniques manquees :</strong> {mitre.missed_techniques.join(', ')}
            </p>
          )}
        </div>

        {/* Risk Assessment */}
        <div style={{ marginBottom: '20px' }}>
          <h2 style={{ fontSize: '15px', fontWeight: 'bold', color: '#e63946', borderBottom: '1px solid #e2e8f0', paddingBottom: '6px', marginBottom: '10px' }}>
            5. Evaluation des Risques
          </h2>
          <div style={{ display: 'flex', gap: '24px', fontSize: '13px', marginBottom: '8px' }}>
            <span><strong>Posture de securite :</strong> {risk.security_posture}</span>
            <span><strong>Niveau de maturite :</strong> {risk.maturity_level}</span>
          </div>
          <p style={{ fontSize: '13px', lineHeight: '1.6', color: '#334155' }}>{risk.posture_description}</p>
        </div>

        {/* Recommendations */}
        {recs.length > 0 && (
          <div style={{ marginBottom: '20px' }}>
            <h2 style={{ fontSize: '15px', fontWeight: 'bold', color: '#e63946', borderBottom: '1px solid #e2e8f0', paddingBottom: '6px', marginBottom: '10px' }}>
              6. Recommandations
            </h2>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px' }}>
              <thead>
                <tr style={{ background: '#f1f5f9' }}>
                  <th style={{ textAlign: 'left', padding: '6px 10px', borderBottom: '1px solid #e2e8f0', width: '80px' }}>Priorite</th>
                  <th style={{ textAlign: 'left', padding: '6px 10px', borderBottom: '1px solid #e2e8f0' }}>Titre</th>
                  <th style={{ textAlign: 'left', padding: '6px 10px', borderBottom: '1px solid #e2e8f0' }}>Description</th>
                </tr>
              </thead>
              <tbody>
                {recs.map((r, i) => {
                  const prioColor = { critical: '#dc2626', high: '#f97316', medium: '#f59e0b', low: '#64748b' }
                  return (
                    <tr key={i}>
                      <td style={{ padding: '6px 10px', borderBottom: '1px solid #f1f5f9', fontWeight: 'bold', textTransform: 'uppercase', color: prioColor[r.priority] || '#64748b' }}>{r.priority}</td>
                      <td style={{ padding: '6px 10px', borderBottom: '1px solid #f1f5f9', fontWeight: '500' }}>{r.title}</td>
                      <td style={{ padding: '6px 10px', borderBottom: '1px solid #f1f5f9', color: '#64748b' }}>{r.description}</td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}

        {/* Conclusion */}
        {report.conclusion && (
          <div style={{ marginBottom: '20px' }}>
            <h2 style={{ fontSize: '15px', fontWeight: 'bold', color: '#e63946', borderBottom: '1px solid #e2e8f0', paddingBottom: '6px', marginBottom: '10px' }}>
              7. Conclusion
            </h2>
            <p style={{ fontSize: '13px', lineHeight: '1.6', color: '#334155' }}>{report.conclusion}</p>
          </div>
        )}

        {/* Footer */}
        <div style={{ borderTop: '2px solid #e63946', paddingTop: '12px', marginTop: '30px', display: 'flex', justifyContent: 'space-between', fontSize: '10px', color: '#94a3b8' }}>
          <span>Genere par CyberTwin SOC - Jumeau Numerique de Cybersecurite</span>
          <span>Document confidentiel - Ne pas diffuser</span>
        </div>
      </div>

      {/* ================================================================== */}
      {/* SCREEN DISPLAY (visible report)                                    */}
      {/* ================================================================== */}
      <div ref={reportRef} className="space-y-6" style={{ color: '#e2e8f0' }}>
        {/* PDF Header */}
        <div className="bg-gradient-to-r from-[#e63946]/20 to-[#f4a261]/20 border border-[#e63946]/30 rounded-xl p-6">
          <div className="flex items-center gap-4 mb-3">
            <div className="p-3 bg-[#e63946]/20 rounded-xl">
              <FileText className="w-8 h-8 text-[#e63946]" />
            </div>
            <div>
              <h2 className="text-xl font-bold text-white">CyberTwin SOC — Security Assessment Report</h2>
              <p className="text-sm text-gray-400">CONFIDENTIAL — Generated {new Date().toLocaleDateString('fr-FR')}</p>
            </div>
          </div>
        </div>

        {/* Executive Summary */}
        <section className="card p-6">
          <h2 className="text-lg font-semibold mb-4 text-[#e63946]">1. Executive Summary</h2>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4">
            <div><p className="text-xs text-gray-500">Scenario</p><p className="font-semibold">{exec.scenario_name}</p></div>
            <div><p className="text-xs text-gray-500">Severity</p><p className="font-semibold capitalize">{exec.scenario_severity}</p></div>
            <div><p className="text-xs text-gray-500">Attack Phases</p><p className="font-semibold">{exec.total_attack_phases}</p></div>
            <div><p className="text-xs text-gray-500">Alerts</p><p className="font-semibold">{exec.total_alerts_generated}</p></div>
          </div>
          <div className={`p-4 rounded-lg border ${
            exec.risk_level === 'Low' ? 'bg-green-600/10 border-green-600/20' :
            exec.risk_level === 'Medium' ? 'bg-yellow-600/10 border-yellow-600/20' :
            'bg-red-600/10 border-red-600/20'
          }`}>
            <p className="text-sm">{exec.assessment}</p>
          </div>
        </section>

        {/* Scores - bars for PDF compatibility */}
        <section className="card p-6">
          <h2 className="text-lg font-semibold mb-4">2. Security Posture Scores</h2>
          {/* SVG gauges for screen display */}
          <div className="flex flex-wrap justify-around gap-4 mb-6">
            <ScoreGauge score={scores?.overall_score || 0} label="Overall" size={130} />
            <ScoreGauge score={scores?.detection_score || 0} label="Detection" size={100} />
            <ScoreGauge score={scores?.coverage_score || 0} label="Coverage" size={100} />
            <ScoreGauge score={scores?.response_score || 0} label="Response" size={100} />
            <ScoreGauge score={scores?.visibility_score || 0} label="Visibility" size={100} />
          </div>
          {/* Bar fallback */}
          <div className="space-y-3">
            <ScoreBar score={scores?.overall_score || 0} label="Overall" color={scores?.overall_score >= 70 ? '#22c55e' : scores?.overall_score >= 40 ? '#f59e0b' : '#ef4444'} />
            <ScoreBar score={scores?.detection_score || 0} label="Detection" color="#e63946" />
            <ScoreBar score={scores?.coverage_score || 0} label="Coverage" color="#457b9d" />
            <ScoreBar score={scores?.response_score || 0} label="Response" color="#f59e0b" />
            <ScoreBar score={scores?.visibility_score || 0} label="Visibility" color="#22c55e" />
          </div>
          <div className="text-center mt-4">
            <span className="text-sm text-gray-400">Maturity Level: </span>
            <span className="text-sm font-bold text-[#e63946]">{scores?.maturity_level}</span>
          </div>
        </section>

        {/* Detection Analysis */}
        <section className="card p-6">
          <h2 className="text-lg font-semibold mb-4">3. Detection Analysis</h2>
          <div className="grid grid-cols-3 gap-4 mb-4">
            <div className="text-center p-3 bg-gray-800 rounded-lg">
              <p className="text-2xl font-bold text-green-400">{detection.phases_detected || 0}</p>
              <p className="text-xs text-gray-500">Detected</p>
            </div>
            <div className="text-center p-3 bg-gray-800 rounded-lg">
              <p className="text-2xl font-bold text-red-400">{detection.phases_missed || 0}</p>
              <p className="text-xs text-gray-500">Missed</p>
            </div>
            <div className="text-center p-3 bg-gray-800 rounded-lg">
              <p className="text-2xl font-bold text-[#e63946]">{detection.detection_rate || 0}%</p>
              <p className="text-xs text-gray-500">Detection Rate</p>
            </div>
          </div>
          {detection.phase_by_phase && (
            <div className="space-y-2">
              {detection.phase_by_phase.map((p, i) => (
                <div key={i} className={`flex items-center justify-between p-3 rounded-lg border ${
                  p.detected ? 'bg-green-600/10 border-green-600/20' : 'bg-red-600/10 border-red-600/20'
                }`}>
                  <div>
                    <span className="text-sm font-medium">Phase {p.phase}: {p.name}</span>
                    <span className="text-xs text-gray-500 ml-2">{p.technique_id}</span>
                  </div>
                  <span className={`text-xs font-bold ${p.detected ? 'text-green-400' : 'text-red-400'}`}>
                    {p.detected ? `Detected (${p.alert_count} alerts)` : 'MISSED'}
                  </span>
                </div>
              ))}
            </div>
          )}
        </section>

        {/* MITRE Coverage */}
        <section className="card p-6">
          <h2 className="text-lg font-semibold mb-4">4. MITRE ATT&CK Coverage</h2>
          <div className="flex gap-8 mb-4 text-sm">
            <div><span className="text-gray-500">Expected: </span><strong>{mitre.expected_techniques?.length || 0}</strong></div>
            <div><span className="text-gray-500">Detected: </span><strong className="text-green-400">{mitre.detected_techniques?.length || 0}</strong></div>
            <div><span className="text-gray-500">Missed: </span><strong className="text-red-400">{mitre.missed_techniques?.length || 0}</strong></div>
            <div><span className="text-gray-500">Coverage: </span><strong className="text-[#e63946]">{mitre.coverage_percentage || 0}%</strong></div>
          </div>
        </section>

        {/* Risk Assessment */}
        <section className="card p-6">
          <h2 className="text-lg font-semibold mb-4">5. Risk Assessment</h2>
          <div className="grid grid-cols-2 gap-4">
            <div><span className="text-xs text-gray-500">Security Posture</span><p className="font-bold text-lg">{risk.security_posture}</p></div>
            <div><span className="text-xs text-gray-500">Maturity Level</span><p className="font-bold text-lg">{risk.maturity_level}</p></div>
          </div>
          <p className="text-sm text-gray-400 mt-3">{risk.posture_description}</p>
        </section>

        {/* Recommendations */}
        <section className="card p-6">
          <h2 className="text-lg font-semibold mb-4">6. Recommendations</h2>
          <div className="space-y-3">
            {recs.map((r, i) => (
              <div key={i} className={`p-4 rounded-lg border ${
                r.priority === 'critical' ? 'border-red-600/30 bg-red-600/5' :
                r.priority === 'high' ? 'border-orange-600/30 bg-orange-600/5' :
                r.priority === 'medium' ? 'border-yellow-600/30 bg-yellow-600/5' :
                'border-gray-700 bg-gray-800/30'
              }`}>
                <div className="flex items-center gap-2 mb-1">
                  <span className={`text-xs font-bold uppercase ${
                    r.priority === 'critical' ? 'text-red-400' :
                    r.priority === 'high' ? 'text-orange-400' :
                    r.priority === 'medium' ? 'text-yellow-400' :
                    'text-gray-400'
                  }`}>{r.priority}</span>
                  <span className="text-xs text-gray-500">{r.category}</span>
                </div>
                <p className="font-medium text-sm">{r.title}</p>
                <p className="text-xs text-gray-400 mt-1">{r.description}</p>
              </div>
            ))}
          </div>
        </section>

        {/* Conclusion */}
        <section className="card p-6">
          <h2 className="text-lg font-semibold mb-3">7. Conclusion</h2>
          <p className="text-sm text-gray-300 leading-relaxed">{report.conclusion}</p>
        </section>

        {/* Footer */}
        <div className="text-center text-xs text-gray-600 border-t border-[#21262d] pt-4">
          Generated by CyberTwin SOC Platform — Digital Twin for Cyber Attack Simulation
        </div>
      </div>
    </div>
  )
}
