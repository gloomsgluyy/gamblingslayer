import { useState } from 'react'
import {
    analyzeInfrastructure,
    analyzeDNS,
    analyzeRotation,
    analyzeBehavior,
    analyzeWeakLinks,
    buildAttackChain,
    generateEvidenceReport,
    comprehensiveAnalysis,
    getAnalysisStatus
} from '../services/api'

function Analysis() {
    const [url, setUrl] = useState('')
    const [analysisType, setAnalysisType] = useState('comprehensive')
    const [loading, setLoading] = useState(false)
    const [result, setResult] = useState(null)
    const [error, setError] = useState(null)

    const analysisTypes = [
        { id: 'comprehensive', label: 'Comprehensive', description: 'Full analysis with all modules' },
        { id: 'infrastructure', label: 'Infrastructure (SIR)', description: 'DNS, WHOIS, SSL analysis' },
        { id: 'dns', label: 'DNS Analysis (DTSM)', description: 'DNS tampering detection' },
        { id: 'rotation', label: 'Domain Rotation (DRM)', description: 'Redirect chain mapping' },
        { id: 'behavior', label: 'Behavior (DABE)', description: 'Operator behavior patterns' },
        { id: 'weaklinks', label: 'Weak Links (IWLD)', description: 'Infrastructure vulnerabilities' },
        { id: 'attackchain', label: 'Attack Chain (SACR)', description: 'Event sequence reconstruction' },
        { id: 'evidence', label: 'Evidence Report (NERE)', description: 'Generate full report' }
    ]

    const handleAnalyze = async (e) => {
        e.preventDefault()
        if (!url.trim()) return

        setLoading(true)
        setResult(null)
        setError(null)

        try {
            let response
            switch (analysisType) {
                case 'comprehensive':
                    response = await comprehensiveAnalysis(url)
                    const analysisId = response.data.analysis_id
                    await pollAnalysis(analysisId)
                    return
                case 'infrastructure':
                    response = await analyzeInfrastructure(url)
                    break
                case 'dns':
                    response = await analyzeDNS(url)
                    break
                case 'rotation':
                    response = await analyzeRotation(url)
                    break
                case 'behavior':
                    response = await analyzeBehavior(url)
                    break
                case 'weaklinks':
                    response = await analyzeWeakLinks(url)
                    break
                case 'attackchain':
                    response = await buildAttackChain(url)
                    break
                case 'evidence':
                    response = await generateEvidenceReport(url)
                    break
                default:
                    throw new Error('Unknown analysis type')
            }
            setResult(response.data)
        } catch (err) {
            setError(err.response?.data?.detail || 'Analysis failed')
        } finally {
            setLoading(false)
        }
    }

    const pollAnalysis = async (analysisId) => {
        const maxAttempts = 60
        let attempts = 0

        const poll = async () => {
            try {
                const response = await getAnalysisStatus(analysisId)
                const data = response.data

                if (data.status === 'completed') {
                    setResult(data.result)
                    setLoading(false)
                } else if (data.status === 'failed') {
                    setError(data.error || 'Analysis failed')
                    setLoading(false)
                } else if (attempts < maxAttempts) {
                    attempts++
                    setTimeout(poll, 2000)
                } else {
                    setError('Analysis timeout')
                    setLoading(false)
                }
            } catch (err) {
                setError('Failed to get analysis status')
                setLoading(false)
            }
        }

        poll()
    }

    const renderResult = () => {
        if (!result) return null

        return (
            <div className="glass-card p-6">
                <h2 className="text-xl font-semibold text-dark-100 mb-6">Analysis Results</h2>

                {result.risk_assessment && (
                    <div className="mb-6 p-4 rounded-xl bg-dark-700/30">
                        <h3 className="text-lg font-medium text-dark-200 mb-3">Risk Assessment</h3>
                        <div className="grid grid-cols-2 gap-4">
                            <div>
                                <p className="text-sm text-dark-400">Risk Score</p>
                                <p className="text-3xl font-bold text-primary-400">{result.risk_assessment.risk_score || 0}</p>
                            </div>
                            <div>
                                <p className="text-sm text-dark-400">Risk Level</p>
                                <p className="text-xl font-semibold text-dark-100 capitalize">{result.risk_assessment.risk_level || 'Unknown'}</p>
                            </div>
                        </div>
                    </div>
                )}

                {result.findings && result.findings.length > 0 && (
                    <div className="mb-6">
                        <h3 className="text-lg font-medium text-dark-200 mb-3">Key Findings</h3>
                        <div className="space-y-2">
                            {result.findings.map((finding, i) => (
                                <div key={i} className={`p-3 rounded-lg border ${finding.severity === 'high' ? 'bg-danger-500/10 border-danger-500/20' :
                                        finding.severity === 'medium' ? 'bg-warning-500/10 border-warning-500/20' :
                                            'bg-dark-700/30 border-dark-600/50'
                                    }`}>
                                    <p className="font-medium text-dark-100">{finding.title}</p>
                                    <p className="text-sm text-dark-400">{finding.details}</p>
                                </div>
                            ))}
                        </div>
                    </div>
                )}

                {result.evidence && result.evidence.domain_info && (
                    <div className="mb-6">
                        <h3 className="text-lg font-medium text-dark-200 mb-3">Domain Information</h3>
                        <div className="grid grid-cols-2 gap-4 p-4 rounded-xl bg-dark-700/30">
                            <div>
                                <p className="text-sm text-dark-400">Domain</p>
                                <p className="text-dark-100">{result.evidence.domain_info.domain}</p>
                            </div>
                            <div>
                                <p className="text-sm text-dark-400">Registrar</p>
                                <p className="text-dark-100">{result.evidence.domain_info.registrar || 'Unknown'}</p>
                            </div>
                            <div>
                                <p className="text-sm text-dark-400">Hosting Provider</p>
                                <p className="text-dark-100">{result.evidence.domain_info.hosting_provider || 'Unknown'}</p>
                            </div>
                            <div>
                                <p className="text-sm text-dark-400">SSL Issuer</p>
                                <p className="text-dark-100">{result.evidence.domain_info.ssl_issuer || 'Unknown'}</p>
                            </div>
                        </div>
                    </div>
                )}

                {result.weak_links && result.weak_links.length > 0 && (
                    <div className="mb-6">
                        <h3 className="text-lg font-medium text-dark-200 mb-3">Weak Links</h3>
                        <div className="space-y-2">
                            {result.weak_links.map((weak, i) => (
                                <div key={i} className={`p-3 rounded-lg border ${weak.severity === 'high' ? 'bg-danger-500/10 border-danger-500/20' :
                                        weak.severity === 'medium' ? 'bg-warning-500/10 border-warning-500/20' :
                                            'bg-success-500/10 border-success-500/20'
                                    }`}>
                                    <p className="font-medium text-dark-100">{weak.type}</p>
                                    <p className="text-sm text-dark-400">{weak.description}</p>
                                </div>
                            ))}
                        </div>
                    </div>
                )}

                {result.recommendations && result.recommendations.length > 0 && (
                    <div className="mb-6">
                        <h3 className="text-lg font-medium text-dark-200 mb-3">Recommendations</h3>
                        <div className="space-y-2">
                            {result.recommendations.map((rec, i) => (
                                <div key={i} className="p-3 rounded-lg bg-primary-500/10 border border-primary-500/20">
                                    <p className="font-medium text-primary-400">[{rec.priority?.toUpperCase()}] {rec.action}</p>
                                    <p className="text-sm text-dark-400">{rec.details}</p>
                                </div>
                            ))}
                        </div>
                    </div>
                )}

                {result.summary && (
                    <div className="p-4 rounded-xl bg-dark-700/30">
                        <h3 className="text-lg font-medium text-dark-200 mb-2">Summary</h3>
                        <p className="text-dark-300">{result.summary}</p>
                    </div>
                )}

                <div className="mt-6 p-4 rounded-xl bg-dark-800/50">
                    <details>
                        <summary className="text-sm text-dark-400 cursor-pointer">View Raw Data</summary>
                        <pre className="mt-4 text-xs text-dark-300 overflow-x-auto">
                            {JSON.stringify(result, null, 2)}
                        </pre>
                    </details>
                </div>
            </div>
        )
    }

    return (
        <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8">
            <div className="mb-8">
                <h1 className="text-3xl font-bold text-dark-100 mb-2">Deep Analysis</h1>
                <p className="text-dark-400">Advanced OSINT analysis using specialized modules</p>
            </div>

            <div className="glass-card p-6 mb-8">
                <form onSubmit={handleAnalyze}>
                    <div className="mb-6">
                        <label className="block text-sm font-medium text-dark-200 mb-2">
                            URL or Domain to Analyze
                        </label>
                        <input
                            type="text"
                            value={url}
                            onChange={(e) => setUrl(e.target.value)}
                            placeholder="https://example.com or example.com"
                            className="input-field"
                            required
                        />
                    </div>

                    <div className="mb-6">
                        <label className="block text-sm font-medium text-dark-200 mb-3">
                            Analysis Type
                        </label>
                        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
                            {analysisTypes.map((type) => (
                                <button
                                    key={type.id}
                                    type="button"
                                    onClick={() => setAnalysisType(type.id)}
                                    className={`p-3 rounded-xl text-left transition-all ${analysisType === type.id
                                            ? 'bg-primary-500/20 border-primary-500 border-2'
                                            : 'bg-dark-700/50 border-dark-600 border hover:border-dark-500'
                                        }`}
                                >
                                    <p className="font-medium text-dark-100">{type.label}</p>
                                    <p className="text-xs text-dark-400">{type.description}</p>
                                </button>
                            ))}
                        </div>
                    </div>

                    <button
                        type="submit"
                        disabled={loading || !url.trim()}
                        className="btn-primary flex items-center gap-2"
                    >
                        {loading ? (
                            <>
                                <div className="loading-spinner w-5 h-5"></div>
                                Analyzing...
                            </>
                        ) : (
                            'Start Analysis'
                        )}
                    </button>
                </form>
            </div>

            {error && (
                <div className="glass-card p-6 mb-8 border-danger-500/30 bg-danger-500/5">
                    <p className="text-danger-400">{error}</p>
                </div>
            )}

            {renderResult()}
        </div>
    )
}

export default Analysis
