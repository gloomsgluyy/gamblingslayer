import { useState } from 'react'
import { Link } from 'react-router-dom'
import { quickScan, submitReport, getStatistics } from '../services/api'

function HeroSection() {
    const [url, setUrl] = useState('')
    const [scanning, setScanning] = useState(false)
    const [result, setResult] = useState(null)
    const [error, setError] = useState(null)

    const handleScan = async (e) => {
        e.preventDefault()
        if (!url.trim()) return

        setScanning(true)
        setResult(null)
        setError(null)

        try {
            const response = await quickScan(url)
            setResult(response.data)
        } catch (err) {
            setError(err.response?.data?.detail || 'Scan failed. Please try again.')
        } finally {
            setScanning(false)
        }
    }

    const getCategoryStyle = (category) => {
        switch (category) {
            case 'direct_judol':
                return 'risk-critical'
            case 'deface_forward':
                return 'risk-high'
            case 'suspected':
                return 'risk-medium'
            default:
                return 'risk-low'
        }
    }

    const getCategoryLabel = (category) => {
        switch (category) {
            case 'direct_judol':
                return 'Direct Gambling Site'
            case 'deface_forward':
                return 'Defaced/Forwarded'
            case 'suspected':
                return 'Suspected'
            case 'false_positive':
                return 'Safe'
            default:
                return category
        }
    }

    return (
        <section className="relative py-20 overflow-hidden">
            <div className="absolute inset-0 bg-gradient-to-b from-primary-500/5 to-transparent pointer-events-none"></div>
            <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[800px] h-[800px] bg-primary-500/5 rounded-full blur-3xl pointer-events-none"></div>

            <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 text-center relative z-10">
                <h1 className="text-4xl md:text-6xl font-extrabold mb-6">
                    <span className="gradient-text">Protect Your Community</span>
                    <br />
                    <span className="text-dark-100">From Online Gambling</span>
                </h1>

                <p className="text-lg md:text-xl text-dark-300 mb-10 max-w-2xl mx-auto">
                    Advanced OSINT platform for detecting, analyzing, and mapping online gambling websites.
                    Scan suspicious links instantly with AI-powered analysis.
                </p>

                <form onSubmit={handleScan} className="max-w-2xl mx-auto mb-8">
                    <div className="flex flex-col sm:flex-row gap-3">
                        <div className="flex-1 relative">
                            <input
                                type="url"
                                value={url}
                                onChange={(e) => setUrl(e.target.value)}
                                placeholder="Enter URL to scan (e.g., https://example.com)"
                                className="input-field pl-12 pr-4"
                                disabled={scanning}
                            />
                            <svg className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-dark-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71" />
                                <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71" />
                            </svg>
                        </div>
                        <button
                            type="submit"
                            disabled={scanning || !url.trim()}
                            className="btn-primary flex items-center justify-center gap-2 min-w-[140px] disabled:opacity-50 disabled:cursor-not-allowed"
                        >
                            {scanning ? (
                                <>
                                    <div className="loading-spinner w-5 h-5"></div>
                                    Scanning...
                                </>
                            ) : (
                                <>
                                    <svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                        <circle cx="11" cy="11" r="8" />
                                        <path d="m21 21-4.35-4.35" />
                                    </svg>
                                    Scan Now
                                </>
                            )}
                        </button>
                    </div>
                </form>

                {error && (
                    <div className="max-w-2xl mx-auto mb-8 p-4 rounded-xl bg-danger-500/10 border border-danger-500/20 text-danger-400">
                        {error}
                    </div>
                )}

                {result && (
                    <div className="max-w-2xl mx-auto glass-card p-6 text-left">
                        <div className="flex items-start justify-between mb-4">
                            <div>
                                <h3 className="text-lg font-semibold text-dark-100 mb-1">Scan Result</h3>
                                <p className="text-sm text-dark-400 truncate max-w-md">{result.url}</p>
                            </div>
                            <span className={`category-badge border ${getCategoryStyle(result.category)}`}>
                                {getCategoryLabel(result.category)}
                            </span>
                        </div>

                        <div className="grid grid-cols-3 gap-4 mb-4">
                            <div className="text-center p-3 rounded-lg bg-dark-700/30">
                                <p className="text-2xl font-bold text-primary-400">{result.final_score || 0}</p>
                                <p className="text-xs text-dark-400">Risk Score</p>
                            </div>
                            <div className="text-center p-3 rounded-lg bg-dark-700/30">
                                <p className="text-2xl font-bold text-primary-400">{result.score || 0}</p>
                                <p className="text-xs text-dark-400">Manual Score</p>
                            </div>
                            <div className="text-center p-3 rounded-lg bg-dark-700/30">
                                <p className="text-2xl font-bold text-primary-400">{result.ai_score || 0}</p>
                                <p className="text-xs text-dark-400">AI Score</p>
                            </div>
                        </div>

                        {result.title && (
                            <div className="mb-4">
                                <p className="text-sm text-dark-400 mb-1">Page Title</p>
                                <p className="text-dark-100">{result.title}</p>
                            </div>
                        )}

                        {result.detected_keywords && result.detected_keywords.length > 0 && (
                            <div className="mb-4">
                                <p className="text-sm text-dark-400 mb-2">Detected Keywords</p>
                                <div className="flex flex-wrap gap-2">
                                    {result.detected_keywords.slice(0, 10).map((kw, i) => (
                                        <span key={i} className="px-2 py-1 text-xs bg-danger-500/10 text-danger-400 rounded-md">
                                            {kw.keyword} ({kw.count})
                                        </span>
                                    ))}
                                </div>
                            </div>
                        )}

                        {result.ai_reasoning && (
                            <div className="p-3 rounded-lg bg-dark-700/30">
                                <p className="text-sm text-dark-400 mb-1">AI Analysis</p>
                                <p className="text-sm text-dark-200">{result.ai_reasoning}</p>
                            </div>
                        )}
                    </div>
                )}
            </div>
        </section>
    )
}

function FeaturesSection() {
    const features = [
        {
            title: 'GESE',
            subtitle: 'Gambling Ecosystem Search Engine',
            description: 'AI-powered detection with web scraping and machine learning scoring',
            color: 'from-primary-500 to-primary-600'
        },
        {
            title: 'SIR',
            subtitle: 'Shadow Infrastructure Reconnaissance',
            description: 'Analyze DNS, WHOIS, SSL, and infrastructure relationships',
            color: 'from-indigo-500 to-indigo-600'
        },
        {
            title: 'DTSM',
            subtitle: 'DNS Tampering Detection',
            description: 'Multi-resolver analysis to detect DNS manipulation',
            color: 'from-purple-500 to-purple-600'
        },
        {
            title: 'DRM',
            subtitle: 'Domain Rotation Map',
            description: 'Track redirect chains and mirror domain networks',
            color: 'from-pink-500 to-pink-600'
        },
        {
            title: 'CME',
            subtitle: 'Counter Mobility Engine',
            description: 'Monitor infrastructure changes and operator movements',
            color: 'from-danger-500 to-danger-600'
        },
        {
            title: 'DABE',
            subtitle: 'Behavior Extractor',
            description: 'Analyze adversary patterns and behavior over time',
            color: 'from-warning-500 to-warning-600'
        },
        {
            title: 'IWLD',
            subtitle: 'Weak Link Detector',
            description: 'Find vulnerable points in gambling infrastructure',
            color: 'from-success-500 to-success-600'
        },
        {
            title: 'SACR',
            subtitle: 'Attack Chain Reconstructor',
            description: 'Build event sequences and attack pattern timelines',
            color: 'from-teal-500 to-teal-600'
        },
        {
            title: 'NERE',
            subtitle: 'Evidence Reporting',
            description: 'Generate comprehensive reports for authorities',
            color: 'from-cyan-500 to-cyan-600'
        }
    ]

    return (
        <section className="py-20">
            <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                <div className="text-center mb-16">
                    <h2 className="text-3xl md:text-4xl font-bold text-dark-100 mb-4">
                        Powerful OSINT Modules
                    </h2>
                    <p className="text-dark-300 max-w-2xl mx-auto">
                        Nine specialized modules working together to detect, analyze, and map online gambling networks
                    </p>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                    {features.map((feature, index) => (
                        <div key={index} className="glass-card-hover p-6 group">
                            <div className={`w-12 h-12 rounded-xl bg-gradient-to-br ${feature.color} flex items-center justify-center mb-4 group-hover:scale-110 transition-transform duration-300`}>
                                <span className="text-white font-bold text-sm">{feature.title}</span>
                            </div>
                            <h3 className="text-lg font-semibold text-dark-100 mb-1">{feature.subtitle}</h3>
                            <p className="text-sm text-dark-400">{feature.description}</p>
                        </div>
                    ))}
                </div>
            </div>
        </section>
    )
}

function ReportSection() {
    const [url, setUrl] = useState('')
    const [description, setDescription] = useState('')
    const [submitting, setSubmitting] = useState(false)
    const [submitted, setSubmitted] = useState(false)
    const [error, setError] = useState(null)

    const handleSubmit = async (e) => {
        e.preventDefault()
        if (!url.trim()) return

        setSubmitting(true)
        setError(null)

        try {
            await submitReport(url, description)
            setSubmitted(true)
            setUrl('')
            setDescription('')
        } catch (err) {
            setError(err.response?.data?.detail || 'Failed to submit report')
        } finally {
            setSubmitting(false)
        }
    }

    return (
        <section className="py-20 bg-dark-900/50">
            <div className="max-w-3xl mx-auto px-4 sm:px-6 lg:px-8">
                <div className="text-center mb-12">
                    <h2 className="text-3xl md:text-4xl font-bold text-dark-100 mb-4">
                        Report Suspicious Links
                    </h2>
                    <p className="text-dark-300">
                        Help protect your community by reporting suspicious gambling links
                    </p>
                </div>

                {submitted ? (
                    <div className="glass-card p-8 text-center">
                        <div className="w-16 h-16 rounded-full bg-success-500/10 flex items-center justify-center mx-auto mb-4">
                            <svg className="w-8 h-8 text-success-500" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" />
                                <polyline points="22 4 12 14.01 9 11.01" />
                            </svg>
                        </div>
                        <h3 className="text-xl font-semibold text-dark-100 mb-2">Report Submitted</h3>
                        <p className="text-dark-400 mb-6">Thank you for helping keep the community safe</p>
                        <button onClick={() => setSubmitted(false)} className="btn-secondary">
                            Submit Another Report
                        </button>
                    </div>
                ) : (
                    <form onSubmit={handleSubmit} className="glass-card p-8">
                        {error && (
                            <div className="mb-6 p-4 rounded-xl bg-danger-500/10 border border-danger-500/20 text-danger-400">
                                {error}
                            </div>
                        )}

                        <div className="mb-6">
                            <label className="block text-sm font-medium text-dark-200 mb-2">
                                Suspicious URL *
                            </label>
                            <input
                                type="url"
                                value={url}
                                onChange={(e) => setUrl(e.target.value)}
                                placeholder="https://suspicious-site.com"
                                className="input-field"
                                required
                            />
                        </div>

                        <div className="mb-6">
                            <label className="block text-sm font-medium text-dark-200 mb-2">
                                Additional Information (Optional)
                            </label>
                            <textarea
                                value={description}
                                onChange={(e) => setDescription(e.target.value)}
                                placeholder="Any additional context about where you found this link..."
                                rows={4}
                                className="input-field resize-none"
                            />
                        </div>

                        <button
                            type="submit"
                            disabled={submitting || !url.trim()}
                            className="btn-primary w-full flex items-center justify-center gap-2"
                        >
                            {submitting ? (
                                <>
                                    <div className="loading-spinner w-5 h-5"></div>
                                    Submitting...
                                </>
                            ) : (
                                <>
                                    <svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                        <path d="M22 2L11 13" />
                                        <path d="M22 2l-7 20-4-9-9-4 20-7z" />
                                    </svg>
                                    Submit Report
                                </>
                            )}
                        </button>
                    </form>
                )}
            </div>
        </section>
    )
}

function Home() {
    return (
        <div>
            <HeroSection />
            <FeaturesSection />
            <ReportSection />
        </div>
    )
}

export default Home
