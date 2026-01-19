import { useState, useEffect } from 'react'
import { quickScan, startFullScan, getScanStatus, getScanResults } from '../services/api'

function Scanner() {
    const [mode, setMode] = useState('quick')
    const [url, setUrl] = useState('')
    const [keywords, setKeywords] = useState('')
    const [scanning, setScanning] = useState(false)
    const [scanId, setScanId] = useState(null)
    const [progress, setProgress] = useState(0)
    const [results, setResults] = useState(null)
    const [error, setError] = useState(null)

    useEffect(() => {
        let interval
        if (scanId && scanning) {
            interval = setInterval(async () => {
                try {
                    const response = await getScanStatus(scanId)
                    const data = response.data
                    setProgress(data.progress || 0)

                    if (data.status === 'completed') {
                        setScanning(false)
                        if (data.result) {
                            setResults(data.result)
                        } else {
                            const resultsResponse = await getScanResults(scanId)
                            setResults({ results: resultsResponse.data.results })
                        }
                    } else if (data.status === 'failed') {
                        setScanning(false)
                        setError(data.error || 'Scan failed')
                    }
                } catch (err) {
                    console.error('Status check failed:', err)
                }
            }, 2000)
        }
        return () => clearInterval(interval)
    }, [scanId, scanning])

    const handleQuickScan = async (e) => {
        e.preventDefault()
        if (!url.trim()) return

        setScanning(true)
        setResults(null)
        setError(null)

        try {
            const response = await quickScan(url)
            setResults({ single: response.data })
        } catch (err) {
            setError(err.response?.data?.detail || 'Scan failed')
        } finally {
            setScanning(false)
        }
    }

    const handleFullScan = async (e) => {
        e.preventDefault()

        setScanning(true)
        setResults(null)
        setError(null)
        setProgress(0)

        try {
            const keywordList = keywords.split(',').map(k => k.trim()).filter(k => k)
            const response = await startFullScan(keywordList.length > 0 ? keywordList : null)
            setScanId(response.data.scan_id)
        } catch (err) {
            setError(err.response?.data?.detail || 'Failed to start scan')
            setScanning(false)
        }
    }

    const getCategoryStyle = (category) => {
        switch (category) {
            case 'direct_judol': return 'risk-critical'
            case 'deface_forward': return 'risk-high'
            case 'suspected': return 'risk-medium'
            default: return 'risk-low'
        }
    }

    const getCategoryLabel = (category) => {
        switch (category) {
            case 'direct_judol': return 'Direct Gambling'
            case 'deface_forward': return 'Defaced/Forward'
            case 'suspected': return 'Suspected'
            case 'false_positive': return 'Safe'
            default: return category
        }
    }

    return (
        <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8">
            <div className="mb-8">
                <h1 className="text-3xl font-bold text-dark-100 mb-2">URL Scanner</h1>
                <p className="text-dark-400">Scan URLs for gambling content with AI-powered analysis</p>
            </div>

            <div className="glass-card p-6 mb-8">
                <div className="flex gap-4 mb-6">
                    <button
                        onClick={() => setMode('quick')}
                        className={`px-4 py-2 rounded-lg font-medium transition-all ${mode === 'quick'
                                ? 'bg-primary-500 text-white'
                                : 'bg-dark-700 text-dark-300 hover:bg-dark-600'
                            }`}
                    >
                        Quick Scan
                    </button>
                    <button
                        onClick={() => setMode('full')}
                        className={`px-4 py-2 rounded-lg font-medium transition-all ${mode === 'full'
                                ? 'bg-primary-500 text-white'
                                : 'bg-dark-700 text-dark-300 hover:bg-dark-600'
                            }`}
                    >
                        Full Network Scan
                    </button>
                </div>

                {mode === 'quick' ? (
                    <form onSubmit={handleQuickScan}>
                        <div className="mb-4">
                            <label className="block text-sm font-medium text-dark-200 mb-2">
                                URL to Scan
                            </label>
                            <input
                                type="url"
                                value={url}
                                onChange={(e) => setUrl(e.target.value)}
                                placeholder="https://example.com"
                                className="input-field"
                                required
                            />
                        </div>
                        <button
                            type="submit"
                            disabled={scanning || !url.trim()}
                            className="btn-primary flex items-center gap-2"
                        >
                            {scanning ? (
                                <>
                                    <div className="loading-spinner w-5 h-5"></div>
                                    Scanning...
                                </>
                            ) : (
                                'Start Quick Scan'
                            )}
                        </button>
                    </form>
                ) : (
                    <form onSubmit={handleFullScan}>
                        <div className="mb-4">
                            <label className="block text-sm font-medium text-dark-200 mb-2">
                                Keywords (optional, comma-separated)
                            </label>
                            <input
                                type="text"
                                value={keywords}
                                onChange={(e) => setKeywords(e.target.value)}
                                placeholder="slot gacor, judi online, togel"
                                className="input-field"
                            />
                            <p className="text-xs text-dark-500 mt-1">Leave empty to use default gambling keywords</p>
                        </div>
                        <button
                            type="submit"
                            disabled={scanning}
                            className="btn-primary flex items-center gap-2"
                        >
                            {scanning ? (
                                <>
                                    <div className="loading-spinner w-5 h-5"></div>
                                    Scanning... {progress.toFixed(0)}%
                                </>
                            ) : (
                                'Start Full Network Scan'
                            )}
                        </button>
                    </form>
                )}

                {scanning && mode === 'full' && (
                    <div className="mt-6">
                        <div className="flex justify-between text-sm mb-2">
                            <span className="text-dark-400">Scan Progress</span>
                            <span className="text-dark-300">{progress.toFixed(0)}%</span>
                        </div>
                        <div className="h-2 bg-dark-700 rounded-full overflow-hidden">
                            <div
                                className="h-full bg-gradient-to-r from-primary-500 to-primary-400 transition-all duration-300"
                                style={{ width: `${progress}%` }}
                            ></div>
                        </div>
                    </div>
                )}
            </div>

            {error && (
                <div className="glass-card p-6 mb-8 border-danger-500/30 bg-danger-500/5">
                    <p className="text-danger-400">{error}</p>
                </div>
            )}

            {results && (
                <div className="glass-card p-6">
                    <h2 className="text-xl font-semibold text-dark-100 mb-6">Scan Results</h2>

                    {results.single && (
                        <div className="space-y-4">
                            <div className="flex items-start justify-between p-4 rounded-xl bg-dark-700/30">
                                <div className="flex-1 min-w-0">
                                    <p className="font-medium text-dark-100 truncate">{results.single.url}</p>
                                    <p className="text-sm text-dark-400">{results.single.title || 'No title'}</p>
                                </div>
                                <div className="flex items-center gap-4">
                                    <div className="text-center">
                                        <p className="text-2xl font-bold text-primary-400">{results.single.final_score || 0}</p>
                                        <p className="text-xs text-dark-500">Score</p>
                                    </div>
                                    <span className={`category-badge border ${getCategoryStyle(results.single.category)}`}>
                                        {getCategoryLabel(results.single.category)}
                                    </span>
                                </div>
                            </div>
                        </div>
                    )}

                    {results.statistics && (
                        <div className="mb-6">
                            <h3 className="text-lg font-medium text-dark-200 mb-4">Statistics</h3>
                            <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
                                <div className="stat-card">
                                    <p className="text-2xl font-bold text-primary-400">{results.statistics.total_scanned || 0}</p>
                                    <p className="text-xs text-dark-400">Total Scanned</p>
                                </div>
                                <div className="stat-card">
                                    <p className="text-2xl font-bold text-danger-400">{results.statistics.direct_judol_count || 0}</p>
                                    <p className="text-xs text-dark-400">Direct Gambling</p>
                                </div>
                                <div className="stat-card">
                                    <p className="text-2xl font-bold text-warning-500">{results.statistics.deface_forward_count || 0}</p>
                                    <p className="text-xs text-dark-400">Defaced</p>
                                </div>
                                <div className="stat-card">
                                    <p className="text-2xl font-bold text-warning-400">{results.statistics.suspected_count || 0}</p>
                                    <p className="text-xs text-dark-400">Suspected</p>
                                </div>
                                <div className="stat-card">
                                    <p className="text-2xl font-bold text-success-400">{results.statistics.false_positive_count || 0}</p>
                                    <p className="text-xs text-dark-400">Safe</p>
                                </div>
                            </div>
                        </div>
                    )}

                    {results.direct_judol && results.direct_judol.length > 0 && (
                        <div className="mb-6">
                            <h3 className="text-lg font-medium text-danger-400 mb-4">
                                Direct Gambling Sites ({results.direct_judol.length})
                            </h3>
                            <div className="space-y-2 max-h-64 overflow-y-auto">
                                {results.direct_judol.map((item, i) => (
                                    <div key={i} className="flex items-center justify-between p-3 rounded-lg bg-danger-500/10 border border-danger-500/20">
                                        <span className="text-sm text-dark-200 truncate flex-1">{item.url}</span>
                                        <span className="text-danger-400 font-medium ml-4">{item.final_score}</span>
                                    </div>
                                ))}
                            </div>
                        </div>
                    )}

                    {results.suspected && results.suspected.length > 0 && (
                        <div className="mb-6">
                            <h3 className="text-lg font-medium text-warning-400 mb-4">
                                Suspected Sites ({results.suspected.length})
                            </h3>
                            <div className="space-y-2 max-h-64 overflow-y-auto">
                                {results.suspected.map((item, i) => (
                                    <div key={i} className="flex items-center justify-between p-3 rounded-lg bg-warning-500/10 border border-warning-500/20">
                                        <span className="text-sm text-dark-200 truncate flex-1">{item.url}</span>
                                        <span className="text-warning-400 font-medium ml-4">{item.final_score}</span>
                                    </div>
                                ))}
                            </div>
                        </div>
                    )}
                </div>
            )}
        </div>
    )
}

export default Scanner
