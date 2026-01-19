import { useState, useEffect } from 'react'
import { getReports, submitReport, updateReportStatus } from '../services/api'

function Reports() {
    const [reports, setReports] = useState([])
    const [loading, setLoading] = useState(true)
    const [filter, setFilter] = useState('all')
    const [showForm, setShowForm] = useState(false)
    const [url, setUrl] = useState('')
    const [description, setDescription] = useState('')
    const [submitting, setSubmitting] = useState(false)

    useEffect(() => {
        fetchReports()
    }, [filter])

    const fetchReports = async () => {
        setLoading(true)
        try {
            const status = filter === 'all' ? null : filter
            const response = await getReports(status)
            setReports(response.data.reports || [])
        } catch (err) {
            console.error('Failed to fetch reports:', err)
        } finally {
            setLoading(false)
        }
    }

    const handleSubmit = async (e) => {
        e.preventDefault()
        if (!url.trim()) return

        setSubmitting(true)
        try {
            await submitReport(url, description)
            setUrl('')
            setDescription('')
            setShowForm(false)
            fetchReports()
        } catch (err) {
            console.error('Failed to submit report:', err)
        } finally {
            setSubmitting(false)
        }
    }

    const handleStatusUpdate = async (reportId, newStatus) => {
        try {
            await updateReportStatus(reportId, newStatus)
            fetchReports()
        } catch (err) {
            console.error('Failed to update status:', err)
        }
    }

    const getStatusStyle = (status) => {
        switch (status) {
            case 'pending': return 'bg-warning-500/20 text-warning-400'
            case 'verified': return 'bg-danger-500/20 text-danger-400'
            case 'investigating': return 'bg-primary-500/20 text-primary-400'
            case 'resolved': return 'bg-success-500/20 text-success-400'
            case 'rejected': return 'bg-dark-500/20 text-dark-400'
            default: return 'bg-dark-500/20 text-dark-400'
        }
    }

    const formatDate = (dateString) => {
        if (!dateString) return 'N/A'
        return new Date(dateString).toLocaleDateString('id-ID', {
            day: 'numeric',
            month: 'short',
            year: 'numeric',
            hour: '2-digit',
            minute: '2-digit'
        })
    }

    return (
        <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8">
            <div className="flex items-center justify-between mb-8">
                <div>
                    <h1 className="text-3xl font-bold text-dark-100 mb-2">User Reports</h1>
                    <p className="text-dark-400">Community-submitted suspicious link reports</p>
                </div>
                <button onClick={() => setShowForm(!showForm)} className="btn-primary">
                    {showForm ? 'Cancel' : 'Submit Report'}
                </button>
            </div>

            {showForm && (
                <div className="glass-card p-6 mb-8">
                    <h2 className="text-xl font-semibold text-dark-100 mb-4">Submit New Report</h2>
                    <form onSubmit={handleSubmit}>
                        <div className="mb-4">
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
                        <div className="mb-4">
                            <label className="block text-sm font-medium text-dark-200 mb-2">
                                Description (Optional)
                            </label>
                            <textarea
                                value={description}
                                onChange={(e) => setDescription(e.target.value)}
                                placeholder="Additional context about this link..."
                                rows={3}
                                className="input-field resize-none"
                            />
                        </div>
                        <button type="submit" disabled={submitting} className="btn-primary">
                            {submitting ? 'Submitting...' : 'Submit Report'}
                        </button>
                    </form>
                </div>
            )}

            <div className="glass-card p-6">
                <div className="flex items-center gap-4 mb-6">
                    <span className="text-sm text-dark-400">Filter:</span>
                    {['all', 'pending', 'verified', 'investigating', 'resolved', 'rejected'].map((status) => (
                        <button
                            key={status}
                            onClick={() => setFilter(status)}
                            className={`px-3 py-1 rounded-lg text-sm capitalize transition-all ${filter === status
                                    ? 'bg-primary-500 text-white'
                                    : 'bg-dark-700 text-dark-300 hover:bg-dark-600'
                                }`}
                        >
                            {status}
                        </button>
                    ))}
                </div>

                {loading ? (
                    <div className="flex items-center justify-center py-12">
                        <div className="loading-spinner"></div>
                    </div>
                ) : reports.length === 0 ? (
                    <div className="text-center py-12">
                        <p className="text-dark-400">No reports found</p>
                    </div>
                ) : (
                    <div className="space-y-4">
                        {reports.map((report) => (
                            <div key={report.id} className="p-4 rounded-xl bg-dark-700/30 border border-dark-600/50">
                                <div className="flex items-start justify-between mb-3">
                                    <div className="flex-1 min-w-0">
                                        <a
                                            href={report.url}
                                            target="_blank"
                                            rel="noopener noreferrer"
                                            className="text-primary-400 hover:text-primary-300 font-medium truncate block"
                                        >
                                            {report.url}
                                        </a>
                                        <p className="text-xs text-dark-500 mt-1">
                                            Report ID: {report.report_id} | Submitted: {formatDate(report.created_at)}
                                        </p>
                                    </div>
                                    <span className={`px-3 py-1 rounded-full text-xs font-medium capitalize ${getStatusStyle(report.status)}`}>
                                        {report.status}
                                    </span>
                                </div>

                                {report.description && (
                                    <p className="text-sm text-dark-300 mb-3">{report.description}</p>
                                )}

                                <div className="flex items-center gap-2">
                                    <span className="text-xs text-dark-500">Update status:</span>
                                    {['pending', 'investigating', 'verified', 'resolved', 'rejected'].map((status) => (
                                        <button
                                            key={status}
                                            onClick={() => handleStatusUpdate(report.report_id, status)}
                                            className={`px-2 py-1 rounded text-xs capitalize transition-all ${report.status === status
                                                    ? 'bg-primary-500/20 text-primary-400'
                                                    : 'bg-dark-600 text-dark-400 hover:bg-dark-500'
                                                }`}
                                        >
                                            {status}
                                        </button>
                                    ))}
                                </div>
                            </div>
                        ))}
                    </div>
                )}
            </div>
        </div>
    )
}

export default Reports
