import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import { getStatistics, getReports, getScanResults } from '../services/api'

function Dashboard() {
    const [stats, setStats] = useState(null)
    const [recentReports, setRecentReports] = useState([])
    const [loading, setLoading] = useState(true)

    useEffect(() => {
        fetchData()
    }, [])

    const fetchData = async () => {
        try {
            const [statsRes, reportsRes] = await Promise.all([
                getStatistics(),
                getReports(null, 10)
            ])
            setStats(statsRes.data)
            setRecentReports(reportsRes.data.reports || [])
        } catch (err) {
            console.error('Failed to fetch dashboard data:', err)
        } finally {
            setLoading(false)
        }
    }

    const formatDate = (dateString) => {
        if (!dateString) return 'N/A'
        return new Date(dateString).toLocaleDateString('id-ID', {
            day: 'numeric',
            month: 'short',
            hour: '2-digit',
            minute: '2-digit'
        })
    }

    const getStatusStyle = (status) => {
        switch (status) {
            case 'pending': return 'bg-warning-500/20 text-warning-400'
            case 'verified': return 'bg-danger-500/20 text-danger-400'
            case 'investigating': return 'bg-primary-500/20 text-primary-400'
            case 'resolved': return 'bg-success-500/20 text-success-400'
            default: return 'bg-dark-500/20 text-dark-400'
        }
    }

    if (loading) {
        return (
            <div className="flex items-center justify-center min-h-[60vh]">
                <div className="loading-spinner"></div>
            </div>
        )
    }

    return (
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div className="mb-8">
                <h1 className="text-3xl font-bold text-dark-100 mb-2">Dashboard</h1>
                <p className="text-dark-400">Overview of scanning activity and reports</p>
            </div>

            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
                <div className="stat-card">
                    <p className="text-3xl font-bold text-primary-400">{stats?.total_scans || 0}</p>
                    <p className="text-sm text-dark-400">Total Scans</p>
                </div>
                <div className="stat-card">
                    <p className="text-3xl font-bold text-success-400">{stats?.completed_scans || 0}</p>
                    <p className="text-sm text-dark-400">Completed</p>
                </div>
                <div className="stat-card">
                    <p className="text-3xl font-bold text-danger-400">{stats?.direct_judol || 0}</p>
                    <p className="text-sm text-dark-400">Gambling Sites</p>
                </div>
                <div className="stat-card">
                    <p className="text-3xl font-bold text-warning-400">{stats?.suspected || 0}</p>
                    <p className="text-sm text-dark-400">Suspected</p>
                </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
                <div className="glass-card p-6">
                    <h2 className="text-lg font-semibold text-dark-100 mb-4">Scan Statistics</h2>
                    <div className="space-y-4">
                        <div className="flex justify-between items-center">
                            <span className="text-dark-400">Total Results</span>
                            <span className="text-dark-100 font-medium">{stats?.total_results || 0}</span>
                        </div>
                        <div className="flex justify-between items-center">
                            <span className="text-dark-400">Direct Gambling</span>
                            <span className="text-danger-400 font-medium">{stats?.direct_judol || 0}</span>
                        </div>
                        <div className="flex justify-between items-center">
                            <span className="text-dark-400">Defaced/Forward</span>
                            <span className="text-warning-500 font-medium">{stats?.deface_forward || 0}</span>
                        </div>
                        <div className="flex justify-between items-center">
                            <span className="text-dark-400">Suspected</span>
                            <span className="text-warning-400 font-medium">{stats?.suspected || 0}</span>
                        </div>
                    </div>
                </div>

                <div className="glass-card p-6">
                    <h2 className="text-lg font-semibold text-dark-100 mb-4">Report Statistics</h2>
                    <div className="space-y-4">
                        <div className="flex justify-between items-center">
                            <span className="text-dark-400">Total Reports</span>
                            <span className="text-dark-100 font-medium">{stats?.total_reports || 0}</span>
                        </div>
                        <div className="flex justify-between items-center">
                            <span className="text-dark-400">Pending Review</span>
                            <span className="text-warning-400 font-medium">{stats?.pending_reports || 0}</span>
                        </div>
                        <div className="flex justify-between items-center">
                            <span className="text-dark-400">Domains Tracked</span>
                            <span className="text-primary-400 font-medium">{stats?.total_domains || 0}</span>
                        </div>
                    </div>
                </div>

                <div className="glass-card p-6">
                    <h2 className="text-lg font-semibold text-dark-100 mb-4">Quick Actions</h2>
                    <div className="space-y-3">
                        <Link to="/scanner" className="btn-primary w-full flex items-center justify-center gap-2">
                            <svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                <circle cx="11" cy="11" r="8" />
                                <path d="m21 21-4.35-4.35" />
                            </svg>
                            New Scan
                        </Link>
                        <Link to="/analysis" className="btn-secondary w-full flex items-center justify-center gap-2">
                            <svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                <line x1="18" y1="20" x2="18" y2="10" />
                                <line x1="12" y1="20" x2="12" y2="4" />
                                <line x1="6" y1="20" x2="6" y2="14" />
                            </svg>
                            Deep Analysis
                        </Link>
                        <Link to="/reports" className="btn-secondary w-full flex items-center justify-center gap-2">
                            <svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
                                <polyline points="14,2 14,8 20,8" />
                            </svg>
                            View Reports
                        </Link>
                    </div>
                </div>
            </div>

            <div className="glass-card p-6">
                <div className="flex items-center justify-between mb-4">
                    <h2 className="text-lg font-semibold text-dark-100">Recent Reports</h2>
                    <Link to="/reports" className="text-sm text-primary-400 hover:text-primary-300">
                        View All
                    </Link>
                </div>

                {recentReports.length === 0 ? (
                    <p className="text-dark-400 text-center py-8">No reports yet</p>
                ) : (
                    <div className="space-y-3">
                        {recentReports.map((report) => (
                            <div key={report.id} className="flex items-center justify-between p-3 rounded-lg bg-dark-700/30">
                                <div className="flex-1 min-w-0">
                                    <p className="text-dark-200 truncate">{report.url}</p>
                                    <p className="text-xs text-dark-500">{formatDate(report.created_at)}</p>
                                </div>
                                <span className={`px-2 py-1 rounded text-xs font-medium capitalize ${getStatusStyle(report.status)}`}>
                                    {report.status}
                                </span>
                            </div>
                        ))}
                    </div>
                )}
            </div>
        </div>
    )
}

export default Dashboard
