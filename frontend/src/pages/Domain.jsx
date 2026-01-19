import { useState, useEffect } from 'react'
import { useParams, Link } from 'react-router-dom'
import {
    getDomainInfo,
    getDomainDNS,
    getDomainRelations,
    getDomainChanges,
    getDomainBehavior,
    getDomainWeakLinks
} from '../services/api'

function Domain() {
    const { domain } = useParams()
    const [activeTab, setActiveTab] = useState('overview')
    const [data, setData] = useState({
        info: null,
        dns: null,
        relations: null,
        changes: null,
        behavior: null,
        weaklinks: null
    })
    const [loading, setLoading] = useState(true)
    const [error, setError] = useState(null)

    useEffect(() => {
        fetchDomainData()
    }, [domain])

    const fetchDomainData = async () => {
        setLoading(true)
        setError(null)

        try {
            const [infoRes, dnsRes, relationsRes, changesRes, behaviorRes, weaklinksRes] = await Promise.allSettled([
                getDomainInfo(domain),
                getDomainDNS(domain),
                getDomainRelations(domain),
                getDomainChanges(domain),
                getDomainBehavior(domain),
                getDomainWeakLinks(domain)
            ])

            setData({
                info: infoRes.status === 'fulfilled' ? infoRes.value.data : null,
                dns: dnsRes.status === 'fulfilled' ? dnsRes.value.data : null,
                relations: relationsRes.status === 'fulfilled' ? relationsRes.value.data : null,
                changes: changesRes.status === 'fulfilled' ? changesRes.value.data : null,
                behavior: behaviorRes.status === 'fulfilled' ? behaviorRes.value.data : null,
                weaklinks: weaklinksRes.status === 'fulfilled' ? weaklinksRes.value.data : null
            })
        } catch (err) {
            setError('Failed to load domain data')
        } finally {
            setLoading(false)
        }
    }

    const tabs = [
        { id: 'overview', label: 'Overview' },
        { id: 'dns', label: 'DNS History' },
        { id: 'relations', label: 'Relations' },
        { id: 'changes', label: 'Changes' },
        { id: 'behavior', label: 'Behavior' },
        { id: 'weaklinks', label: 'Weak Links' }
    ]

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

    const renderOverview = () => {
        const info = data.info
        if (!info) return <p className="text-dark-400">No domain information available</p>

        let ipAddresses = info.ip_addresses || []
        let nameservers = info.nameservers || []

        if (typeof ipAddresses === 'string') {
            try { ipAddresses = JSON.parse(ipAddresses) } catch (e) { ipAddresses = [] }
        }
        if (typeof nameservers === 'string') {
            try { nameservers = JSON.parse(nameservers) } catch (e) { nameservers = [] }
        }

        return (
            <div className="space-y-6">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <div className="p-4 rounded-xl bg-dark-700/30">
                        <h3 className="text-lg font-medium text-dark-200 mb-4">Basic Information</h3>
                        <div className="space-y-3">
                            <div>
                                <p className="text-sm text-dark-400">Domain</p>
                                <p className="text-dark-100 font-medium">{info.domain}</p>
                            </div>
                            <div>
                                <p className="text-sm text-dark-400">Registrar</p>
                                <p className="text-dark-100">{info.registrar || 'Unknown'}</p>
                            </div>
                            <div>
                                <p className="text-sm text-dark-400">Hosting Provider</p>
                                <p className="text-dark-100">{info.hosting_provider || 'Unknown'}</p>
                            </div>
                            <div>
                                <p className="text-sm text-dark-400">ASN</p>
                                <p className="text-dark-100">{info.asn || 'Unknown'}</p>
                            </div>
                        </div>
                    </div>

                    <div className="p-4 rounded-xl bg-dark-700/30">
                        <h3 className="text-lg font-medium text-dark-200 mb-4">SSL Information</h3>
                        <div className="space-y-3">
                            <div>
                                <p className="text-sm text-dark-400">SSL Issuer</p>
                                <p className="text-dark-100">{info.ssl_issuer || 'Unknown'}</p>
                            </div>
                            <div>
                                <p className="text-sm text-dark-400">SSL Expiry</p>
                                <p className="text-dark-100">{info.ssl_expiry || 'Unknown'}</p>
                            </div>
                            <div>
                                <p className="text-sm text-dark-400">First Seen</p>
                                <p className="text-dark-100">{formatDate(info.first_seen)}</p>
                            </div>
                            <div>
                                <p className="text-sm text-dark-400">Last Seen</p>
                                <p className="text-dark-100">{formatDate(info.last_seen)}</p>
                            </div>
                        </div>
                    </div>
                </div>

                <div className="p-4 rounded-xl bg-dark-700/30">
                    <h3 className="text-lg font-medium text-dark-200 mb-4">IP Addresses</h3>
                    {ipAddresses.length > 0 ? (
                        <div className="flex flex-wrap gap-2">
                            {ipAddresses.map((ip, i) => (
                                <span key={i} className="px-3 py-1 bg-primary-500/10 text-primary-400 rounded-lg text-sm">
                                    {ip}
                                </span>
                            ))}
                        </div>
                    ) : (
                        <p className="text-dark-400">No IP addresses recorded</p>
                    )}
                </div>

                <div className="p-4 rounded-xl bg-dark-700/30">
                    <h3 className="text-lg font-medium text-dark-200 mb-4">Nameservers</h3>
                    {nameservers.length > 0 ? (
                        <div className="flex flex-wrap gap-2">
                            {nameservers.map((ns, i) => (
                                <span key={i} className="px-3 py-1 bg-dark-600 text-dark-200 rounded-lg text-sm">
                                    {ns}
                                </span>
                            ))}
                        </div>
                    ) : (
                        <p className="text-dark-400">No nameservers recorded</p>
                    )}
                </div>
            </div>
        )
    }

    const renderDNS = () => {
        const dns = data.dns
        if (!dns || !dns.dns_history || dns.dns_history.length === 0) {
            return <p className="text-dark-400">No DNS history available</p>
        }

        return (
            <div className="space-y-3">
                {dns.dns_history.map((record, i) => (
                    <div key={i} className="p-3 rounded-lg bg-dark-700/30 flex items-center justify-between">
                        <div>
                            <span className="px-2 py-1 bg-primary-500/20 text-primary-400 rounded text-xs font-medium mr-2">
                                {record.record_type}
                            </span>
                            <span className="text-dark-200">{record.record_value}</span>
                        </div>
                        <div className="text-right">
                            <p className="text-xs text-dark-400">Resolver: {record.resolver}</p>
                            <p className="text-xs text-dark-500">{formatDate(record.captured_at)}</p>
                        </div>
                    </div>
                ))}
            </div>
        )
    }

    const renderRelations = () => {
        const relations = data.relations
        if (!relations || !relations.relations || relations.relations.length === 0) {
            return <p className="text-dark-400">No domain relations found</p>
        }

        return (
            <div className="space-y-3">
                {relations.relations.map((rel, i) => (
                    <div key={i} className="p-3 rounded-lg bg-dark-700/30">
                        <div className="flex items-center justify-between mb-2">
                            <span className="text-dark-200">{rel.source_domain}</span>
                            <span className="px-2 py-1 bg-primary-500/20 text-primary-400 rounded text-xs">
                                {rel.relation_type}
                            </span>
                            <span className="text-dark-200">{rel.target_domain}</span>
                        </div>
                        <div className="flex justify-between text-xs text-dark-500">
                            <span>Confidence: {rel.confidence}%</span>
                        </div>
                    </div>
                ))}
            </div>
        )
    }

    const renderChanges = () => {
        const changes = data.changes
        if (!changes || !changes.changes || changes.changes.length === 0) {
            return <p className="text-dark-400">No infrastructure changes recorded</p>
        }

        return (
            <div className="space-y-3">
                {changes.changes.map((change, i) => (
                    <div key={i} className="p-3 rounded-lg bg-dark-700/30">
                        <div className="flex items-center justify-between mb-2">
                            <span className="px-2 py-1 bg-warning-500/20 text-warning-400 rounded text-xs font-medium">
                                {change.change_type}
                            </span>
                            <span className="text-xs text-dark-500">{formatDate(change.detected_at)}</span>
                        </div>
                        <div className="grid grid-cols-2 gap-2 text-sm">
                            <div>
                                <p className="text-dark-500">Old</p>
                                <p className="text-dark-300 truncate">{change.old_value || 'N/A'}</p>
                            </div>
                            <div>
                                <p className="text-dark-500">New</p>
                                <p className="text-dark-300 truncate">{change.new_value || 'N/A'}</p>
                            </div>
                        </div>
                    </div>
                ))}
            </div>
        )
    }

    const renderBehavior = () => {
        const behavior = data.behavior
        if (!behavior || !behavior.behavior_logs || behavior.behavior_logs.length === 0) {
            return <p className="text-dark-400">No behavior logs recorded</p>
        }

        return (
            <div className="space-y-3">
                {behavior.behavior_logs.map((log, i) => (
                    <div key={i} className="p-3 rounded-lg bg-dark-700/30">
                        <div className="flex items-center justify-between mb-2">
                            <span className="px-2 py-1 bg-danger-500/20 text-danger-400 rounded text-xs font-medium">
                                {log.behavior_type}
                            </span>
                            <span className="text-xs text-dark-500">{formatDate(log.detected_at)}</span>
                        </div>
                        <p className="text-sm text-dark-300">{log.description}</p>
                    </div>
                ))}
            </div>
        )
    }

    const renderWeakLinks = () => {
        const weaklinks = data.weaklinks
        if (!weaklinks || !weaklinks.weak_links || weaklinks.weak_links.length === 0) {
            return <p className="text-dark-400">No weak links detected</p>
        }

        const getSeverityStyle = (severity) => {
            switch (severity) {
                case 'high': return 'bg-danger-500/20 text-danger-400'
                case 'medium': return 'bg-warning-500/20 text-warning-400'
                default: return 'bg-success-500/20 text-success-400'
            }
        }

        return (
            <div className="space-y-3">
                {weaklinks.weak_links.map((weak, i) => (
                    <div key={i} className={`p-3 rounded-lg border ${weak.severity === 'high' ? 'bg-danger-500/5 border-danger-500/20' :
                            weak.severity === 'medium' ? 'bg-warning-500/5 border-warning-500/20' :
                                'bg-success-500/5 border-success-500/20'
                        }`}>
                        <div className="flex items-center justify-between mb-2">
                            <span className="font-medium text-dark-100">{weak.weakness_type}</span>
                            <span className={`px-2 py-1 rounded text-xs font-medium ${getSeverityStyle(weak.severity)}`}>
                                {weak.severity}
                            </span>
                        </div>
                        <p className="text-sm text-dark-300 mb-2">{weak.description}</p>
                        {weak.remediation && (
                            <p className="text-xs text-dark-500">Remediation: {weak.remediation}</p>
                        )}
                    </div>
                ))}
            </div>
        )
    }

    const renderContent = () => {
        switch (activeTab) {
            case 'overview': return renderOverview()
            case 'dns': return renderDNS()
            case 'relations': return renderRelations()
            case 'changes': return renderChanges()
            case 'behavior': return renderBehavior()
            case 'weaklinks': return renderWeakLinks()
            default: return null
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
        <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8">
            <div className="mb-8">
                <Link to="/dashboard" className="text-sm text-primary-400 hover:text-primary-300 mb-2 inline-block">
                    Back to Dashboard
                </Link>
                <h1 className="text-3xl font-bold text-dark-100 mb-2">{domain}</h1>
                <p className="text-dark-400">Domain analysis and tracking information</p>
            </div>

            {error && (
                <div className="glass-card p-6 mb-8 border-danger-500/30 bg-danger-500/5">
                    <p className="text-danger-400">{error}</p>
                </div>
            )}

            <div className="glass-card mb-8">
                <div className="flex gap-1 p-2 border-b border-dark-700/50 overflow-x-auto">
                    {tabs.map((tab) => (
                        <button
                            key={tab.id}
                            onClick={() => setActiveTab(tab.id)}
                            className={`px-4 py-2 rounded-lg text-sm font-medium whitespace-nowrap transition-all ${activeTab === tab.id
                                    ? 'bg-primary-500 text-white'
                                    : 'text-dark-300 hover:bg-dark-700/50'
                                }`}
                        >
                            {tab.label}
                        </button>
                    ))}
                </div>
                <div className="p-6">
                    {renderContent()}
                </div>
            </div>
        </div>
    )
}

export default Domain
