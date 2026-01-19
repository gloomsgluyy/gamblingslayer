import axios from 'axios'

const API_BASE = '/api'

const api = axios.create({
    baseURL: API_BASE,
    headers: {
        'Content-Type': 'application/json'
    }
})

api.interceptors.request.use((config) => {
    const token = localStorage.getItem('token')
    if (token) {
        config.headers.Authorization = `Bearer ${token}`
    }
    return config
})

export const healthCheck = () => api.get('/health')

export const getStatistics = () => api.get('/statistics')

export const quickScan = (url) => api.post('/scan/quick', { url })

export const startFullScan = (keywords) => api.post('/scan/full', { keywords })

export const getScanStatus = (scanId) => api.get(`/scan/${scanId}`)

export const getScanResults = (scanId, category) => {
    const params = category ? { category } : {}
    return api.get(`/scan/${scanId}/results`, { params })
}

export const submitReport = (url, description, reporterType = 'anonymous') =>
    api.post('/report', { url, description, reporter_type: reporterType })

export const getReports = (status, limit = 100) => {
    const params = { limit }
    if (status) params.status = status
    return api.get('/reports', { params })
}

export const updateReportStatus = (reportId, status) =>
    api.put(`/report/${reportId}/status`, null, { params: { status } })

export const analyzeInfrastructure = (url) => api.post('/analyze/infrastructure', { url })

export const analyzeDNS = (url) => api.post('/analyze/dns', { url })

export const analyzeRotation = (url) => api.post('/analyze/rotation', { url })

export const analyzeRotationBatch = (urls) => api.post('/analyze/rotation/batch', { urls })

export const analyzeMobility = (url) => api.post('/analyze/mobility', { url })

export const analyzeMobilityBatch = (urls) => api.post('/analyze/mobility/batch', { urls })

export const analyzeBehavior = (url) => api.post('/analyze/behavior', { url })

export const getBehaviorReport = (url) => api.post('/analyze/behavior/report', { url })

export const analyzeWeakLinks = (url) => api.post('/analyze/weaklinks', { url })

export const analyzeWeakLinksBatch = (urls) => api.post('/analyze/weaklinks/batch', { urls })

export const getBlocklist = (urls) => api.post('/analyze/blocklist', { urls })

export const buildAttackChain = (url) => api.post('/analyze/attackchain', { url })

export const buildNetworkAttackChain = (urls) => api.post('/analyze/attackchain/network', { urls })

export const generateEvidenceReport = (url) => api.post('/evidence/report', { url })

export const generateNetworkReport = (urls) => api.post('/evidence/network', { urls })

export const getDomainInfo = (domain) => api.get(`/domain/${domain}`)

export const getDomainDNS = (domain) => api.get(`/domain/${domain}/dns`)

export const getDomainRelations = (domain) => api.get(`/domain/${domain}/relations`)

export const getDomainChanges = (domain) => api.get(`/domain/${domain}/changes`)

export const getDomainBehavior = (domain) => api.get(`/domain/${domain}/behavior`)

export const getDomainWeakLinks = (domain) => api.get(`/domain/${domain}/weaklinks`)

export const comprehensiveAnalysis = (url) => api.post('/comprehensive', { url })

export const getAnalysisStatus = (analysisId) => api.get(`/analysis/${analysisId}`)

export const login = (username, password) => api.post('/auth/login', { username, password })

export const register = (username, password, role = 'user') =>
    api.post('/auth/register', { username, password, role })

export default api
