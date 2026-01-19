import { Outlet, Link, useLocation } from 'react-router-dom'

function Logo() {
    return (
        <svg viewBox="0 0 100 100" className="w-10 h-10">
            <defs>
                <linearGradient id="shield-gradient" x1="0%" y1="0%" x2="100%" y2="100%">
                    <stop offset="0%" style={{ stopColor: '#0ea5e9' }} />
                    <stop offset="100%" style={{ stopColor: '#6366f1' }} />
                </linearGradient>
                <linearGradient id="sword-gradient" x1="0%" y1="0%" x2="100%" y2="100%">
                    <stop offset="0%" style={{ stopColor: '#f59e0b' }} />
                    <stop offset="100%" style={{ stopColor: '#ef4444' }} />
                </linearGradient>
            </defs>
            <path d="M50 5 L85 20 L85 55 Q85 75 50 95 Q15 75 15 55 L15 20 Z" fill="url(#shield-gradient)" opacity="0.9" />
            <path d="M50 5 L85 20 L85 55 Q85 75 50 95 Q15 75 15 55 L15 20 Z" fill="none" stroke="#ffffff" strokeWidth="2" opacity="0.3" />
            <path d="M50 25 L50 75 M35 40 L65 40" stroke="url(#sword-gradient)" strokeWidth="6" strokeLinecap="round" />
            <circle cx="50" cy="55" r="8" fill="#ffffff" opacity="0.9" />
            <path d="M46 55 L49 58 L54 52" stroke="#0ea5e9" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
    )
}

function ShieldIcon() {
    return (
        <svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
        </svg>
    )
}

function SearchIcon() {
    return (
        <svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <circle cx="11" cy="11" r="8" />
            <path d="m21 21-4.35-4.35" />
        </svg>
    )
}

function FileIcon() {
    return (
        <svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
            <polyline points="14,2 14,8 20,8" />
            <line x1="16" y1="13" x2="8" y2="13" />
            <line x1="16" y1="17" x2="8" y2="17" />
        </svg>
    )
}

function ChartIcon() {
    return (
        <svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <line x1="18" y1="20" x2="18" y2="10" />
            <line x1="12" y1="20" x2="12" y2="4" />
            <line x1="6" y1="20" x2="6" y2="14" />
        </svg>
    )
}

function DashboardIcon() {
    return (
        <svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <rect x="3" y="3" width="7" height="7" />
            <rect x="14" y="3" width="7" height="7" />
            <rect x="14" y="14" width="7" height="7" />
            <rect x="3" y="14" width="7" height="7" />
        </svg>
    )
}

function Layout() {
    const location = useLocation()

    const navLinks = [
        { path: '/', label: 'Home', icon: ShieldIcon },
        { path: '/scanner', label: 'Scanner', icon: SearchIcon },
        { path: '/reports', label: 'Reports', icon: FileIcon },
        { path: '/analysis', label: 'Analysis', icon: ChartIcon },
        { path: '/dashboard', label: 'Dashboard', icon: DashboardIcon },
    ]

    return (
        <div className="min-h-screen gradient-bg">
            <nav className="fixed top-0 left-0 right-0 z-50 bg-dark-900/80 backdrop-blur-xl border-b border-dark-700/50">
                <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                    <div className="flex items-center justify-between h-16">
                        <Link to="/" className="flex items-center gap-3">
                            <Logo />
                            <span className="text-xl font-bold gradient-text">Gambling Slayer</span>
                        </Link>

                        <div className="hidden md:flex items-center gap-1">
                            {navLinks.map(({ path, label, icon: Icon }) => (
                                <Link
                                    key={path}
                                    to={path}
                                    className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-all duration-200 ${location.pathname === path
                                            ? 'bg-primary-500/10 text-primary-400'
                                            : 'text-dark-300 hover:text-white hover:bg-dark-700/50'
                                        }`}
                                >
                                    <Icon />
                                    {label}
                                </Link>
                            ))}
                        </div>

                        <div className="flex items-center gap-4">
                            <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-success-500/10 border border-success-500/20">
                                <div className="pulse-dot bg-success-500"></div>
                                <span className="text-xs font-medium text-success-400">Operational</span>
                            </div>
                        </div>
                    </div>
                </div>
            </nav>

            <main className="pt-20 pb-12">
                <Outlet />
            </main>

            <footer className="border-t border-dark-700/50 py-8 bg-dark-900/50">
                <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                    <div className="flex flex-col md:flex-row items-center justify-between gap-4">
                        <div className="flex items-center gap-3">
                            <Logo />
                            <div>
                                <p className="text-sm font-semibold text-dark-100">Gambling Slayer</p>
                                <p className="text-xs text-dark-400">OSINT Platform for Online Gambling Detection</p>
                            </div>
                        </div>
                        <p className="text-xs text-dark-500">
                            Protecting communities from online gambling threats
                        </p>
                    </div>
                </div>
            </footer>

            <div className="md:hidden fixed bottom-0 left-0 right-0 bg-dark-900/95 backdrop-blur-xl border-t border-dark-700/50 z-50">
                <div className="flex items-center justify-around py-2">
                    {navLinks.map(({ path, label, icon: Icon }) => (
                        <Link
                            key={path}
                            to={path}
                            className={`flex flex-col items-center gap-1 px-3 py-2 rounded-lg text-xs ${location.pathname === path
                                    ? 'text-primary-400'
                                    : 'text-dark-400'
                                }`}
                        >
                            <Icon />
                            <span>{label}</span>
                        </Link>
                    ))}
                </div>
            </div>
        </div>
    )
}

export default Layout
