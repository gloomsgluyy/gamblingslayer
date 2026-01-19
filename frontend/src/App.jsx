import { BrowserRouter as Router, Routes, Route } from 'react-router-dom'
import { useState, createContext, useContext } from 'react'
import Layout from './components/Layout'
import Home from './pages/Home'
import Scanner from './pages/Scanner'
import Reports from './pages/Reports'
import Analysis from './pages/Analysis'
import Dashboard from './pages/Dashboard'
import Domain from './pages/Domain'

export const AppContext = createContext()

export function useApp() {
    return useContext(AppContext)
}

function App() {
    const [user, setUser] = useState(null)
    const [theme, setTheme] = useState('dark')

    const value = {
        user,
        setUser,
        theme,
        setTheme,
        isAuthenticated: !!user
    }

    return (
        <AppContext.Provider value={value}>
            <Router>
                <Routes>
                    <Route path="/" element={<Layout />}>
                        <Route index element={<Home />} />
                        <Route path="scanner" element={<Scanner />} />
                        <Route path="reports" element={<Reports />} />
                        <Route path="analysis" element={<Analysis />} />
                        <Route path="dashboard" element={<Dashboard />} />
                        <Route path="domain/:domain" element={<Domain />} />
                    </Route>
                </Routes>
            </Router>
        </AppContext.Provider>
    )
}

export default App
