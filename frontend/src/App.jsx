import React, { useState, useEffect, useRef } from 'react';
import Simulator from './pages/Simulator';
import Dashboard from './pages/Dashboard';
import LandingPage from './pages/LandingPage';
import { loginAdmin, createEmployee, getAnomalyAlerts, triggerAnomalyScan, acknowledgeAnomalyAlert } from './services/api';
import EncryptionIndicator from './components/EncryptionIndicator';

function App() {
  // appPhase controls the high-level flow: 'landing' → 'login' → 'app'
  const [appPhase, setAppPhase] = useState('loading'); // start with 'loading' to avoid flash
  const [currentView, setCurrentView] = useState('dashboard');
  const [isDark, setIsDark] = useState(true);
  const [isSidebarOpen, setIsSidebarOpen] = useState(false);
  const [showProvisionModal, setShowProvisionModal] = useState(false);
  
  // Notification / Anomaly State
  const [anomalyAlerts, setAnomalyAlerts] = useState([]);
  const [showNotifPanel, setShowNotifPanel] = useState(false);
  const notifRef = useRef(null);
  
  // Login State
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [authError, setAuthError] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [showProvisionPassword, setShowProvisionPassword] = useState(false);

  // On mount: check for existing token to determine the initial phase
  useEffect(() => {
    const token = localStorage.getItem('InthreatDetection_token');
    if (token) {
      // Token exists — go directly to the authenticated app
      setAppPhase('app');
    } else {
      // No token — show the landing page
      setAppPhase('landing');
    }
  }, []);

  // Poll anomaly alerts every 10 seconds when authenticated
  useEffect(() => {
    if (appPhase !== 'app') return;
    const fetchAlerts = async () => {
      try {
        const data = await getAnomalyAlerts();
        setAnomalyAlerts(data);
      } catch (err) {
        // Silently fail — don't break the app if anomaly service is down
      }
    };
    fetchAlerts();
    const interval = setInterval(fetchAlerts, 10000);
    return () => clearInterval(interval);
  }, [appPhase]);

  // Close notification panel when clicking outside
  useEffect(() => {
    const handleClickOutside = (e) => {
      if (notifRef.current && !notifRef.current.contains(e.target)) {
        setShowNotifPanel(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const handleLogin = async (e) => {
    e.preventDefault();
    setAuthError('');
    try {
      const data = await loginAdmin(username, password);
      localStorage.setItem('InthreatDetection_token', data.access_token);
      setAppPhase('app');
      setCurrentView('dashboard');
    } catch (err) {
      setAuthError('Access Denied. Invalid credentials.');
    }
  };

  const handleLogout = () => {
    localStorage.removeItem('InthreatDetection_token');
    setAppPhase('landing');
    setIsSidebarOpen(false);
    setUsername('');
    setPassword('');
  };

  const renderProvisionModal = () => {
    if (!showProvisionModal) return null;
    return (
      <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-[60] p-4 backdrop-blur-sm">
        <div className={`${isDark ? 'bg-[#1e222b] border-[#2d3340]' : 'bg-white border-gray-200'} p-6 rounded-xl shadow-2xl w-full max-w-md border`}>
          <div className="flex justify-between items-center mb-6">
            <h2 className={`text-lg font-bold ${isDark ? 'text-gray-200' : 'text-gray-800'}`}>Provision Employee Account</h2>
            <button onClick={() => setShowProvisionModal(false)} className={`text-2xl font-bold leading-none transition-colors ${isDark ? 'text-gray-400 hover:text-white' : 'text-gray-500 hover:text-gray-900'}`}>&times;</button>
          </div>
          <form 
              onSubmit={async (e) => {
                  e.preventDefault();
                  const empId = e.target.empId.value;
                  const empName = e.target.empName.value;
                  const empPass = e.target.empPass.value;
                  const empRole = e.target.empRole.value; 
                  try {
                      await createEmployee(empId, empName, empPass, empRole);
                      alert(`Success: ${empRole} account ${empId} provisioned.`);
                      e.target.reset();
                      setShowProvisionModal(false);
                  } catch (err) {
                      alert("Failed to create employee.");
                  }
              }} 
              className="flex flex-col gap-4"
          >
              <div className="flex flex-col gap-1">
                  <label className={`text-xs font-bold uppercase tracking-wider ${isDark ? 'text-gray-400' : 'text-gray-600'}`}>Full Name</label>
                  <input name="empName" required placeholder="e.g., John Doe" className={`border rounded px-4 py-2 w-full outline-none transition-colors ${isDark ? 'bg-[#15171e] border-[#2d3340] text-white focus:border-blue-500' : 'bg-gray-50 border-gray-300 text-black focus:border-blue-500'}`}/>
              </div>
              <div className="flex flex-col gap-1">
                  <label className={`text-xs font-bold uppercase tracking-wider ${isDark ? 'text-gray-400' : 'text-gray-600'}`}>User ID</label>
                  <input name="empId" required placeholder="e.g., ADM-01" className={`border rounded px-4 py-2 w-full outline-none transition-colors ${isDark ? 'bg-[#15171e] border-[#2d3340] text-white focus:border-blue-500' : 'bg-gray-50 border-gray-300 text-black focus:border-blue-500'}`}/>
              </div>
              <div className="flex flex-col gap-1">
                  <label className={`text-xs font-bold uppercase tracking-wider ${isDark ? 'text-gray-400' : 'text-gray-600'}`}>Role</label>
                  <select name="empRole" required className={`border rounded px-4 py-2 w-full outline-none cursor-pointer transition-colors ${isDark ? 'bg-[#15171e] border-[#2d3340] text-white focus:border-blue-500' : 'bg-gray-50 border-gray-300 text-black focus:border-blue-500'}`}>
                      <option value="" disabled selected>Select Role</option>
                      <option value="Admin">Admin</option>
                      <option value="Sys Admin">Sys Admin</option>
                      <option value="DB Admin">DB Admin</option>
                      <option value="Dev">Dev / Engineer</option>
                      <option value="HR">Human Resources</option>
                      <option value="Design">Design</option>
                      <option value="Branch Manager">Branch Manager</option>
                      <option value="Ops Analyst">Ops Analyst</option>
                      <option value="Support Staff">Support Staff</option>
                      <option value="User">Standard User</option>
                  </select>
              </div>
              <div className="flex flex-col gap-1">
                  <label className={`text-xs font-bold uppercase tracking-wider ${isDark ? 'text-gray-400' : 'text-gray-600'}`}>Password</label>
                  <div className="relative">
                      <input name="empPass" required type={showProvisionPassword ? "text" : "password"} placeholder="Password" className={`border rounded px-4 py-2 w-full outline-none transition-colors ${isDark ? 'bg-[#15171e] border-[#2d3340] text-white focus:border-blue-500' : 'bg-gray-50 border-gray-300 text-black focus:border-blue-500'}`}/>
                      <button 
                          type="button"
                          onClick={() => setShowProvisionPassword(!showProvisionPassword)}
                          className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-400 focus:outline-none"
                      >
                          {showProvisionPassword ? (
                                <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.88 9.88l-3.29-3.29m7.532 7.532l3.29 3.29M3 3l3.59 3.59m0 0A9.953 9.953 0 0112 5c4.478 0 8.268 2.943 9.543 7a10.025 10.025 0 01-4.132 5.411m0 0L21 21" />
                                </svg>
                            ) : (
                                <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
                                </svg>
                            )}
                      </button>
                  </div>
              </div>
              <button type="submit" className="bg-blue-600 hover:bg-blue-700 text-white py-2 px-4 rounded font-bold transition mt-2">Create Account</button>
          </form>
        </div>
      </div>
    );
  };

  // ─── PHASE: Loading (prevents flash of wrong content) ──────────
  if (appPhase === 'loading') {
    return (
      <div className="min-h-screen bg-[#0b0d12] flex items-center justify-center">
        <div className="text-blue-500 animate-pulse font-bold tracking-widest">INITIALIZING...</div>
      </div>
    );
  }

  // ─── PHASE: Landing Page ──────────────────────────────────────
  if (appPhase === 'landing') {
    return <LandingPage isDark={isDark} onEnter={() => setAppPhase('login')} />;
  }

  // ─── PHASE: Login Screen ──────────────────────────────────────
  if (appPhase === 'login') {
    return (
      <div className="min-h-screen bg-[#0b0d12] flex flex-col justify-center items-center font-sans relative overflow-hidden">
        {/* Background glow */}
        <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[600px] h-[400px] bg-blue-600/8 rounded-full blur-[100px] pointer-events-none"></div>
        
        <div className="relative z-10 bg-[#1e222b] p-8 rounded-xl border border-[#2d3340] shadow-2xl w-96 text-center">
            <div className="flex items-center justify-center space-x-2 mb-2">
              <div className="bg-blue-600 text-white font-black text-xs tracking-wider flex items-center justify-center w-7 h-7 rounded-md shadow-lg shadow-blue-600/20">
                ID
              </div>
              <h1 className="text-2xl font-black tracking-wider text-white">InThreat<span className="text-blue-500">Detection</span></h1>
            </div>
            <p className="text-gray-500 text-sm mb-6">Restricted SOC Access</p>
            
            {authError && <div className="bg-red-500/10 border border-red-500/50 text-red-400 text-xs py-2 rounded mb-4">{authError}</div>}
            
            <form onSubmit={handleLogin} className="space-y-4">
                <input 
                    type="text" 
                    placeholder="Admin Username" 
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    className="w-full bg-[#15171e] border border-[#2d3340] rounded-lg px-4 py-2.5 text-white outline-none focus:border-blue-500 transition-colors"
                />
                <div className="relative">
                    <input 
                        type={showPassword ? "text" : "password"} 
                        placeholder="Password" 
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                        className="w-full bg-[#15171e] border border-[#2d3340] rounded-lg px-4 py-2.5 pr-12 text-white outline-none focus:border-blue-500 transition-colors"
                    />
                    <button 
                        type="button"
                        onClick={() => setShowPassword(!showPassword)}
                        className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-400 focus:outline-none"
                    >
                        {showPassword ? (
                            <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.88 9.88l-3.29-3.29m7.532 7.532l3.29 3.29M3 3l3.59 3.59m0 0A9.953 9.953 0 0112 5c4.478 0 8.268 2.943 9.543 7a10.025 10.025 0 01-4.132 5.411m0 0L21 21" />
                            </svg>
                        ) : (
                            <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
                            </svg>
                        )}
                    </button>
                </div>
                <button type="submit" className="w-full bg-blue-600 hover:bg-blue-700 text-white font-bold py-2.5 rounded-lg transition shadow-lg shadow-blue-600/20 hover:shadow-blue-600/40">
                    Authenticate
                </button>
            </form>
            <button 
                onClick={() => setAppPhase('landing')} 
                className="mt-6 text-gray-500 hover:text-gray-300 text-xs underline transition-colors"
            >
                ← Back to Home
            </button>
        </div>
      </div>
    );
  }

  // ─── PHASE: Authenticated App ─────────────────────────────────
  return (
    <div className={`min-h-screen ${isDark ? 'bg-[#15171e]' : 'bg-[#f8f9fa]'} flex flex-col font-sans transition-colors duration-300`}>
      {/* Top Navbar */}
      <nav className={`${isDark ? 'bg-[#1e222b] border-[#2d3340]' : 'bg-white border-gray-200'} border-b px-6 py-3 flex justify-between items-center shadow-sm relative z-40 transition-colors duration-300`}>
        <div className="flex items-center space-x-3">
          {/* Logo */}
          <div className="bg-blue-600 text-white font-black text-sm tracking-wider flex items-center justify-center w-8 h-8 rounded shrink-0 shadow-inner">
            ID
          </div>
          <span className={`text-lg font-black tracking-wider ${isDark ? 'text-white' : 'text-gray-900'}`}>
            InThreat<span className="text-blue-500">Detection</span>
          </span>
        </div>
        
        <div className="flex items-center space-x-4">
          <EncryptionIndicator onTogglePanel={() => {}} />
          {/* Notification Bell with Dropdown */}
          <div className="relative" ref={notifRef}>
            <button 
              onClick={() => setShowNotifPanel(!showNotifPanel)}
              className={`p-2 rounded-full transition relative ${isDark ? 'text-gray-400 hover:bg-[#2d3340] hover:text-white' : 'text-gray-500 hover:bg-gray-100 hover:text-gray-900'}`}
            >
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9"></path></svg>
              {/* Badge */}
              {anomalyAlerts.filter(a => a.status === 'OPEN').length > 0 && (
                <span className="absolute -top-0.5 -right-0.5 bg-red-500 text-white text-[10px] font-black min-w-[18px] h-[18px] flex items-center justify-center rounded-full shadow-lg animate-pulse">
                  {anomalyAlerts.filter(a => a.status === 'OPEN').length}
                </span>
              )}
            </button>

            {/* Notification Dropdown Panel */}
            {showNotifPanel && (
              <div className={`absolute right-0 top-12 w-96 max-h-[70vh] overflow-y-auto rounded-xl shadow-2xl border z-50 ${isDark ? 'bg-[#1e222b] border-[#2d3340]' : 'bg-white border-gray-200'}`}>
                <div className={`px-4 py-3 border-b flex justify-between items-center ${isDark ? 'border-[#2d3340]' : 'border-gray-200'}`}>
                  <h3 className={`font-bold text-sm ${isDark ? 'text-white' : 'text-gray-800'}`}>🛡️ Anomaly Alerts</h3>
                  <button 
                    onClick={async () => { try { await triggerAnomalyScan(); const data = await getAnomalyAlerts(); setAnomalyAlerts(data); } catch(e){} }}
                    className="text-xs font-bold text-blue-500 hover:text-blue-400 transition"
                  >Run Scan</button>
                </div>
                {anomalyAlerts.length === 0 ? (
                  <div className={`p-6 text-center text-sm ${isDark ? 'text-gray-500' : 'text-gray-400'}`}>No anomaly alerts detected.</div>
                ) : (
                  <div className="divide-y divide-[#2d3340]">
                    {anomalyAlerts.slice(0, 20).map((alert) => {
                      const sevColor = alert.severity === 'Critical' ? 'bg-red-500' : alert.severity === 'High' ? 'bg-orange-500' : 'bg-yellow-500';
                      return (
                        <div key={alert._id} className={`px-4 py-3 flex items-start space-x-3 transition-colors ${alert.status === 'ACKNOWLEDGED' ? 'opacity-50' : ''} ${isDark ? 'hover:bg-[#262b36]' : 'hover:bg-gray-50'}`}>
                          <span className={`mt-1 w-2.5 h-2.5 rounded-full shrink-0 ${sevColor}`}></span>
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center justify-between">
                              <span className={`text-xs font-bold truncate ${isDark ? 'text-gray-200' : 'text-gray-800'}`}>{alert.employee_name} ({alert.employee_id})</span>
                              <span className={`text-[10px] shrink-0 ml-2 ${isDark ? 'text-gray-500' : 'text-gray-400'}`}>{alert.anomaly_type}</span>
                            </div>
                            <p className={`text-[11px] mt-0.5 leading-snug line-clamp-2 ${isDark ? 'text-gray-400' : 'text-gray-500'}`}>{alert.description}</p>
                            <div className="flex items-center justify-between mt-1.5">
                              <span className={`text-[10px] ${isDark ? 'text-gray-600' : 'text-gray-400'}`}>{alert.confidence}% confidence</span>
                              {alert.status === 'OPEN' && (
                                <button 
                                  onClick={async (e) => { e.stopPropagation(); try { await acknowledgeAnomalyAlert(alert._id); const data = await getAnomalyAlerts(); setAnomalyAlerts(data); } catch(err){} }}
                                  className="text-[10px] font-bold text-blue-400 hover:text-blue-300 transition"
                                >Dismiss</button>
                              )}
                            </div>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            )}
          </div>
          {/* Theme Toggle */}
          <button onClick={() => setIsDark(!isDark)} className={`p-2 rounded-full transition ${isDark ? 'text-gray-400 hover:bg-[#2d3340] hover:text-white' : 'text-gray-500 hover:bg-gray-100 hover:text-gray-900'}`} title="Toggle Theme">
            {isDark ? '☀️' : '🌙'}
          </button>
        </div>
      </nav>

      {/* Main Content Area */}
      <main className="flex-1 relative flex flex-col">
        {/* Sidebar Toggle Button (Below Navbar, Left-most) */}
        <div className="absolute top-4 left-4 z-30">
          <button 
            onClick={() => setIsSidebarOpen(true)}
            className={`p-2.5 rounded-lg shadow-sm border transition-colors ${isDark ? 'bg-[#1e222b] border-[#2d3340] text-gray-400 hover:text-white hover:bg-[#262b36]' : 'bg-white border-gray-200 text-gray-600 hover:text-gray-900 hover:bg-gray-50'}`}
          >
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M4 6h16M4 12h16M4 18h16"></path></svg>
          </button>
        </div>

        {/* Sidebar Overlay */}
        {isSidebarOpen && (
          <>
            {/* Backdrop */}
            <div 
              className="fixed inset-0 bg-black/60 z-40 backdrop-blur-sm transition-opacity" 
              onClick={() => setIsSidebarOpen(false)}
            ></div>
            {/* Sidebar Drawer */}
            <div className={`fixed top-0 left-0 h-full w-72 shadow-2xl z-50 transform transition-transform duration-300 flex flex-col ${isDark ? 'bg-[#1e222b] border-r border-[#2d3340]' : 'bg-white border-r border-gray-200'}`}>
              <div className={`px-6 py-5 flex justify-between items-center border-b ${isDark ? 'border-[#2d3340]' : 'border-gray-200'}`}>
                <h3 className={`font-black tracking-widest text-sm uppercase ${isDark ? 'text-gray-400' : 'text-gray-500'}`}>Navigation</h3>
                <button onClick={() => setIsSidebarOpen(false)} className={`text-2xl leading-none transition ${isDark ? 'text-gray-400 hover:text-white' : 'text-gray-500 hover:text-gray-900'}`}>&times;</button>
              </div>

              <div className="flex flex-col p-4 space-y-2 flex-1">
                <button 
                  onClick={() => { setCurrentView('dashboard'); setIsSidebarOpen(false); }}
                  className={`text-left px-4 py-3 rounded-lg font-bold transition-colors flex items-center space-x-3 ${currentView === 'dashboard' ? 'bg-blue-600 text-white shadow-md' : (isDark ? 'text-gray-300 hover:bg-[#2d3340] hover:text-white' : 'text-gray-600 hover:bg-gray-100 hover:text-gray-900')}`}
                >
                  <span>📊</span>
                  <span>SOC Terminal</span>
                </button>
                <button 
                  onClick={() => { setCurrentView('simulator'); setIsSidebarOpen(false); }}
                  className={`text-left px-4 py-3 rounded-lg font-bold transition-colors flex items-center space-x-3 ${currentView === 'simulator' ? 'bg-blue-600 text-white shadow-md' : (isDark ? 'text-gray-300 hover:bg-[#2d3340] hover:text-white' : 'text-gray-600 hover:bg-gray-100 hover:text-gray-900')}`}
                >
                  <span>🧑‍💻</span>
                  <span>Employee Simulator</span>
                </button>
                
                <div className={`my-4 border-t ${isDark ? 'border-[#2d3340]' : 'border-gray-200'}`}></div>
                
                <button 
                  onClick={() => { setShowProvisionModal(true); setIsSidebarOpen(false); }}
                  className={`text-left px-4 py-3 rounded-lg font-bold transition-colors flex items-center space-x-3 ${isDark ? 'text-gray-300 hover:bg-[#2d3340] hover:text-white' : 'text-gray-600 hover:bg-gray-100 hover:text-gray-900'}`}
                >
                  <span className="text-blue-500 text-xl leading-none">+</span>
                  <span>Provision User</span>
                </button>
              </div>

              <div className={`p-4 border-t ${isDark ? 'border-[#2d3340]' : 'border-gray-200'}`}>
                <button 
                  onClick={() => { handleLogout(); setIsSidebarOpen(false); }} 
                  className={`w-full text-left px-4 py-3 rounded-lg font-bold transition-colors flex items-center space-x-3 ${isDark ? 'text-red-400 hover:bg-red-500/10 hover:text-red-300' : 'text-red-600 hover:bg-red-50'}`}
                >
                  <span>🚪</span>
                  <span>Secure Logout</span>
                </button>
              </div>
            </div>
          </>
        )}

        {/* View Rendering */}
        <div className={`flex-1 flex flex-col transition-all duration-300 ${currentView === 'dashboard' ? 'pl-16' : ''}`}>
          {currentView === 'dashboard' ? <Dashboard isDark={isDark} anomalyAlerts={anomalyAlerts} onAnomalyRefresh={async () => { try { const data = await getAnomalyAlerts(); setAnomalyAlerts(data); } catch(e){} }} /> : <Simulator />}
        </div>
      </main>

      {renderProvisionModal()}
    </div>
  );
}

export default App;