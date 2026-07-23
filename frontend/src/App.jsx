import React, { useState, useEffect } from 'react';
import Simulator from './pages/Simulator';
import Dashboard from './pages/Dashboard';
import { loginAdmin, createEmployee } from './services/api';
import EncryptionIndicator from './components/EncryptionIndicator';

function App() {
  const [currentView, setCurrentView] = useState('dashboard');
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [isDark, setIsDark] = useState(true);
  const [isSidebarOpen, setIsSidebarOpen] = useState(false);
  const [showProvisionModal, setShowProvisionModal] = useState(false);
  
  // Login State
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [authError, setAuthError] = useState('');

  // Check for existing token on load
  useEffect(() => {
    const token = localStorage.getItem('InthreatDetection_token');
    if (token) setIsAuthenticated(true);
  }, []);

  const handleLogin = async (e) => {
    e.preventDefault();
    setAuthError('');
    try {
      const data = await loginAdmin(username, password);
      localStorage.setItem('InthreatDetection_token', data.access_token);
      setIsAuthenticated(true);
    } catch (err) {
      setAuthError('Access Denied. Invalid credentials.');
    }
  };

  const handleLogout = () => {
    localStorage.removeItem('InthreatDetection_token');
    setIsAuthenticated(false);
    setIsSidebarOpen(false);
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
              <input name="empName" required placeholder="Full Name (e.g., John Doe)" className={`border rounded px-4 py-2 w-full outline-none transition-colors ${isDark ? 'bg-[#15171e] border-[#2d3340] text-white focus:border-blue-500' : 'bg-gray-50 border-gray-300 text-black focus:border-blue-500'}`}/>
              <input name="empId" required placeholder="User ID (e.g., ADM-01)" className={`border rounded px-4 py-2 w-full outline-none transition-colors ${isDark ? 'bg-[#15171e] border-[#2d3340] text-white focus:border-blue-500' : 'bg-gray-50 border-gray-300 text-black focus:border-blue-500'}`}/>
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
              <input name="empPass" required type="password" placeholder="Password" className={`border rounded px-4 py-2 w-full outline-none transition-colors ${isDark ? 'bg-[#15171e] border-[#2d3340] text-white focus:border-blue-500' : 'bg-gray-50 border-gray-300 text-black focus:border-blue-500'}`}/>
              <button type="submit" className="bg-blue-600 hover:bg-blue-700 text-white py-2 px-4 rounded font-bold transition mt-2">Create Account</button>
          </form>
        </div>
      </div>
    );
  };

  // Render the Login Screen if they want the dashboard but aren't authenticated
  if (currentView === 'dashboard' && !isAuthenticated) {
    return (
      <div className="min-h-screen bg-[#15171e] flex flex-col justify-center items-center font-sans">
        <div className="bg-[#1e222b] p-8 rounded-xl border border-[#2d3340] shadow-2xl w-96 text-center">
            <h1 className="text-2xl font-black tracking-wider text-white mb-2">InThreat<span className="text-blue-500">Detection</span></h1>
            <p className="text-gray-400 text-sm mb-6">Restricted SOC Access</p>
            
            {authError && <div className="bg-red-500/10 border border-red-500/50 text-red-500 text-xs py-2 rounded mb-4">{authError}</div>}
            
            <form onSubmit={handleLogin} className="space-y-4">
                <input 
                    type="text" 
                    placeholder="Admin Username" 
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    className="w-full bg-[#15171e] border border-[#2d3340] rounded px-3 py-2 text-white outline-none focus:border-blue-500"
                />
                <input 
                    type="password" 
                    placeholder="Password" 
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    className="w-full bg-[#15171e] border border-[#2d3340] rounded px-3 py-2 text-white outline-none focus:border-blue-500"
                />
                <button type="submit" className="w-full bg-blue-600 hover:bg-blue-700 text-white font-bold py-2 rounded transition">
                    Authenticate
                </button>
            </form>
            <button 
                onClick={() => setCurrentView('simulator')} 
                className="mt-6 text-gray-500 hover:text-gray-300 text-xs underline"
            >
                Return to Public Simulator
            </button>
        </div>
      </div>
    );
  }

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
          {isAuthenticated && (
            <EncryptionIndicator onTogglePanel={() => {}} />
          )}
          {/* Notification Bell */}
          <button className={`p-2 rounded-full transition ${isDark ? 'text-gray-400 hover:bg-[#2d3340] hover:text-white' : 'text-gray-500 hover:bg-gray-100 hover:text-gray-900'}`}>
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9"></path></svg>
          </button>
          {/* Theme Toggle */}
          <button onClick={() => setIsDark(!isDark)} className={`p-2 rounded-full transition ${isDark ? 'text-gray-400 hover:bg-[#2d3340] hover:text-white' : 'text-gray-500 hover:bg-gray-100 hover:text-gray-900'}`} title="Toggle Theme">
            {isDark ? '☀️' : '🌙'}
          </button>
        </div>
      </nav>

      {/* Main Content Area */}
      <main className="flex-1 relative flex flex-col">
        {isAuthenticated && (
          <>
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
          </>
        )}

        {/* View Rendering */}
        <div className={`flex-1 flex flex-col transition-all duration-300 ${isAuthenticated && currentView === 'dashboard' ? 'pl-16' : ''}`}>
          {currentView === 'dashboard' ? <Dashboard isDark={isDark} /> : <Simulator />}
        </div>
      </main>

      {renderProvisionModal()}
    </div>
  );
}

export default App;