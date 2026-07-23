import React, { useState, useEffect } from 'react';
import Simulator from './pages/Simulator';
import Dashboard from './pages/Dashboard';
import { loginAdmin } from './services/api';
import EncryptionIndicator from './components/EncryptionIndicator';

function App() {
  const [currentView, setCurrentView] = useState('dashboard');
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  
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
  };

  // Render the Login Screen if they want the dashboard but aren't authenticated
  if (currentView === 'dashboard' && !isAuthenticated) {
    return (
      <div className="min-h-screen bg-gray-950 flex flex-col justify-center items-center font-sans">
        <div className="bg-gray-900 p-8 rounded-xl border border-gray-800 shadow-2xl w-96 text-center">
            <h1 className="text-2xl font-black tracking-wider text-white mb-2">InThreat<span className="text-blue-500">Detection</span></h1>
            <p className="text-gray-400 text-sm mb-6">Restricted SOC Access</p>
            
            {authError && <div className="bg-red-500/10 border border-red-500/50 text-red-500 text-xs py-2 rounded mb-4">{authError}</div>}
            
            <form onSubmit={handleLogin} className="space-y-4">
                <input 
                    type="text" 
                    placeholder="Admin Username" 
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    className="w-full bg-gray-950 border border-gray-800 rounded px-3 py-2 text-white outline-none focus:border-blue-500"
                />
                <input 
                    type="password" 
                    placeholder="Password" 
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    className="w-full bg-gray-950 border border-gray-800 rounded px-3 py-2 text-white outline-none focus:border-blue-500"
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
    <div className="min-h-screen bg-gray-950 flex flex-col font-sans">
      <nav className="bg-gray-900 border-b border-gray-800 px-6 py-3 flex justify-between items-center shadow-sm">
        <span className="text-lg font-black tracking-wider text-white">InThreat<span className="text-blue-500">Detection</span></span>
        <div className="flex items-center space-x-4">
          {/* Quantum Encryption Indicator */}
          {isAuthenticated && (
            <EncryptionIndicator onTogglePanel={() => {}} />
          )}
          <div className="flex bg-gray-950 p-1 rounded-lg border border-gray-800">
            <button 
              onClick={() => setCurrentView('dashboard')}
              className={`px-4 py-1.5 rounded-md text-xs font-semibold transition ${currentView === 'dashboard' ? 'bg-blue-600 text-white shadow' : 'text-gray-400 hover:text-white'}`}
            >
              SOC Terminal
            </button>
            <button 
              onClick={() => setCurrentView('simulator')}
              className={`px-4 py-1.5 rounded-md text-xs font-semibold transition ${currentView === 'simulator' ? 'bg-blue-600 text-white shadow' : 'text-gray-400 hover:text-white'}`}
            >
              Employee Simulator
            </button>
          </div>
          {isAuthenticated && currentView === 'dashboard' && (
              <button onClick={handleLogout} className="text-xs text-red-400 hover:text-red-300 border border-red-500/30 px-3 py-1.5 rounded bg-red-500/10">
                  Logout
              </button>
          )}
        </div>
      </nav>

      <main className="flex-1 bg-gray-950">
        {currentView === 'dashboard' ? <Dashboard /> : <Simulator />}
      </main>
    </div>
  );
}

export default App;