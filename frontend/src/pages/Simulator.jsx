import React, { useState, useEffect } from 'react';
import { logActivity, loginEmployee } from '../services/api';

const ACTIONS = [
    { label: 'Login', value: 'LOGIN', color: 'bg-blue-500' },
    { label: 'View Customer', value: 'VIEW_CUSTOMER', color: 'bg-gray-500' },
    { label: 'Download File', value: 'DOWNLOAD_FILE', color: 'bg-yellow-500' },
    { label: 'Download Confidential File', value: 'DOWNLOAD_CONFIDENTIAL', color: 'bg-orange-600' },
    { label: 'Delete File', value: 'DELETE_FILE', color: 'bg-red-500' },
    { label: 'USB Connected', value: 'USB_CONNECTED', color: 'bg-purple-500' },
    { label: 'Failed Login', value: 'FAILED_LOGIN', color: 'bg-red-700' },
    { label: 'Change Permission', value: 'CHANGE_PERMISSION', color: 'bg-pink-600' },
    { label: 'Logout', value: 'LOGOUT', color: 'bg-gray-800' },
];

export default function Simulator() {
    // Read from localStorage on initial render to keep session alive
    const [activeEmployee, setActiveEmployee] = useState(() => localStorage.getItem('InthreatDetection_employee') || null);
    
    const [empIdInput, setEmpIdInput] = useState('');
    const [empPassInput, setEmpPassInput] = useState('');
    const [loginError, setLoginError] = useState('');
    const [lastAction, setLastAction] = useState(null);

    const handleEmployeeLogin = async (e) => {
        e.preventDefault();
        setLoginError('');
        try {
            const result = await loginEmployee(empIdInput, empPassInput);
            
            // Set state AND save to localStorage
            setActiveEmployee(result.employee_id);
            localStorage.setItem('InthreatDetection_employee', result.employee_id);
            
            await logActivity('LOGIN', result.employee_id);
        } catch (err) {
            setLoginError('Authentication failed. Verify credentials with SOC Admin.');
        }
    };

    const handleAction = async (actionValue) => {
        try {
            const result = await logActivity(actionValue, activeEmployee);
            setLastAction({ action: result.action, time: new Date().toLocaleTimeString() });
            
            if (actionValue === 'LOGOUT') {
                // Clear state AND remove from localStorage
                setActiveEmployee(null);
                setLastAction(null);
                localStorage.removeItem('InthreatDetection_employee');
            }
        } catch (err) {
            alert("Failed to log activity. Check backend connection.");
        }
    };

    // View 1: The Login Gate
    if (!activeEmployee) {
        return (
            <div className="flex flex-col items-center justify-center pt-20 font-sans">
                <div className="bg-white p-8 rounded-xl shadow-lg border border-gray-200 w-96 text-center">
                    <h1 className="text-2xl font-bold mb-2 text-gray-800">Employee Portal</h1>
                    <p className="text-gray-500 text-sm mb-6">Enter your corporate credentials.</p>
                    
                    {loginError && <div className="bg-red-50 text-red-600 text-xs py-2 rounded mb-4 border border-red-200">{loginError}</div>}
                    
                    <form onSubmit={handleEmployeeLogin} className="space-y-4">
                        <input 
                            required
                            type="text" 
                            placeholder="Employee ID" 
                            value={empIdInput}
                            onChange={(e) => setEmpIdInput(e.target.value)}
                            className="w-full border border-gray-300 rounded px-3 py-2 outline-none focus:border-blue-500 text-black"
                        />
                        <input 
                            required
                            type="password" 
                            placeholder="Password" 
                            value={empPassInput}
                            onChange={(e) => setEmpPassInput(e.target.value)}
                            className="w-full border border-gray-300 rounded px-3 py-2 outline-none focus:border-blue-500 text-black"
                        />
                        <button type="submit" className="w-full bg-blue-600 hover:bg-blue-700 text-white font-bold py-2 rounded transition">
                            Sign In
                        </button>
                    </form>
                </div>
            </div>
        );
    }

    // View 2: The Telemetry Generator
    return (
        <div className="p-8 max-w-4xl mx-auto font-sans">
            <div className="flex justify-between items-center mb-8 border-b border-gray-800 pb-4">
                <div>
                    <h1 className="text-3xl font-bold text-white tracking-tight">Endpoint Simulator</h1>
                    <p className="text-gray-400 mt-1">Generating live telemetry for <span className="text-blue-400 font-mono font-bold">{activeEmployee}</span></p>
                </div>
                <button 
                    onClick={() => handleAction('LOGOUT')}
                    className="bg-red-500/10 hover:bg-red-500/20 text-red-500 border border-red-500/50 px-4 py-2 rounded text-sm font-bold transition"
                >
                    Terminate Session
                </button>
            </div>
            
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-8">
                {ACTIONS.filter(a => a.value !== 'LOGIN' && a.value !== 'LOGOUT').map((btn) => (
                    <button
                        key={btn.value}
                        onClick={() => handleAction(btn.value)}
                        className={`${btn.color} text-white py-3 px-4 rounded shadow hover:opacity-90 transition active:scale-95 font-medium`}
                    >
                        {btn.label}
                    </button>
                ))}
            </div>

            {lastAction && (
                <div className="bg-green-900/30 border border-green-500/50 text-green-400 px-4 py-3 rounded flex justify-between items-center">
                    <span><strong>Network Payload Sent:</strong> <code>{lastAction.action}</code></span>
                    <span className="text-sm font-mono">{lastAction.time}</span>
                </div>
            )}
        </div>
    );
}