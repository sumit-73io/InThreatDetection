import React, { useState, useEffect } from 'react';
import { getQuantumStatus } from '../services/api';

/**
 * EncryptionIndicator — Navbar-level indicator showing quantum encryption status.
 * 
 * Shows a lock icon with "PQC: Active/Inactive" label.
 * Clicking it can optionally trigger expansion of the full QuantumShield panel.
 * 
 * Props:
 *   - onTogglePanel: callback to toggle the QuantumShield panel visibility
 */
export default function EncryptionIndicator({ onTogglePanel }) {
    const [isActive, setIsActive] = useState(false);
    const [fingerprint, setFingerprint] = useState('');
    const [hover, setHover] = useState(false);

    useEffect(() => {
        const checkStatus = async () => {
            try {
                const status = await getQuantumStatus();
                setIsActive(status?.status === 'active');
                setFingerprint(status?.key_fingerprint || '');
            } catch {
                setIsActive(false);
            }
        };
        checkStatus();
        const interval = setInterval(checkStatus, 15000);
        return () => clearInterval(interval);
    }, []);

    return (
        <button
            onClick={onTogglePanel}
            onMouseEnter={() => setHover(true)}
            onMouseLeave={() => setHover(false)}
            className={`
                relative flex items-center space-x-2 px-3 py-1.5 rounded-lg text-xs font-bold
                transition-all duration-300 border
                ${isActive 
                    ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30 hover:bg-emerald-500/20 hover:shadow-lg hover:shadow-emerald-500/10' 
                    : 'bg-red-500/10 text-red-400 border-red-500/30 hover:bg-red-500/20'
                }
            `}
            title={isActive ? `PQC Active — Key: ${fingerprint}` : 'Quantum encryption is not active'}
        >
            {/* Lock Icon */}
            <div className="relative">
                <svg 
                    className={`w-4 h-4 transition-transform duration-300 ${hover ? 'scale-110' : ''}`} 
                    fill="currentColor" 
                    viewBox="0 0 24 24"
                >
                    {isActive ? (
                        // Locked icon
                        <path d="M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zm-6 9c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2zm3.1-9H8.9V6c0-1.71 1.39-3.1 3.1-3.1 1.71 0 3.1 1.39 3.1 3.1v2z"/>
                    ) : (
                        // Unlocked icon
                        <path d="M12 17c1.1 0 2-.9 2-2s-.9-2-2-2-2 .9-2 2 .9 2 2 2zm6-9h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6h1.9c0-1.71 1.39-3.1 3.1-3.1 1.71 0 3.1 1.39 3.1 3.1v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zm0 12H6V10h12v10z"/>
                    )}
                </svg>
                {/* Active pulse indicator */}
                {isActive && (
                    <span className="absolute -top-0.5 -right-0.5 flex h-2 w-2">
                        <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                        <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
                    </span>
                )}
            </div>

            {/* Label */}
            <span className="hidden sm:inline">
                PQC: {isActive ? 'Active' : 'Inactive'}
            </span>
        </button>
    );
}
