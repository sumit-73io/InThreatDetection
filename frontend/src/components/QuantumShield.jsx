import React, { useState, useEffect, useCallback } from 'react';
import { getQuantumStatus, getIntegrityStats, runIntegrityVerification } from '../services/api';

export default function QuantumShield({ isDark }) {
    const [quantumStatus, setQuantumStatus] = useState(null);
    const [integrityStats, setIntegrityStats] = useState(null);
    const [scanning, setScanning] = useState(false);
    const [scanResults, setScanResults] = useState(null);
    const [expanded, setExpanded] = useState(false);
    const [error, setError] = useState(null);

    const fetchStatus = useCallback(async () => {
        try {
            const [status, stats] = await Promise.all([
                getQuantumStatus(),
                getIntegrityStats()
            ]);
            setQuantumStatus(status);
            setIntegrityStats(stats);
            setError(null);
        } catch (err) {
            setError('Unable to reach Quantum Security Engine');
        }
    }, []);

    useEffect(() => {
        fetchStatus();
        const interval = setInterval(fetchStatus, 10000);
        return () => clearInterval(interval);
    }, [fetchStatus]);

    const handleIntegrityScan = async () => {
        setScanning(true);
        setScanResults(null);
        try {
            const results = await runIntegrityVerification();
            setScanResults(results);
            await fetchStatus();
        } catch (err) {
            setError('Integrity scan failed');
        } finally {
            setScanning(false);
        }
    };

    const cardBg = isDark ? 'bg-[#1e222b] border-[#2d3340]' : 'bg-white border-gray-100';
    const textPrimary = isDark ? 'text-gray-200' : 'text-gray-800';
    const textSecondary = isDark ? 'text-gray-400' : 'text-gray-500';
    const innerBg = isDark ? 'bg-[#15171e]' : 'bg-gray-50';

    const overallScore = integrityStats?.overall?.integrity_score ?? 100;
    const chainIntact = integrityStats?.overall?.chain_intact ?? true;

    const getShieldColor = () => {
        if (scanning) return 'text-amber-400';
        if (!quantumStatus || quantumStatus.status !== 'active') return 'text-gray-500';
        if (overallScore >= 95 && chainIntact) return 'text-emerald-400';
        if (overallScore >= 70) return 'text-amber-400';
        return 'text-red-400';
    };

    const getStatusLabel = () => {
        if (scanning) return 'SCANNING...';
        if (!quantumStatus || quantumStatus.status !== 'active') return 'OFFLINE';
        if (overallScore >= 95 && chainIntact) return 'ALL SYSTEMS SECURE';
        if (overallScore >= 70) return 'PARTIAL INTEGRITY';
        return 'TAMPERING DETECTED';
    };

    return (
        <div className={`${cardBg} border rounded-xl shadow-lg overflow-hidden mb-6 transition-all duration-500`}>
            {/* Main Status Bar */}
            <div 
                className="px-6 py-4 flex items-center justify-between cursor-pointer select-none"
                onClick={() => setExpanded(!expanded)}
            >
                <div className="flex items-center space-x-4">
                    {/* Animated Shield Icon */}
                    <div className="relative">
                        <svg className={`w-10 h-10 ${getShieldColor()} transition-colors duration-500 ${scanning ? 'animate-pulse' : ''}`} fill="currentColor" viewBox="0 0 24 24">
                            <path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 10.99h7c-.53 4.12-3.28 7.79-7 8.94V12H5V6.3l7-3.11v8.8z"/>
                        </svg>
                        {quantumStatus?.status === 'active' && !scanning && (
                            <span className="absolute -top-0.5 -right-0.5 flex h-3 w-3">
                                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                                <span className="relative inline-flex rounded-full h-3 w-3 bg-emerald-500"></span>
                            </span>
                        )}
                    </div>
                    <div>
                        <h3 className={`text-sm font-bold tracking-wider uppercase ${getShieldColor()}`}>
                            🛡️ Quantum Shield — {getStatusLabel()}
                        </h3>
                        <p className={`text-xs ${textSecondary} mt-0.5`}>
                            {quantumStatus?.algorithm_suite?.symmetric_cipher || 'AES-256-GCM'} + {quantumStatus?.algorithm_suite?.hash_function || 'SHA3-256'} | Key: {quantumStatus?.key_fingerprint || '—'}
                        </p>
                    </div>
                </div>

                <div className="flex items-center space-x-4">
                    {/* Integrity Score Circle */}
                    <div className="relative w-12 h-12">
                        <svg className="w-12 h-12 transform -rotate-90" viewBox="0 0 36 36">
                            <path className={isDark ? 'stroke-gray-700' : 'stroke-gray-200'} d="M18 2.0845a 15.9155 15.9155 0 0 1 0 31.831a 15.9155 15.9155 0 0 1 0 -31.831" fill="none" strokeWidth="3"/>
                            <path 
                                className={`${overallScore >= 95 ? 'stroke-emerald-400' : overallScore >= 70 ? 'stroke-amber-400' : 'stroke-red-400'} transition-all duration-1000`}
                                strokeDasharray={`${overallScore}, 100`}
                                d="M18 2.0845a 15.9155 15.9155 0 0 1 0 31.831a 15.9155 15.9155 0 0 1 0 -31.831" 
                                fill="none" 
                                strokeWidth="3" 
                                strokeLinecap="round"
                            />
                        </svg>
                        <span className={`absolute inset-0 flex items-center justify-center text-xs font-bold ${textPrimary}`}>
                            {overallScore}%
                        </span>
                    </div>

                    {/* Expand Arrow */}
                    <svg className={`w-5 h-5 ${textSecondary} transition-transform duration-300 ${expanded ? 'rotate-180' : ''}`} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
                        <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
                    </svg>
                </div>
            </div>

            {/* Expanded Details Panel */}
            {expanded && (
                <div className={`border-t ${isDark ? 'border-[#2d3340]' : 'border-gray-200'} px-6 py-5 space-y-5`}
                    style={{ animation: 'slideDown 0.3s ease-out' }}
                >
                    {/* Algorithm Suite */}
                    <div>
                        <h4 className={`text-xs font-bold uppercase tracking-wider mb-3 ${textSecondary}`}>Algorithm Suite</h4>
                        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                            {quantumStatus?.algorithm_suite && Object.entries(quantumStatus.algorithm_suite).map(([key, value]) => (
                                <div key={key} className={`${innerBg} rounded-lg px-3 py-2.5 border ${isDark ? 'border-[#2d3340]' : 'border-gray-200'}`}>
                                    <p className={`text-[10px] uppercase tracking-wider font-semibold ${textSecondary}`}>
                                        {key.replace(/_/g, ' ')}
                                    </p>
                                    <p className={`text-xs font-bold mt-1 ${textPrimary} truncate`} title={value}>{value}</p>
                                </div>
                            ))}
                        </div>
                    </div>

                    {/* Integrity Statistics */}
                    <div>
                        <h4 className={`text-xs font-bold uppercase tracking-wider mb-3 ${textSecondary}`}>Data Integrity Status</h4>
                        <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
                            <div className={`${innerBg} rounded-lg px-4 py-3 border ${isDark ? 'border-[#2d3340]' : 'border-gray-200'} text-center`}>
                                <p className={`text-2xl font-bold ${textPrimary}`}>{integrityStats?.overall?.total_documents ?? 0}</p>
                                <p className={`text-[10px] uppercase tracking-wider font-semibold ${textSecondary}`}>Total Records</p>
                            </div>
                            <div className={`${innerBg} rounded-lg px-4 py-3 border ${isDark ? 'border-[#2d3340]' : 'border-gray-200'} text-center`}>
                                <p className="text-2xl font-bold text-emerald-400">{integrityStats?.overall?.verified ?? 0}</p>
                                <p className={`text-[10px] uppercase tracking-wider font-semibold ${textSecondary}`}>Verified ✅</p>
                            </div>
                            <div className={`${innerBg} rounded-lg px-4 py-3 border ${isDark ? 'border-[#2d3340]' : 'border-gray-200'} text-center`}>
                                <p className="text-2xl font-bold text-red-400">{integrityStats?.overall?.tampered ?? 0}</p>
                                <p className={`text-[10px] uppercase tracking-wider font-semibold ${textSecondary}`}>Tampered 🚨</p>
                            </div>
                            <div className={`${innerBg} rounded-lg px-4 py-3 border ${isDark ? 'border-[#2d3340]' : 'border-gray-200'} text-center`}>
                                <p className="text-2xl font-bold text-amber-400">{integrityStats?.overall?.unverified ?? 0}</p>
                                <p className={`text-[10px] uppercase tracking-wider font-semibold ${textSecondary}`}>Unverified ⚠️</p>
                            </div>
                            <div className={`${innerBg} rounded-lg px-4 py-3 border ${isDark ? 'border-[#2d3340]' : 'border-gray-200'} text-center`}>
                                <p className={`text-2xl font-bold ${chainIntact ? 'text-emerald-400' : 'text-red-400'}`}>
                                    {chainIntact ? '🔗' : '💔'}
                                </p>
                                <p className={`text-[10px] uppercase tracking-wider font-semibold ${textSecondary}`}>
                                    Hash Chain {chainIntact ? 'Intact' : 'Broken'}
                                </p>
                            </div>
                        </div>
                    </div>

                    {/* Per-Collection Breakdown */}
                    {integrityStats && (
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                            {['activities', 'alerts'].map(collection => {
                                const stats = integrityStats[collection];
                                if (!stats) return null;
                                return (
                                    <div key={collection} className={`${innerBg} rounded-lg px-4 py-3 border ${isDark ? 'border-[#2d3340]' : 'border-gray-200'}`}>
                                        <div className="flex justify-between items-center mb-2">
                                            <span className={`text-xs font-bold uppercase ${textSecondary}`}>
                                                {collection === 'activities' ? '📋 Activities' : '🚨 Alerts'}
                                            </span>
                                            <span className={`text-xs font-bold ${stats.integrity_score >= 95 ? 'text-emerald-400' : stats.integrity_score >= 70 ? 'text-amber-400' : 'text-red-400'}`}>
                                                {stats.integrity_score}%
                                            </span>
                                        </div>
                                        <div className={`w-full h-2 rounded-full ${isDark ? 'bg-gray-700' : 'bg-gray-200'}`}>
                                            <div 
                                                className={`h-full rounded-full transition-all duration-1000 ${stats.integrity_score >= 95 ? 'bg-emerald-400' : stats.integrity_score >= 70 ? 'bg-amber-400' : 'bg-red-400'}`}
                                                style={{ width: `${stats.integrity_score}%` }}
                                            />
                                        </div>
                                        <div className="flex justify-between mt-2">
                                            <span className={`text-[10px] ${textSecondary}`}>{stats.verified} verified</span>
                                            <span className={`text-[10px] ${textSecondary}`}>{stats.total} total</span>
                                        </div>
                                    </div>
                                );
                            })}
                        </div>
                    )}

                    {/* Engine Metadata */}
                    <div className="flex items-center justify-between">
                        <div className="flex items-center space-x-4">
                            <span className={`text-[10px] ${textSecondary}`}>
                                Uptime: {quantumStatus?.uptime || '—'}
                            </span>
                            <span className={`text-[10px] ${textSecondary}`}>
                                Ops: {quantumStatus?.operations_performed ?? 0}
                            </span>
                            <span className={`text-[10px] ${textSecondary}`}>
                                Key: {quantumStatus?.key_strength_bits || 256}-bit
                            </span>
                        </div>

                        {/* Scan Button */}
                        <button
                            onClick={handleIntegrityScan}
                            disabled={scanning}
                            className={`flex items-center space-x-2 px-4 py-2 rounded-lg text-sm font-bold transition-all duration-300 ${
                                scanning 
                                    ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30 cursor-wait' 
                                    : 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 hover:bg-emerald-500/20 hover:shadow-lg hover:shadow-emerald-500/10'
                            }`}
                        >
                            {scanning ? (
                                <>
                                    <svg className="animate-spin w-4 h-4" fill="none" viewBox="0 0 24 24">
                                        <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"/>
                                        <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"/>
                                    </svg>
                                    <span>Scanning...</span>
                                </>
                            ) : (
                                <>
                                    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
                                        <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                                    </svg>
                                    <span>Run Integrity Scan</span>
                                </>
                            )}
                        </button>
                    </div>

                    {/* Scan Progress Bar */}
                    {scanning && (
                        <div className={`w-full h-1.5 rounded-full overflow-hidden ${isDark ? 'bg-gray-700' : 'bg-gray-200'}`}>
                            <div className="h-full bg-gradient-to-r from-amber-400 via-emerald-400 to-cyan-400 rounded-full animate-scan-progress" 
                                style={{
                                    width: '40%',
                                    animation: 'scanProgress 2s ease-in-out infinite'
                                }}
                            />
                        </div>
                    )}

                    {error && (
                        <div className="bg-red-500/10 border border-red-500/30 text-red-400 text-xs px-4 py-2 rounded-lg">
                            ⚠️ {error}
                        </div>
                    )}
                </div>
            )}

            <style>{`
                @keyframes slideDown {
                    from { opacity: 0; max-height: 0; }
                    to { opacity: 1; max-height: 1000px; }
                }
                @keyframes scanProgress {
                    0% { transform: translateX(-100%); }
                    50% { transform: translateX(150%); }
                    100% { transform: translateX(300%); }
                }
            `}</style>
        </div>
    );
}
