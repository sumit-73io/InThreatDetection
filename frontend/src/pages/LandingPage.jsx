import React, { useState, useEffect } from 'react';

export default function LandingPage({ onEnter, isDark }) {
    const [isVisible, setIsVisible] = useState(false);

    useEffect(() => {
        const t = setTimeout(() => setIsVisible(true), 100);
        return () => clearTimeout(t);
    }, []);

    const features = [
        {
            icon: '🔍',
            title: 'Behavioral Analytics',
            desc: 'AI-powered UEBA engine detects insider threats through real-time session monitoring and behavioral pattern analysis.'
        },
        {
            icon: '🛡️',
            title: 'Quantum-Grade Encryption',
            desc: 'Every data point is encrypted with AES-256-GCM and integrity-verified through SHA-3 hash chains.'
        },
        {
            icon: '🧠',
            title: 'Local AI Investigation',
            desc: 'Fully offline forensic report engine generates SOC-analyst grade intelligence — zero cloud dependency.'
        },
        {
            icon: '⚡',
            title: 'Real-Time Risk Scoring',
            desc: 'Continuous cumulative risk calculation across all employee sessions with sub-second alerting latency.'
        },
    ];

    return (
        <div className="min-h-screen bg-[#0b0d12] text-white flex flex-col overflow-hidden relative">
            {/* Animated background grid */}
            <div className="absolute inset-0 opacity-[0.03]" style={{
                backgroundImage: `linear-gradient(rgba(59,130,246,0.3) 1px, transparent 1px), linear-gradient(90deg, rgba(59,130,246,0.3) 1px, transparent 1px)`,
                backgroundSize: '60px 60px'
            }}></div>

            {/* Subtle radial glow */}
            <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[800px] h-[600px] bg-blue-600/10 rounded-full blur-[120px] pointer-events-none"></div>

            {/* Nav */}
            <nav className="relative z-10 flex items-center justify-between px-8 py-5">
                <div className="flex items-center space-x-3">
                    <div className="bg-blue-600 text-white font-black text-sm tracking-wider flex items-center justify-center w-9 h-9 rounded-lg shadow-lg shadow-blue-600/30">
                        ID
                    </div>
                    <span className="text-lg font-black tracking-wider">
                        InThreat<span className="text-blue-500">Detection</span>
                    </span>
                </div>
                <button
                    onClick={onEnter}
                    className="px-5 py-2 text-sm font-bold rounded-lg border border-[#2d3340] hover:border-blue-500 hover:bg-blue-600/10 transition-all duration-300"
                >
                    SOC Login →
                </button>
            </nav>

            {/* Hero */}
            <div className={`relative z-10 flex-1 flex flex-col items-center justify-center text-center px-6 transition-all duration-1000 ${isVisible ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-8'}`}>
                <div className="mb-6 inline-flex items-center space-x-2 px-4 py-1.5 rounded-full border border-blue-500/30 bg-blue-500/10 text-blue-400 text-xs font-bold tracking-widest uppercase">
                    <span className="w-2 h-2 rounded-full bg-blue-500 animate-pulse"></span>
                    <span>Threat Detection Platform</span>
                </div>

                <h1 className="text-5xl md:text-7xl font-black leading-tight max-w-4xl tracking-tight">
                    Detect Insider Threats<br />
                    <span className="bg-gradient-to-r from-blue-400 via-blue-500 to-cyan-400 bg-clip-text text-transparent">
                        Before They Strike
                    </span>
                </h1>

                <p className="mt-6 text-gray-400 text-lg md:text-xl max-w-2xl leading-relaxed">
                    Enterprise-grade User & Entity Behavior Analytics with quantum-resilient
                    cryptography and AI-powered forensic investigation — running entirely on your infrastructure.
                </p>

                <div className="mt-10 flex items-center space-x-4">
                    <button
                        onClick={onEnter}
                        className="px-8 py-3.5 rounded-xl bg-blue-600 hover:bg-blue-700 text-white font-bold text-base shadow-lg shadow-blue-600/30 hover:shadow-blue-600/50 transition-all duration-300 hover:scale-105 active:scale-95"
                    >
                        Access SOC Terminal
                    </button>
                    <a
                        href="https://github.com/sumit-73io/InThreatDetection"
                        target="_blank"
                        rel="noopener noreferrer"
                        className="px-6 py-3.5 rounded-xl border border-[#2d3340] hover:border-gray-500 text-gray-300 font-bold text-base transition-all duration-300"
                    >
                        View on GitHub
                    </a>
                </div>

                {/* Stats bar */}
                <div className={`mt-16 flex items-center divide-x divide-[#2d3340] transition-all duration-1000 delay-300 ${isVisible ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-8'}`}>
                    {[
                        { value: 'AES-256', label: 'Encryption' },
                        { value: 'SHA-3', label: 'Hash Chains' },
                        { value: '100%', label: 'Offline' },
                        { value: 'Real-time', label: 'Monitoring' },
                    ].map((stat, i) => (
                        <div key={i} className="px-8 text-center">
                            <div className="text-xl font-black text-blue-400">{stat.value}</div>
                            <div className="text-xs text-gray-500 mt-1 uppercase tracking-wider">{stat.label}</div>
                        </div>
                    ))}
                </div>
            </div>

            {/* Features Section */}
            <div className={`relative z-10 px-8 pb-16 transition-all duration-1000 delay-500 ${isVisible ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-12'}`}>
                <div className="max-w-5xl mx-auto grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                    {features.map((f, i) => (
                        <div
                            key={i}
                            className="bg-[#12141b] border border-[#1e222b] rounded-xl p-5 hover:border-blue-500/40 hover:bg-[#15171e] transition-all duration-300 group"
                        >
                            <div className="text-2xl mb-3 group-hover:scale-110 transition-transform duration-300">{f.icon}</div>
                            <h3 className="font-bold text-sm text-white mb-1.5">{f.title}</h3>
                            <p className="text-xs text-gray-500 leading-relaxed">{f.desc}</p>
                        </div>
                    ))}
                </div>
            </div>

            {/* Footer */}
            <footer className="relative z-10 border-t border-[#1e222b] px-8 py-4 text-center text-xs text-gray-600">
                © {new Date().getFullYear()} InThreatDetection — Insider Threat Detection & Investigation Platform
            </footer>
        </div>
    );
}
