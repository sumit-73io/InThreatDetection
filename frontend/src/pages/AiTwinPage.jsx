import React, { useEffect, useState, useCallback } from 'react';
import RadarChart from '../components/RadarChart';
import ThreatGauge from '../components/ThreatGauge';
import EmbeddingHeatmap from '../components/EmbeddingHeatmap';
import {
  getAiTwinProfiles, getAiTwinProfile, getAiTwinAlerts,
  initializeAiTwin, resetAiTwin, simulateAiTwinEvent, acknowledgeAiTwinAlert,
  trainNormalAiTwin, blockEmployee, unblockEmployee
} from '../services/api';

// ── Helpers ──────────────────────────────────────────────────────────────

const RADAR_DOMAINS = ['Identity', 'Keyboard', 'Mouse', 'Application', 'File', 'Network', 'Security'];
const DOMAIN_KEYS   = ['identity', 'keyboard', 'mouse', 'application', 'file', 'network', 'security'];

function statusBadge(profile) {
  const { status, is_trained, current_threat_score } = profile;
  if (status === 'ALERT' || current_threat_score >= 75)
    return { label: 'THREAT', cls: 'bg-red-500/20 text-red-400 border-red-500/40 animate-pulse', dot: 'bg-red-400' };
  if (status === 'TRAINED' || is_trained)
    return { label: 'ACTIVE', cls: 'bg-emerald-500/20 text-emerald-400 border-emerald-500/40', dot: 'bg-emerald-400' };
  if (status === 'TRAINING')
    return { label: 'TRAINING', cls: 'bg-blue-500/20 text-blue-400 border-blue-500/40', dot: 'bg-blue-400' };
  return { label: 'INIT', cls: 'bg-gray-500/20 text-gray-400 border-gray-500/40', dot: 'bg-gray-400' };
}

function threatColor(score) {
  if (score >= 75) return '#ef4444';
  if (score >= 55) return '#f97316';
  if (score >= 30) return '#f59e0b';
  return '#22c55e';
}

function timeAgo(dateStr) {
  if (!dateStr) return '—';
  const d = new Date(dateStr.endsWith('Z') ? dateStr : dateStr + 'Z');
  const diff = Math.floor((Date.now() - d) / 1000);
  if (diff < 60) return 'Just now';
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

function trainingProgress(profile) {
  const TRAINING_DAYS = 14;
  const MIN_EVENTS = 50;
  const eventProgress = Math.min(1, (profile.event_count || 0) / MIN_EVENTS);
  const dayProgress = Math.min(1, (profile.days_in_training || 0) / TRAINING_DAYS);
  return Math.min(1, (eventProgress + dayProgress) / 2);
}

function extractRadarValues(profile) {
  // Extract per-domain threat contribution from profile stats
  // We'll use mean values from each domain as a normalized representation
  const safe = (v, max) => Math.min(10, ((v || 0) / max) * 10);
  const safeStats = (stats, max) => {
    if (!stats) return 0;
    return safe(stats.mean || 0, max);
  };

  if (!profile) return Array(7).fill(0);

  return [
    // identity: off_hours_session_rate (0–1) → 0–10, inverted so 0=good
    Math.min(10, (profile.identity?.off_hours_session_rate || 0) * 20),
    // keyboard: wpm deviation proxy
    safeStats(profile.keyboard?.wpm, 120),
    // mouse: click frequency
    safeStats(profile.mouse?.click_frequency_per_min, 60),
    // application: switching rate
    safeStats(profile.application?.switching_rate_per_hour, 30),
    // file: downloads per session
    safeStats(profile.file?.downloads_per_session, 10),
    // network: bandwidth
    safeStats(profile.network?.bandwidth_mb_per_hour, 500),
    // security: failed logins
    Math.min(10, (profile.security?.total_failed_logins || 0) * 2),
  ];
}

// Default baseline values for display during training (represents normal for a bank)
const DEFAULT_BASELINE = [0.5, 5.5, 3.0, 4.0, 1.0, 1.5, 0.2];

// ── Simulation Presets ────────────────────────────────────────────────────
const THREAT_SCENARIOS = [
  {
    name: 'After-Hours Mass Download',
    description: 'Employee logs in at 2:15 AM, downloads 800 confidential files',
    payload: {
      action: 'DOWNLOAD_CONFIDENTIAL',
      is_confidential: true,
      download_size_mb: 2400,
      is_bulk_operation: true,
      file_count: 847,
      session_duration_s: 1200,
    },
  },
  {
    name: 'USB Exfiltration',
    description: 'Unexpected USB device connected with high-volume file transfer',
    payload: {
      action: 'USB_CONNECTED',
      usb_connected: true,
      upload_size_mb: 3200,
      is_bulk_operation: true,
      bandwidth_mb: 800,
    },
  },
  {
    name: 'PowerShell + Privilege Escalation',
    description: 'Employee opens PowerShell (never used before) and escalates privileges',
    payload: {
      action: 'CHANGE_PERMISSION',
      app_name: 'powershell',
      is_privilege_escalation: true,
      is_admin_command: true,
    },
  },
  {
    name: 'Cloud Exfiltration',
    description: 'Massive cloud upload to external storage — never done before',
    payload: {
      action: 'DOWNLOAD_FILE',
      is_cloud_upload: true,
      is_external_connection: true,
      bandwidth_mb: 1500,
      upload_size_mb: 1200,
    },
  },
  {
    name: 'Multiple Failed Logins',
    description: 'Repeated failed login attempts outside business hours',
    payload: {
      action: 'FAILED_LOGIN',
      is_failed_login: true,
      session_duration_s: 30,
    },
  },
];

// ── Main Component ────────────────────────────────────────────────────────

export default function AiTwinPage({ isDark = true }) {
  const [profiles, setProfiles] = useState([]);
  const [selectedProfile, setSelectedProfile] = useState(null);
  const [fullProfile, setFullProfile] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [alertsLoading, setAlertsLoading] = useState(false);
  const [activeTab, setActiveTab] = useState('overview'); // overview | detail | alerts | simulate
  const [simResult, setSimResult] = useState(null);
  const [simLoading, setSimLoading] = useState(false);
  const [simEmployeeId, setSimEmployeeId] = useState('');
  const [selectedScenario, setSelectedScenario] = useState(0);
  const [confirmReset, setConfirmReset] = useState(null);
  const [systemStatus, setSystemStatus] = useState(null);

  // Train Normal State
  const [trainConfig, setTrainConfig] = useState({
    num_events: 50,
    base_wpm: 70,
    base_mouse_speed: 350,
    working_hours_start: 9,
    working_hours_end: 17
  });
  const [trainLoading, setTrainLoading] = useState(false);
  const [trainResult, setTrainResult] = useState(null);
  
  const [blockLoading, setBlockLoading] = useState(false);

  const fetchProfiles = useCallback(async () => {
    try {
      const data = await getAiTwinProfiles();
      const list = data.profiles || [];
      setProfiles(list);
      if (list.length > 0 && !selectedProfile) {
        setSelectedProfile(list[0]);
        setSimEmployeeId(list[0].employee_id);
      }
    } catch (err) {
      console.error('AI Twin profiles fetch error:', err);
    } finally {
      setLoading(false);
    }
  }, []);

  const fetchAlerts = useCallback(async () => {
    setAlertsLoading(true);
    try {
      const data = await getAiTwinAlerts();
      setAlerts(data.alerts || []);
    } catch (err) {
      console.error('AI Twin alerts fetch error:', err);
    } finally {
      setAlertsLoading(false);
    }
  }, []);

  const fetchFullProfile = useCallback(async (employeeId) => {
    try {
      const data = await getAiTwinProfile(employeeId);
      setFullProfile(data.profile || null);
    } catch (err) {
      console.error('Full profile fetch error:', err);
    }
  }, []);

  useEffect(() => {
    fetchProfiles();
    fetchAlerts();
    const interval = setInterval(() => {
      fetchProfiles();
      fetchAlerts();
    }, 15000);
    return () => clearInterval(interval);
  }, [fetchProfiles, fetchAlerts]);

  useEffect(() => {
    if (selectedProfile) {
      fetchFullProfile(selectedProfile.employee_id);
      setSimEmployeeId(selectedProfile.employee_id);
    }
  }, [selectedProfile, fetchFullProfile]);

  const handleSelectProfile = (profile) => {
    setSelectedProfile(profile);
    setActiveTab('detail');
    setSimResult(null);
  };

  const handleSimulate = async () => {
    if (!simEmployeeId) return;
    setSimLoading(true);
    setSimResult(null);
    try {
      const scenario = THREAT_SCENARIOS[selectedScenario];
      const payload = {
        employee_id: simEmployeeId,
        action: scenario.payload.action,
        ...scenario.payload,
      };
      const result = await simulateAiTwinEvent(payload);
      setSimResult(result);
      // NOTE: Do NOT refresh profiles here — the simulate endpoint is read-only
      // and never modifies the AI Twin model, so there is nothing to refresh.
    } catch (err) {
      setSimResult({ error: err?.response?.data?.detail || 'Simulation failed' });
    } finally {
      setSimLoading(false);
    }
  };

  const handleTrainNormal = async () => {
    if (!simEmployeeId) return;
    setTrainLoading(true);
    setTrainResult(null);
    try {
      const payload = {
        employee_id: simEmployeeId,
        num_events: trainConfig.num_events,
        base_wpm: trainConfig.base_wpm,
        base_mouse_speed: trainConfig.base_mouse_speed,
        working_hours_start: trainConfig.working_hours_start,
        working_hours_end: trainConfig.working_hours_end
      };
      const result = await trainNormalAiTwin(payload);
      setTrainResult(result);
      setTimeout(() => {
        fetchProfiles();
        // Switch to detail view so user can see the trained twin
        setActiveTab('detail');
      }, 1500);
    } catch (err) {
      setTrainResult({ error: err?.response?.data?.detail || 'Training failed' });
    } finally {
      setTrainLoading(false);
    }
  };

  const handleReset = async (employeeId) => {
    try {
      await resetAiTwin(employeeId);
      setConfirmReset(null);
      fetchProfiles();
    } catch (err) {
      console.error('Reset error:', err);
    }
  };

  const handleToggleBlock = async (employeeId, isCurrentlyBlocked) => {
    try {
      setBlockLoading(true);
      if (isCurrentlyBlocked) {
        await unblockEmployee(employeeId);
      } else {
        await blockEmployee(employeeId);
      }
      // Re-fetch full profile and summaries to immediately reflect the state
      await fetchProfiles();
      if (selectedProfile && selectedProfile.employee_id === employeeId) {
        await fetchFullProfile(employeeId);
      }
    } catch (err) {
      console.error('Block/Unblock error:', err);
    } finally {
      setBlockLoading(false);
    }
  };

  const openAlerts = alerts.filter(a => a.status === 'OPEN');
  const trainedCount = profiles.filter(p => p.is_trained).length;
  const trainingCount = profiles.filter(p => !p.is_trained).length;
  const alertCount = profiles.filter(p => p.status === 'ALERT' || p.current_threat_score >= 75).length;

  // Radar data
  const baselineValues = fullProfile ? extractRadarValues(fullProfile) : DEFAULT_BASELINE;
  const currentValues = selectedProfile
    ? DOMAIN_KEYS.map((_, i) => {
        const score = selectedProfile.current_threat_score || 0;
        // Simulate a deviation in the direction of the threat score
        return Math.min(10, baselineValues[i] + (score / 100) * Math.random() * 4);
      })
    : DEFAULT_BASELINE;

  const embeddingVec = fullProfile?.embedding_vector || [];

  return (
    <div className="flex flex-col h-full" style={{ fontFamily: 'Inter, system-ui, sans-serif' }}>

      {/* ── Header ─────────────────────────────────────────────────────── */}
      <div className="flex-none px-6 pt-6 pb-4 border-b border-white/5">
        <div className="flex items-start justify-between">
          <div>
            <div className="flex items-center gap-3 mb-1">
              <div className="w-10 h-10 rounded-xl flex items-center justify-center text-2xl"
                style={{ background: 'linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%)', boxShadow: '0 0 20px rgba(99,102,241,0.4)' }}>
                
              </div>
              <div>
                <h1 className="text-xl font-bold text-white tracking-tight">AI Twin Engine</h1>
                <p className="text-xs text-gray-400 mt-0.5">Personalized Behavioural Clone · Self-Comparison Threat Detection</p>
              </div>
            </div>
          </div>
          {/* Status pills */}
          <div className="flex gap-3">
            {[
              { label: 'TRAINED', count: trainedCount, color: '#22c55e', bg: 'rgba(34,197,94,0.1)' },
              { label: 'TRAINING', count: trainingCount, color: '#60a5fa', bg: 'rgba(96,165,250,0.1)' },
              { label: 'THREAT', count: alertCount, color: '#ef4444', bg: 'rgba(239,68,68,0.1)' },
              { label: 'ALERTS', count: openAlerts.length, color: '#f59e0b', bg: 'rgba(245,158,11,0.1)' },
            ].map(({ label, count, color, bg }) => (
              <div key={label} className="flex flex-col items-center px-3 py-2 rounded-lg"
                style={{ background: bg, border: `1px solid ${color}25` }}>
                <span className="text-xl font-bold" style={{ color }}>{count}</span>
                <span className="text-xs font-medium" style={{ color, opacity: 0.7 }}>{label}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Tabs */}
        <div className="flex gap-1 mt-4">
          {[
            { id: 'overview', label: 'Profiles' },
            { id: 'detail', label: 'Twin Detail' },
            { id: 'alerts', label: `Alerts (${openAlerts.length})` },
            { id: 'simulate', label: 'Test Detection' },
            { id: 'train', label: 'Train Twin' },
          ].map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className="px-4 py-1.5 rounded-lg text-xs font-semibold transition-all duration-200"
              style={{
                background: activeTab === tab.id ? 'rgba(99,102,241,0.25)' : 'transparent',
                color: activeTab === tab.id ? '#818cf8' : 'rgba(150,160,180,0.7)',
                border: activeTab === tab.id ? '1px solid rgba(99,102,241,0.4)' : '1px solid transparent',
              }}
            >
              {tab.label}
            </button>
          ))}
        </div>
      </div>

      {/* ── Body ───────────────────────────────────────────────────────── */}
      <div className="flex-1 overflow-y-auto p-6">

        {/* ══ OVERVIEW TAB ══ */}
        {activeTab === 'overview' && (
          <div>
            {loading ? (
              <div className="flex items-center justify-center h-40 gap-3 text-gray-500">
                <div className="w-5 h-5 border-2 border-indigo-400 border-t-transparent rounded-full animate-spin" />
                Loading AI Twin profiles...
              </div>
            ) : profiles.length === 0 ? (
              <div className="text-center py-20">
                <div className="text-5xl mb-4"></div>
                <div className="text-gray-400 text-sm">No AI Twin profiles found.</div>
                <div className="text-gray-500 text-xs mt-1">Provision employees to start AI Twin training.</div>
              </div>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
                {profiles.map(profile => {
                  const badge = statusBadge(profile);
                  const prog = trainingProgress(profile);
                  const tColor = threatColor(profile.current_threat_score || 0);
                  const isSelected = selectedProfile?.employee_id === profile.employee_id;
                  return (
                    <div
                      key={profile.employee_id}
                      onClick={() => handleSelectProfile(profile)}
                      className="relative rounded-xl p-4 cursor-pointer transition-all duration-300"
                      style={{
                        background: isSelected
                          ? 'linear-gradient(135deg, rgba(99,102,241,0.15) 0%, rgba(139,92,246,0.1) 100%)'
                          : 'rgba(255,255,255,0.03)',
                        border: isSelected ? '1px solid rgba(99,102,241,0.5)' : '1px solid rgba(255,255,255,0.06)',
                        boxShadow: isSelected ? '0 0 20px rgba(99,102,241,0.15)' : 'none',
                      }}
                    >
                      {/* Status badge */}
                      <div className="flex items-center justify-between mb-3">
                        <div className={`flex items-center gap-1.5 px-2 py-0.5 rounded-full border text-xs font-bold ${badge.cls}`}>
                          <div className={`w-1.5 h-1.5 rounded-full ${badge.dot}`} />
                          {badge.label}
                        </div>
                        <div className="text-right">
                          <div className="text-lg font-black" style={{ color: tColor }}>
                            {(profile.current_threat_score || 0).toFixed(0)}
                          </div>
                          <div className="text-xs text-gray-500">score</div>
                        </div>
                      </div>

                      {/* Employee info */}
                      <div className="mb-3">
                        <div className="text-sm font-bold text-white truncate">{profile.employee_name || profile.employee_id}</div>
                        <div className="text-xs text-gray-400">{profile.role}</div>
                        <div className="text-xs text-gray-500 mt-0.5">ID: {profile.employee_id}</div>
                      </div>

                      {/* Training progress */}
                      {!profile.is_trained && (
                        <div className="mb-2">
                          <div className="flex justify-between text-xs text-gray-500 mb-1">
                            <span>Training</span>
                            <span>{(prog * 100).toFixed(0)}%</span>
                          </div>
                          <div className="h-1 rounded-full bg-white/5">
                            <div
                              className="h-full rounded-full transition-all duration-700"
                              style={{ width: `${prog * 100}%`, background: 'linear-gradient(90deg, #6366f1, #8b5cf6)' }}
                            />
                          </div>
                        </div>
                      )}

                      {/* Stats row */}
                      <div className="grid grid-cols-3 gap-1 mt-2">
                        {[
                          { label: 'Events', value: profile.event_count || 0 },
                          { label: 'Days', value: profile.days_in_training || 0 },
                          { label: 'Trend', value: profile.threat_trend === 'rising' ? '↑' : profile.threat_trend === 'falling' ? '↓' : '→' },
                        ].map(({ label, value }) => (
                          <div key={label} className="text-center rounded-lg py-1" style={{ background: 'rgba(255,255,255,0.03)' }}>
                            <div className="text-xs font-bold text-white">{value}</div>
                            <div className="text-xs text-gray-500">{label}</div>
                          </div>
                        ))}
                      </div>

                      {/* Threat score mini bar */}
                      <div className="mt-3 h-0.5 rounded-full bg-white/5">
                        <div
                          className="h-full rounded-full transition-all duration-700"
                          style={{ width: `${Math.min(100, profile.current_threat_score || 0)}%`, backgroundColor: tColor }}
                        />
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        )}

        {/* ══ DETAIL TAB ══ */}
        {activeTab === 'detail' && (
          <div>
            {!selectedProfile ? (
              <div className="text-center py-16 text-gray-500">
                <div className="text-4xl mb-3"></div>
                Select a profile from the Overview tab to view details.
              </div>
            ) : (
              <div className="space-y-6">
                {/* Employee header */}
                <div className="flex items-center justify-between rounded-xl p-4"
                  style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.06)' }}>
                  <div className="flex items-center gap-4">
                    <div className="w-12 h-12 rounded-full flex items-center justify-center text-xl font-black text-white"
                      style={{ background: 'linear-gradient(135deg, #6366f1, #8b5cf6)' }}>
                      {(selectedProfile.employee_name || selectedProfile.employee_id).charAt(0)}
                    </div>
                    <div>
                      <div className="flex items-center gap-2">
                        <div className="text-lg font-bold text-white">{selectedProfile.employee_name}</div>
                        {selectedProfile.is_blocked && (
                          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-red-500/20 text-red-400 border border-red-500/30">
                            BLOCKED
                          </span>
                        )}
                      </div>
                      <div className="text-sm text-gray-400">{selectedProfile.role} · {selectedProfile.employee_id}</div>
                      <div className="text-xs text-gray-500 mt-0.5">
                        {selectedProfile.is_trained
                          ? `Trained on ${selectedProfile.event_count} events`
                          : `Training: ${selectedProfile.event_count} / 50 events · Day ${selectedProfile.days_in_training} / 14`}
                      </div>
                    </div>
                  </div>
                  <div className="flex gap-2">
                    <button
                      onClick={() => handleToggleBlock(selectedProfile.employee_id, selectedProfile.is_blocked)}
                      disabled={blockLoading}
                      className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-colors disabled:opacity-50 ${
                        selectedProfile.is_blocked 
                          ? 'text-gray-400 border border-gray-500/30 hover:bg-gray-500/10' 
                          : 'text-red-400 border border-red-500/30 hover:bg-red-500/10'
                      }`}
                    >
                      {blockLoading ? 'Updating...' : selectedProfile.is_blocked ? 'Unblock Account' : 'Block (24h)'}
                    </button>
                    <button
                      onClick={() => setConfirmReset(selectedProfile.employee_id)}
                      className="px-3 py-1.5 rounded-lg text-xs font-semibold text-orange-400 border border-orange-500/30 hover:bg-orange-500/10 transition-colors"
                    >
                      Reset Twin
                    </button>
                    <button
                      onClick={() => { setSimEmployeeId(selectedProfile.employee_id); setActiveTab('simulate'); }}
                      className="px-3 py-1.5 rounded-lg text-xs font-semibold text-indigo-400 border border-indigo-500/30 hover:bg-indigo-500/10 transition-colors"
                    >
                      Simulate Attack
                    </button>
                  </div>
                </div>

                {/* Main content grid */}
                <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">

                  {/* Left: Radar + Gauge */}
                  <div className="lg:col-span-1 space-y-4">
                    {/* Threat Gauge */}
                    <div className="rounded-xl p-5 flex flex-col items-center"
                      style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.06)' }}>
                      <ThreatGauge
                        score={Math.round(selectedProfile.current_threat_score || 0)}
                        size={180}
                        label="Twin Threat Score"
                      />
                      <div className="flex gap-4 mt-3 text-center">
                        <div>
                          <div className="text-xs text-gray-500">Trend</div>
                          <div className={`text-sm font-bold ${selectedProfile.threat_trend === 'rising' ? 'text-red-400' : selectedProfile.threat_trend === 'falling' ? 'text-emerald-400' : 'text-gray-400'}`}>
                            {selectedProfile.threat_trend === 'rising' ? '↑ Rising' : selectedProfile.threat_trend === 'falling' ? '↓ Falling' : '→ Stable'}
                          </div>
                        </div>
                        <div>
                          <div className="text-xs text-gray-500">Status</div>
                          <div className={`text-sm font-bold ${selectedProfile.is_trained ? 'text-emerald-400' : 'text-blue-400'}`}>
                            {selectedProfile.is_trained ? 'Monitoring' : 'Training'}
                          </div>
                        </div>
                      </div>
                    </div>

                    {/* Radar Chart */}
                    <div className="rounded-xl p-5 flex flex-col items-center"
                      style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.06)' }}>
                      <h3 className="text-xs font-bold text-gray-400 uppercase tracking-widest mb-3 self-start">
                        Behavioural Radar
                      </h3>
                      <RadarChart
                        domains={RADAR_DOMAINS}
                        baseline={DEFAULT_BASELINE}
                        current={baselineValues}
                        size={240}
                      />
                      <div className="flex gap-4 mt-3 text-xs">
                        <div className="flex items-center gap-1.5">
                          <div className="w-6 h-0.5 rounded" style={{ background: 'rgba(59,130,246,0.6)', borderStyle: 'dashed' }} />
                          <span className="text-gray-500">Baseline</span>
                        </div>
                        <div className="flex items-center gap-1.5">
                          <div className="w-6 h-0.5 rounded" style={{ background: 'rgba(239,68,68,0.85)' }} />
                          <span className="text-gray-500">Current</span>
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Right: Stats + Embedding */}
                  <div className="lg:col-span-2 space-y-4">

                    {/* Training timeline */}
                    {!selectedProfile.is_trained && (
                      <div className="rounded-xl p-4"
                        style={{ background: 'rgba(99,102,241,0.05)', border: '1px solid rgba(99,102,241,0.2)' }}>
                        <div className="flex items-center gap-2 mb-3">
                          <span className="text-indigo-400 text-sm"></span>
                          <h3 className="text-xs font-bold text-indigo-400 uppercase tracking-widest">Training Progress</h3>
                        </div>
                        <div className="grid grid-cols-2 gap-4 mb-3">
                          {[
                            { label: 'Events Collected', current: selectedProfile.event_count || 0, target: 50 },
                            { label: 'Calendar Days', current: selectedProfile.days_in_training || 0, target: 14 },
                          ].map(({ label, current, target }) => (
                            <div key={label}>
                              <div className="flex justify-between text-xs text-gray-400 mb-1">
                                <span>{label}</span>
                                <span className="font-bold text-indigo-400">{current} / {target}</span>
                              </div>
                              <div className="h-2 rounded-full bg-white/5">
                                <div
                                  className="h-full rounded-full transition-all duration-1000"
                                  style={{
                                    width: `${Math.min(100, (current / target) * 100)}%`,
                                    background: 'linear-gradient(90deg, #6366f1, #8b5cf6)',
                                    boxShadow: '0 0 8px rgba(99,102,241,0.5)',
                                  }}
                                />
                              </div>
                            </div>
                          ))}
                        </div>
                        <div className="text-xs text-indigo-300/70 bg-indigo-500/10 rounded-lg px-3 py-2">
                          ℹ️ No threat alerts are generated during training. The AI Twin is learning your employee's normal behaviour patterns.
                        </div>
                      </div>
                    )}

                    {/* Domain Stats Grid */}
                    <div className="rounded-xl p-4"
                      style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.06)' }}>
                      <h3 className="text-xs font-bold text-gray-400 uppercase tracking-widest mb-3">Behavioural Domains</h3>
                      <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
                        {[
                          {
                            domain: 'Identity', icon: '', color: '#818cf8',
                            stats: fullProfile ? [
                              `Sessions: ${fullProfile.identity?.total_sessions || 0}`,
                              `VPN Rate: ${((fullProfile.identity?.vpn_usage_rate || 0) * 100).toFixed(0)}%`,
                              `Off-Hours: ${((fullProfile.identity?.off_hours_session_rate || 0) * 100).toFixed(0)}%`,
                            ] : ['Loading...'],
                          },
                          {
                            domain: 'Keyboard', icon: '⌨️', color: '#34d399',
                            stats: fullProfile?.keyboard?.wpm?.count > 0 ? [
                              `WPM: ${(fullProfile.keyboard.wpm.mean || 0).toFixed(0)} ± ${(fullProfile.keyboard.wpm.std || 0).toFixed(0)}`,
                              `Latency: ${(fullProfile.keyboard.keystroke_latency_ms?.mean || 0).toFixed(0)}ms`,
                              `Backspace: ${((fullProfile.keyboard.backspace_rate?.mean || 0) * 100).toFixed(1)}%`,
                            ] : ['Not enough data'],
                          },
                          {
                            domain: 'Mouse', icon: '', color: '#60a5fa',
                            stats: fullProfile?.mouse?.movement_speed_px_s?.count > 0 ? [
                              `Speed: ${(fullProfile.mouse.movement_speed_px_s.mean || 0).toFixed(0)} px/s`,
                              `Clicks: ${(fullProfile.mouse.click_frequency_per_min?.mean || 0).toFixed(0)}/min`,
                              `Idle: ${((fullProfile.mouse.idle_ratio?.mean || 0) * 100).toFixed(0)}%`,
                            ] : ['Not enough data'],
                          },
                          {
                            domain: 'Applications', icon: '', color: '#f59e0b',
                            stats: fullProfile?.application?.top_apps?.length > 0 ? [
                              `Top: ${(fullProfile.application.top_apps || []).slice(0, 2).join(', ')}`,
                              `Sessions: ${fullProfile.application.total_app_sessions || 0}`,
                              `Clipboard: ${(fullProfile.application.clipboard_ops_per_hour?.mean || 0).toFixed(0)}/hr`,
                            ] : ['Not enough data'],
                          },
                          {
                            domain: 'File Activity', icon: '', color: '#f97316',
                            stats: fullProfile ? [
                              `Downloads: ${(fullProfile.file?.downloads_per_session?.mean || 0).toFixed(1)}/session`,
                              `USB Events: ${(fullProfile.file?.usb_events_per_week?.mean || 0).toFixed(1)}/wk`,
                              `Bulk Ops: ${fullProfile.file?.bulk_download_events || 0}`,
                            ] : ['Loading...'],
                          },
                          {
                            domain: 'Security', icon: '', color: '#f43f5e',
                            stats: fullProfile ? [
                              `Failed Logins: ${fullProfile.security?.total_failed_logins || 0}`,
                              `MFA: ${((fullProfile.security?.mfa_compliance_rate || 1) * 100).toFixed(0)}%`,
                              `Priv Events: ${(fullProfile.security?.privilege_events_per_week?.mean || 0).toFixed(1)}/wk`,
                            ] : ['Loading...'],
                          },
                        ].map(({ domain, icon, color, stats }) => (
                          <div key={domain} className="rounded-lg p-3"
                            style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.05)' }}>
                            <div className="flex items-center gap-1.5 mb-2">
                              <span className="text-sm">{icon}</span>
                              <span className="text-xs font-bold" style={{ color }}>{domain}</span>
                            </div>
                            {stats.map((s, i) => (
                              <div key={i} className="text-xs text-gray-400 leading-5">{s}</div>
                            ))}
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* Embedding Vector Heatmap */}
                    {embeddingVec.length === 64 && (
                      <div className="rounded-xl p-4"
                        style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.06)' }}>
                        <h3 className="text-xs font-bold text-gray-400 uppercase tracking-widest mb-3">
                          64-Dim Behavioural Embedding Vector
                        </h3>
                        <p className="text-xs text-gray-500 mb-3">
                          The AI Twin's compressed numerical fingerprint of this employee's behaviour. Each cell represents one learned feature.
                        </p>
                        <div className="overflow-x-auto">
                          <EmbeddingHeatmap
                            baseline={embeddingVec}
                            current={[]}
                            cellSize={14}
                            embeddingDrift={0}
                          />
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            )}
          </div>
        )}

        {/* ══ ALERTS TAB ══ */}
        {activeTab === 'alerts' && (
          <div>
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-sm font-bold text-white">AI Twin Deviation Alerts</h2>
              <button
                onClick={fetchAlerts}
                className="px-3 py-1.5 text-xs font-semibold rounded-lg text-indigo-400 border border-indigo-500/30 hover:bg-indigo-500/10 transition-colors"
              >
                Refresh
              </button>
            </div>
            {alertsLoading ? (
              <div className="text-center py-10 text-gray-500">Loading alerts...</div>
            ) : alerts.length === 0 ? (
              <div className="text-center py-16">
                <div className="text-4xl mb-3"></div>
                <div className="text-gray-400 text-sm">No AI Twin alerts. All employees behaving normally.</div>
              </div>
            ) : (
              <div className="space-y-3">
                {alerts.map((alert, idx) => {
                  const score = alert.threat_score || 0;
                  const color = threatColor(score);
                  const isOpen = alert.status === 'OPEN';
                  return (
                    <div key={alert._id || idx} className="rounded-xl p-4 transition-all duration-200"
                      style={{
                        background: 'rgba(255,255,255,0.03)',
                        border: `1px solid ${isOpen ? color + '30' : 'rgba(255,255,255,0.06)'}`,
                        boxShadow: isOpen && score >= 75 ? `0 0 15px ${color}20` : 'none',
                      }}>
                      <div className="flex items-start justify-between gap-4">
                        <div className="flex-1">
                          {/* Header row */}
                          <div className="flex items-center gap-3 mb-2">
                            <div className="flex items-center gap-1.5 px-2 py-0.5 rounded-full border text-xs font-bold"
                              style={{ color, background: color + '15', borderColor: color + '40' }}>
                              {alert.severity === 'Critical' ? '' : alert.severity === 'High' ? '' : ''} {alert.severity}
                            </div>
                            <span className="text-sm font-bold text-white">{alert.employee_name}</span>
                            <span className="text-xs text-gray-500">{alert.role}</span>
                            <span className="text-xs text-gray-600">·</span>
                            <span className="text-xs text-gray-500">{timeAgo(alert.timestamp)}</span>
                          </div>
                          {/* Description */}
                          <p className="text-xs text-gray-400 leading-5 mb-2">{alert.description}</p>
                          {/* Flagged domains */}
                          {alert.flagged_domains?.length > 0 && (
                            <div className="flex flex-wrap gap-1.5">
                              {alert.flagged_domains.map(d => (
                                <span key={d} className="px-2 py-0.5 rounded-full text-xs font-medium"
                                  style={{ background: 'rgba(99,102,241,0.15)', color: '#818cf8', border: '1px solid rgba(99,102,241,0.3)' }}>
                                  {d}
                                </span>
                              ))}
                            </div>
                          )}
                          {/* Feature deviations (top 3) */}
                          {alert.feature_deviations?.length > 0 && (
                            <div className="mt-2 grid grid-cols-2 md:grid-cols-3 gap-2">
                              {alert.feature_deviations.slice(0, 6).map((fd, fi) => (
                                <div key={fi} className="rounded-lg px-2 py-1.5"
                                  style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.05)' }}>
                                  <div className="text-xs font-bold text-gray-300 truncate">{fd.feature_name}</div>
                                  <div className="text-xs text-gray-500">
                                    σ = <span className={fd.severity === 'critical' ? 'text-red-400' : fd.severity === 'high' ? 'text-orange-400' : 'text-yellow-400'}>
                                      {fd.z_score?.toFixed(1)}
                                    </span>
                                    {' · '}obs: {fd.observed_value?.toFixed(2)}
                                  </div>
                                </div>
                              ))}
                            </div>
                          )}
                        </div>
                        {/* Score + actions */}
                        <div className="flex flex-col items-center gap-2 flex-none">
                          <div className="text-2xl font-black" style={{ color }}>{score.toFixed(0)}</div>
                          <div className="text-xs text-gray-500">score</div>
                          {alert.embedding_drift > 0 && (
                            <div className="text-xs text-center">
                              <div className="text-gray-500">emb drift</div>
                              <div className="font-bold" style={{ color: alert.embedding_drift > 0.35 ? '#ef4444' : '#6b7280' }}>
                                {alert.embedding_drift.toFixed(3)}
                              </div>
                            </div>
                          )}
                          <div className="flex items-center gap-1">
                            <div className={`w-2 h-2 rounded-full ${isOpen ? 'bg-red-400' : 'bg-gray-500'}`} />
                            <span className="text-xs text-gray-500">{alert.status}</span>
                          </div>
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        )}

        {/* ══ SIMULATE TAB ══ */}
        {activeTab === 'simulate' && (
          <div className="max-w-3xl mx-auto space-y-5">

            {/* ── Architecture Explainer ────────────────────────────── */}
            <div className="rounded-xl overflow-hidden" style={{ border: '1px solid rgba(99,102,241,0.25)' }}>
              <div className="px-4 py-3" style={{ background: 'rgba(99,102,241,0.12)' }}>
                <div className="flex items-center gap-2">
                  <span className="text-indigo-400 text-base"></span>
                  <h3 className="text-sm font-bold text-indigo-300">How AI Twin Training Works</h3>
                </div>
              </div>
              <div className="p-4">
                <div className="grid grid-cols-2 gap-4">
                  {/* Training path */}
                  <div className="rounded-xl p-4" style={{ background: 'rgba(34,197,94,0.06)', border: '1px solid rgba(34,197,94,0.25)' }}>
                    <div className="flex items-center gap-2 mb-3">
                      <div className="w-7 h-7 rounded-lg flex items-center justify-center text-sm"
                        style={{ background: 'rgba(34,197,94,0.2)' }}></div>
                      <span className="text-xs font-bold text-emerald-400 uppercase tracking-wider">Employee Simulator</span>
                    </div>
                    <div className="space-y-1.5">
                      {[
                        'Login / Logout',
                        'View records, use Excel',
                        'Download files (normal)',
                        'Regular typing/mouse',
                        'Standard app usage',
                      ].map(item => (
                        <div key={item} className="flex items-center gap-2 text-xs text-gray-400">
                          <div className="w-1.5 h-1.5 rounded-full bg-emerald-400 flex-none" />
                          {item}
                        </div>
                      ))}
                    </div>
                    <div className="mt-3 rounded-lg p-2 text-center" style={{ background: 'rgba(34,197,94,0.1)' }}>
                      <div className="text-xs font-bold text-emerald-400">→ AI Twin LEARNS</div>
                      <div className="text-xs text-emerald-400/60 mt-0.5">Welford + EMA update</div>
                    </div>
                  </div>

                  {/* Detection path */}
                  <div className="rounded-xl p-4" style={{ background: 'rgba(239,68,68,0.06)', border: '1px solid rgba(239,68,68,0.25)' }}>
                    <div className="flex items-center gap-2 mb-3">
                      <div className="w-7 h-7 rounded-lg flex items-center justify-center text-sm"
                        style={{ background: 'rgba(239,68,68,0.2)' }}></div>
                      <span className="text-xs font-bold text-red-400 uppercase tracking-wider">Threat Simulator</span>
                    </div>
                    <div className="space-y-1.5">
                      {[
                        'Mass after-hours download',
                        'USB exfiltration',
                        'PowerShell escalation',
                        'Cloud exfiltration',
                        'Credential attacks',
                      ].map(item => (
                        <div key={item} className="flex items-center gap-2 text-xs text-gray-400">
                          <div className="w-1.5 h-1.5 rounded-full bg-red-400 flex-none" />
                          {item}
                        </div>
                      ))}
                    </div>
                    <div className="mt-3 rounded-lg p-2 text-center" style={{ background: 'rgba(239,68,68,0.1)' }}>
                      <div className="text-xs font-bold text-red-400">→ AI Twin SCORES ONLY</div>
                      <div className="text-xs text-red-400/60 mt-0.5">Profile never modified</div>
                    </div>
                  </div>
                </div>

                {/* Flow arrow */}
                <div className="mt-4 flex items-center gap-2 rounded-lg p-3"
                  style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.06)' }}>
                  <span className="text-indigo-400">ℹ️</span>
                  <p className="text-xs text-gray-400 leading-5">
                    The AI Twin is trained <strong className="text-white">exclusively</strong> from genuine activities in the{' '}
                    <span className="text-emerald-400 font-bold">Employee Simulator</span>.
                    Threat Simulator events are <strong className="text-white">never learned</strong> — they are scored against the trained baseline
                    and immediately discarded. This prevents baseline poisoning.
                  </p>
                </div>
              </div>
            </div>

            {/* ── Employee Selector ─────────────────────────────────── */}
            <div className="rounded-xl p-4" style={{ background: isDark ? 'rgba(255,255,255,0.03)' : 'rgba(0,0,0,0.02)', border: isDark ? '1px solid rgba(255,255,255,0.06)' : '1px solid rgba(0,0,0,0.1)' }}>
              <label className="block text-xs font-bold text-gray-400 uppercase tracking-widest mb-2">
                Target Employee
              </label>
              <select
                value={simEmployeeId}
                onChange={e => setSimEmployeeId(e.target.value)}
                className={`w-full rounded-lg px-3 py-2 text-sm ${isDark ? 'text-white' : 'text-slate-800'}`}
                style={{ background: isDark ? 'rgba(255,255,255,0.05)' : 'rgba(0,0,0,0.05)', border: isDark ? '1px solid rgba(255,255,255,0.1)' : '1px solid rgba(0,0,0,0.1)' }}
              >
                <option value="">Select employee...</option>
                {profiles.map(p => (
                  <option key={p.employee_id} value={p.employee_id}>
                    {p.employee_name} ({p.employee_id}) — {p.is_trained ? 'Trained — ready to test' : `Training (${p.event_count || 0} events)`}
                  </option>
                ))}
              </select>

              {/* Training status warning for selected employee */}
              {simEmployeeId && (() => {
                const sel = profiles.find(p => p.employee_id === simEmployeeId);
                if (!sel) return null;
                if (sel.is_trained) {
                  return (
                    <div className="mt-2 flex items-center gap-2 text-xs text-emerald-400"
                      style={{ background: 'rgba(34,197,94,0.08)', border: '1px solid rgba(34,197,94,0.2)', borderRadius: 8, padding: '8px 12px' }}>
                      <span></span>
                      <span>Twin is trained on <strong>{sel.event_count}</strong> Employee Simulator events. Detection test ready.</span>
                    </div>
                  );
                }
                const eventsLeft = Math.max(0, 50 - (sel.event_count || 0));
                const daysLeft = Math.max(0, 14 - (sel.days_in_training || 0));
                return (
                  <div className="mt-2 rounded-lg p-3" style={{ background: 'rgba(245,158,11,0.08)', border: '1px solid rgba(245,158,11,0.25)' }}>
                    <div className="flex items-center gap-2 mb-2">
                      <span className="text-amber-400"></span>
                      <span className="text-xs font-bold text-amber-400">Twin is still in training — cannot score threats yet</span>
                    </div>
                    <p className="text-xs text-amber-300/70 leading-5 mb-2">
                      This employee's AI Twin has only seen <strong className="text-amber-300">{sel.event_count} events</strong>.
                      It needs at least <strong className="text-amber-300">{eventsLeft} more events</strong> from the{' '}
                      <strong className={isDark ? 'text-white' : 'text-slate-800'}>Employee Simulator</strong> (normal activities like login, Excel, file views)
                      before its baseline is established.
                    </p>
                    <div className="flex gap-3">
                      {[['Events', sel.event_count || 0, 50], ['Days', sel.days_in_training || 0, 14]].map(([lbl, cur, max]) => (
                        <div key={lbl} className="flex-1">
                          <div className="flex justify-between text-xs text-amber-400/70 mb-1">
                            <span>{lbl}</span><span>{cur}/{max}</span>
                          </div>
                          <div className="h-1.5 rounded-full" style={{ background: 'rgba(255,255,255,0.08)' }}>
                            <div className="h-full rounded-full transition-all"
                              style={{ width: `${Math.min(100, (cur/max)*100)}%`, background: 'linear-gradient(90deg,#f59e0b,#fbbf24)' }} />
                          </div>
                        </div>
                      ))}
                    </div>
                    <button
                      onClick={() => { window.location.hash = '#simulator'; }}
                      className="mt-3 w-full py-1.5 rounded-lg text-xs font-bold text-amber-400 transition-colors"
                      style={{ background: 'rgba(245,158,11,0.12)', border: '1px solid rgba(245,158,11,0.3)' }}
                    >
                      Go to Employee Simulator to generate training data →
                    </button>
                  </div>
                );
              })()}
            </div>

            {/* ── Scenario Selection ────────────────────────────────── */}
            <div className="rounded-xl p-4" style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.06)' }}>
              <div className="flex items-center justify-between mb-3">
                <label className="text-xs font-bold text-gray-400 uppercase tracking-widest">Threat Scenario</label>
                <div className="flex items-center gap-1.5 px-2 py-0.5 rounded-full text-xs font-bold"
                  style={{ background: 'rgba(239,68,68,0.12)', color: '#f87171', border: '1px solid rgba(239,68,68,0.3)' }}>
                  Read-only — profile untouched
                </div>
              </div>
              <div className="space-y-2">
                {THREAT_SCENARIOS.map((scenario, i) => (
                  <div
                    key={i}
                    onClick={() => setSelectedScenario(i)}
                    className="flex items-start gap-3 p-3 rounded-lg cursor-pointer transition-all duration-200"
                    style={{
                      background: selectedScenario === i ? 'rgba(99,102,241,0.15)' : (isDark ? 'rgba(255,255,255,0.02)' : 'rgba(0,0,0,0.02)'),
                      border: selectedScenario === i ? '1px solid rgba(99,102,241,0.4)' : (isDark ? '1px solid rgba(255,255,255,0.05)' : '1px solid rgba(0,0,0,0.05)'),
                    }}
                  >
                    <div className="w-4 h-4 rounded-full border-2 flex-none mt-0.5 flex items-center justify-center"
                      style={{ borderColor: selectedScenario === i ? '#6366f1' : (isDark ? 'rgba(255,255,255,0.2)' : 'rgba(0,0,0,0.2)') }}>
                      {selectedScenario === i && <div className="w-2 h-2 rounded-full bg-indigo-400" />}
                    </div>
                    <div>
                      <div className={`text-sm font-bold ${isDark ? 'text-white' : 'text-slate-800'}`}>{scenario.name}</div>
                      <div className={`text-xs mt-0.5 ${isDark ? 'text-gray-400' : 'text-slate-500'}`}>{scenario.description}</div>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* ── Execute Button ────────────────────────────────────── */}
            <button
              onClick={handleSimulate}
              disabled={simLoading || !simEmployeeId}
              className="w-full py-3 rounded-xl text-sm font-bold text-white transition-all duration-300 disabled:opacity-50 disabled:cursor-not-allowed"
              style={{
                background: simLoading ? 'rgba(99,102,241,0.3)' : 'linear-gradient(135deg, #ef4444 0%, #dc2626 100%)',
                boxShadow: simLoading ? 'none' : '0 0 20px rgba(239,68,68,0.35)',
              }}
            >
              {simLoading ? (
                <span className="flex items-center justify-center gap-2">
                  <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                  Scoring against baseline (read-only)...
                </span>
              ) : (
                `Test Detection: ${THREAT_SCENARIOS[selectedScenario].name}`
              )}
            </button>

            {/* ── Result ───────────────────────────────────────────── */}
            {simResult && (
              <div className="rounded-xl p-4 transition-all duration-300"
                style={{
                  background: simResult.error
                    ? 'rgba(239,68,68,0.05)'
                    : simResult.status === 'cannot_score'
                      ? 'rgba(245,158,11,0.05)'
                      : simResult.alert_generated
                        ? 'rgba(239,68,68,0.08)'
                        : 'rgba(34,197,94,0.05)',
                  border: simResult.error
                    ? '1px solid rgba(239,68,68,0.3)'
                    : simResult.status === 'cannot_score'
                      ? '1px solid rgba(245,158,11,0.3)'
                      : simResult.alert_generated
                        ? '1px solid rgba(239,68,68,0.3)'
                        : '1px solid rgba(34,197,94,0.3)',
                }}>

                {/* API Error */}
                {simResult.error && (
                  <div className="text-red-400 text-sm">{simResult.error}</div>
                )}

                {/* Still training */}
                {simResult.status === 'cannot_score' && (
                  <div>
                    <div className="flex items-center gap-2 mb-2">
                      <span className="text-amber-400 text-lg"></span>
                      <span className="text-sm font-bold text-amber-400">
                        {simResult.reason === 'STILL_TRAINING' ? 'Twin Still in Training — Cannot Score Yet' : 'No Profile Found'}
                      </span>
                    </div>
                    <p className="text-xs text-gray-400 leading-5">{simResult.message}</p>
                    {simResult.reason === 'STILL_TRAINING' && (
                      <div className="mt-3 grid grid-cols-2 gap-3">
                        {[['Events collected', simResult.event_count, simResult.events_needed + simResult.event_count],
                          ['Days in training', 14 - (simResult.days_remaining || 0), 14]].map(([lbl, cur, max]) => (
                          <div key={lbl}>
                            <div className="flex justify-between text-xs text-amber-400/70 mb-1">
                              <span>{lbl}</span><span>{cur}/{max}</span>
                            </div>
                            <div className="h-2 rounded-full" style={{ background: 'rgba(255,255,255,0.08)' }}>
                              <div className="h-full rounded-full" style={{
                                width: `${Math.min(100,(cur/max)*100)}%`,
                                background: 'linear-gradient(90deg,#f59e0b,#fbbf24)'
                              }} />
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )}

                {/* Successful score result */}
                {simResult.status === 'success' && (
                  <>
                    {/* Model unchanged badge */}
                    <div className="flex items-center gap-2 mb-3">
                      <div className="flex items-center gap-1.5 px-2 py-1 rounded-lg text-xs font-bold"
                        style={{ background: 'rgba(34,197,94,0.12)', color: '#4ade80', border: '1px solid rgba(34,197,94,0.3)' }}>
                        SIMULATION ONLY — AI Twin profile unchanged
                      </div>
                    </div>

                    <div className="flex items-center gap-2 mb-3">
                      <span className="text-lg">{simResult.alert_generated ? '' : ''}</span>
                      <div className="text-sm font-bold" style={{ color: simResult.alert_generated ? '#ef4444' : '#22c55e' }}>
                        {simResult.alert_generated
                          ? 'THREAT DETECTED — would trigger a real alert if this were the Employee Simulator'
                          : 'No alert — event is within the employee\'s normal behavioural range'}
                      </div>
                    </div>

                    {simResult.alert && (
                      <div className="space-y-3">
                        <div className="grid grid-cols-3 gap-2">
                          {[
                            { label: 'Threat Score', value: (simResult.alert.threat_score || 0).toFixed(0) + '/100', color: threatColor(simResult.alert.threat_score || 0) },
                            { label: 'Severity', value: simResult.alert.severity || 'Normal', color: '#ef4444' },
                            { label: 'Confidence', value: (simResult.alert.confidence || 0) + '%', color: '#f59e0b' },
                          ].map(({ label, value, color }) => (
                            <div key={label} className="rounded-lg p-2 text-center" style={{ background: 'rgba(255,255,255,0.03)' }}>
                              <div className="text-sm font-black" style={{ color }}>{value}</div>
                              <div className="text-xs text-gray-500">{label}</div>
                            </div>
                          ))}
                        </div>

                        <div className="flex items-center gap-2 text-xs text-gray-500">
                          <span>Baseline from</span>
                          <span className="font-bold text-indigo-400">{simResult.alert.trained_on_events} Employee Simulator events</span>
                          <span>·</span>
                          <span>Emb drift</span>
                          <span className="font-bold" style={{ color: (simResult.alert.embedding_drift || 0) > 0.35 ? '#ef4444' : '#6b7280' }}>
                            {(simResult.alert.embedding_drift || 0).toFixed(3)}
                          </span>
                        </div>

                        {simResult.alert.flagged_domains?.length > 0 && (
                          <div className="flex flex-wrap gap-1.5">
                            <span className="text-xs text-gray-500">Flagged:</span>
                            {simResult.alert.flagged_domains.map(d => (
                              <span key={d} className="px-2 py-0.5 rounded-full text-xs"
                                style={{ background: 'rgba(239,68,68,0.15)', color: '#ef4444', border: '1px solid rgba(239,68,68,0.3)' }}>
                                {d}
                              </span>
                            ))}
                          </div>
                        )}

                        {simResult.alert.feature_deviations?.length > 0 && (
                          <div>
                            <div className="text-xs font-bold text-gray-400 mb-2 uppercase tracking-wider">Feature Deviations</div>
                            <div className="grid grid-cols-2 gap-2">
                              {simResult.alert.feature_deviations.slice(0, 8).map((fd, fi) => (
                                <div key={fi} className="rounded-lg px-3 py-2"
                                  style={{
                                    background: fd.severity === 'critical' ? 'rgba(239,68,68,0.08)' : 'rgba(255,255,255,0.02)',
                                    border: fd.severity === 'critical' ? '1px solid rgba(239,68,68,0.3)' : '1px solid rgba(255,255,255,0.05)',
                                  }}>
                                  <div className="text-xs font-bold text-white truncate">{fd.feature_name}</div>
                                  <div className="text-xs text-gray-500 mt-0.5">
                                    z = <span className={
                                      fd.severity === 'critical' ? 'text-red-400' :
                                      fd.severity === 'high' ? 'text-orange-400' : 'text-yellow-400'
                                    }>{(fd.z_score || 0).toFixed(1)}σ</span>
                                    {fd.baseline_mean !== undefined && (
                                      <span className="text-gray-600"> · baseline: {(fd.baseline_mean || 0).toFixed(2)}</span>
                                    )}
                                  </div>
                                </div>
                              ))}
                            </div>
                          </div>
                        )}

                        <p className="text-xs text-gray-500 leading-5 italic border-t border-white/5 pt-2">{simResult.alert.description}</p>
                      </div>
                    )}
                  </>
                )}
              </div>
            )}
          </div>
        )}
        {/* ══ TRAIN TWIN TAB ══ */}
        {activeTab === 'train' && (
          <div className="max-w-3xl mx-auto space-y-5">
            <div className="rounded-xl p-4"
              style={{ background: 'rgba(34,197,94,0.05)', border: '1px solid rgba(34,197,94,0.2)' }}>
              <div className="flex items-center gap-2 mb-1">
                <span className="text-emerald-400"></span>
                <h3 className="text-sm font-bold text-emerald-400">Train Normal Behaviour</h3>
              </div>
              <p className="text-xs text-gray-400">
                Generate a synthetic normal baseline for an employee. This injects authentic events directly into the AI Twin model, allowing you to bypass manual training and immediately test detection scenarios.
              </p>
            </div>

            {/* Employee selector */}
            <div className="rounded-xl p-4"
              style={{ background: isDark ? 'rgba(255,255,255,0.03)' : 'rgba(0,0,0,0.02)', border: isDark ? '1px solid rgba(255,255,255,0.06)' : '1px solid rgba(0,0,0,0.1)' }}>
              <label className="block text-xs font-bold text-gray-400 uppercase tracking-widest mb-2">
                Target Employee
              </label>
              <select
                value={simEmployeeId}
                onChange={e => setSimEmployeeId(e.target.value)}
                className={`w-full rounded-lg px-3 py-2 text-sm ${isDark ? 'text-white' : 'text-slate-800'}`}
                style={{ background: isDark ? 'rgba(255,255,255,0.05)' : 'rgba(0,0,0,0.05)', border: isDark ? '1px solid rgba(255,255,255,0.1)' : '1px solid rgba(0,0,0,0.1)' }}
              >
                <option value="">Select employee...</option>
                {profiles.map(p => (
                  <option key={p.employee_id} value={p.employee_id}>
                    {p.employee_name} ({p.employee_id}) — {p.is_trained ? 'Trained' : `Training (${p.event_count || 0} events)`}
                  </option>
                ))}
              </select>
            </div>

            {/* Configuration */}
            <div className="rounded-xl p-5 space-y-5"
              style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.06)' }}>
              <h4 className="text-xs font-bold text-gray-400 uppercase tracking-widest">Normal Behaviour Configuration</h4>
              
              <div className="space-y-4">
                <div>
                  <div className="flex justify-between mb-1">
                    <label className="text-sm text-gray-300">Number of Events</label>
                    <span className="text-sm font-bold text-indigo-400">{trainConfig.num_events}</span>
                  </div>
                  <input type="range" min="10" max="200" step="10"
                    value={trainConfig.num_events}
                    onChange={e => setTrainConfig({...trainConfig, num_events: parseInt(e.target.value)})}
                    className="w-full accent-indigo-500" />
                  <p className="text-xs text-gray-500 mt-1">Requires at least 50 events to be fully trained.</p>
                </div>

                <div>
                  <div className="flex justify-between mb-1">
                    <label className="text-sm text-gray-300">Base Typing Speed (WPM)</label>
                    <span className="text-sm font-bold text-emerald-400">{trainConfig.base_wpm} WPM</span>
                  </div>
                  <input type="range" min="20" max="120" step="5"
                    value={trainConfig.base_wpm}
                    onChange={e => setTrainConfig({...trainConfig, base_wpm: parseInt(e.target.value)})}
                    className="w-full accent-emerald-500" />
                </div>

                <div>
                  <div className="flex justify-between mb-1">
                    <label className="text-sm text-gray-300">Base Mouse Speed (px/s)</label>
                    <span className="text-sm font-bold text-emerald-400">{trainConfig.base_mouse_speed}</span>
                  </div>
                  <input type="range" min="100" max="1000" step="50"
                    value={trainConfig.base_mouse_speed}
                    onChange={e => setTrainConfig({...trainConfig, base_mouse_speed: parseInt(e.target.value)})}
                    className="w-full accent-emerald-500" />
                </div>

                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm text-gray-300 mb-1">Working Hours Start</label>
                    <select value={trainConfig.working_hours_start} onChange={e => setTrainConfig({...trainConfig, working_hours_start: parseInt(e.target.value)})}
                      className="w-full rounded-lg px-3 py-2 text-sm text-white bg-gray-800 border border-gray-700">
                      {[...Array(24)].map((_, i) => <option key={i} value={i}>{i.toString().padStart(2, '0')}:00</option>)}
                    </select>
                  </div>
                  <div>
                    <label className="block text-sm text-gray-300 mb-1">Working Hours End</label>
                    <select value={trainConfig.working_hours_end} onChange={e => setTrainConfig({...trainConfig, working_hours_end: parseInt(e.target.value)})}
                      className="w-full rounded-lg px-3 py-2 text-sm text-white bg-gray-800 border border-gray-700">
                      {[...Array(24)].map((_, i) => <option key={i} value={i}>{i.toString().padStart(2, '0')}:00</option>)}
                    </select>
                  </div>
                </div>
              </div>
            </div>

            {/* Execute button */}
            <button
              onClick={handleTrainNormal}
              disabled={trainLoading || !simEmployeeId}
              className="w-full py-3 rounded-xl text-sm font-bold text-white transition-all duration-300 disabled:opacity-50 disabled:cursor-not-allowed"
              style={{
                background: trainLoading ? 'rgba(34,197,94,0.3)' : 'linear-gradient(135deg, #10b981 0%, #059669 100%)',
                boxShadow: trainLoading ? 'none' : '0 0 20px rgba(16,185,129,0.35)',
              }}
            >
              {trainLoading ? (
                <span className="flex items-center justify-center gap-2">
                  <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                  Generating and learning normal behaviour...
                </span>
              ) : (
                `Generate Normal Baseline`
              )}
            </button>

            {/* Result */}
            {trainResult && (
              <div className="rounded-xl p-4 transition-all duration-300"
                style={{
                  background: trainResult.error ? 'rgba(239,68,68,0.05)' : 'rgba(34,197,94,0.05)',
                  border: trainResult.error ? '1px solid rgba(239,68,68,0.3)' : '1px solid rgba(34,197,94,0.3)',
                }}>
                {trainResult.error ? (
                  <div className="text-red-400 text-sm">{trainResult.error}</div>
                ) : (
                  <div className="flex items-center justify-between">
                    <div>
                      <div className="flex items-center gap-2 mb-1">
                        <span className="text-lg"></span>
                        <div className="text-sm font-bold text-emerald-400">
                          {trainResult.message}
                        </div>
                      </div>
                      <p className="text-xs text-emerald-400/80 ml-7">
                        Profile now has {trainResult.event_count} events. It is {trainResult.is_trained ? 'fully trained' : 'still training'}.
                      </p>
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        )}
      </div>

      {/* ── Reset Confirmation Modal ──────────────────────────────────── */}
      {confirmReset && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center z-50">
          <div className="rounded-xl p-6 w-full max-w-sm"
            style={{ background: '#1a1d27', border: '1px solid rgba(239,68,68,0.4)' }}>
            <div className="text-xl mb-2"></div>
            <h3 className="text-white font-bold mb-2">Reset AI Twin?</h3>
            <p className="text-xs text-gray-400 mb-4">
              This will permanently erase all learned behaviour for <strong className="text-white">{confirmReset}</strong> and restart training from zero. This action cannot be undone.
            </p>
            <div className="flex gap-3">
              <button
                onClick={() => setConfirmReset(null)}
                className="flex-1 py-2 rounded-lg text-sm font-semibold text-gray-400 border border-gray-600 hover:border-gray-400 transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={() => handleReset(confirmReset)}
                className="flex-1 py-2 rounded-lg text-sm font-bold text-white bg-red-600 hover:bg-red-500 transition-colors"
              >
                Reset Twin
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
