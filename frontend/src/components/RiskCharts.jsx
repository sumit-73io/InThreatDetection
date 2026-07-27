import { useEffect, useMemo, useState } from 'react';
import * as Icon from './Icons';

/**
 * Dashboard visualisations + derived recommendations.
 *
 * ─── Colour decisions (validated, not eyeballed) ──────────────────────
 *
 * Risk tiers wear STATUS tokens, not categorical ones: Low/Medium/High *mean*
 * good/warning/critical, and the collision rule says a series that means
 * good/bad wears status. They are mode-invariant (#10b981 / #f59e0b / #ef4444),
 * matching the badges and risk bars already used across the console, so "High"
 * is the same red everywhere.
 *
 *   Measured on the real surfaces (#ffffff light card, #1e222b dark card):
 *     dark  — low 6.28:1, medium 7.41:1, high 4.23:1   all >= 3:1
 *     light — low 2.54:1, medium 2.15:1, high 3.76:1   low/medium sub-3:1
 *     distinctness — CVD dE 8.1 (>=8 target), normal-vision 19.8 (>=15 floor)
 *
 *   The two sub-3:1 light values trigger the relief rule, so every status mark
 *   here ships an icon + text label + a direct value label. Colour never
 *   carries meaning alone. (Status scales are deliberately outside the
 *   categorical lightness-band check — stepping the amber darker for dark mode
 *   collapses it against the red: amber/red normal-vision dE falls 19.8 -> 11.8,
 *   which is a worse failure than the band miss.)
 *
 * Magnitude and trend charts are SINGLE-SERIES, so every bar takes the same
 * slot-1 blue rather than a value ramp — bar length already encodes the value,
 * and value-ramping nominal categories burns the identity channel:
 *     light #2a78d6 (4.42:1)   dark #3987e5 (4.38:1)
 *
 * ─── Form decisions ──────────────────────────────────────────────────
 *   risk posture   part-to-whole, 3 ordered tiers  -> donut (<= 6 segments)
 *   risk trend     change over time, one series    -> line + 10% area wash
 *   action mix     magnitude, nominal, long names  -> horizontal bars
 *   role exposure  magnitude, nominal              -> horizontal bars
 *
 * Marks follow the fixed specs: <= 24px bars with a 4px rounded data-end square
 * at the baseline, 2px lines, >= 8px end markers with a 2px surface ring, solid
 * hairline gridlines, a 2px surface gap between touching fills, and selective
 * direct labels (never a number on every point).
 *
 * Every chart has a table-view twin, toggled from the single filter row above
 * all four cards — tooltips enhance, they never gate a value.
 */

// ─── Tokens ──────────────────────────────────────────────────────────

function tokens(isDark) {
    return {
        surface: isDark ? '#1e222b' : '#ffffff',
        grid: isDark ? '#2c2c2a' : '#e1e0d9',
        axis: isDark ? '#383835' : '#c3c2b7',
        muted: '#898781',
        ink: isDark ? '#ffffff' : '#0b0b0b',
        ink2: isDark ? '#c3c2b7' : '#52514e',
        // Single-series / sequential slot-1 blue, stepped per mode.
        series: isDark ? '#3987e5' : '#2a78d6',
        // Status scale — mode-invariant by design.
        risk: { High: '#ef4444', Medium: '#f59e0b', Low: '#10b981' },
    };
}

const RISK_ICON = { High: Icon.AlertOctagon, Medium: Icon.Warning, Low: Icon.Check };

// ─── Geometry helpers ────────────────────────────────────────────────

function polar(cx, cy, r, angle) {
    return [cx + r * Math.cos(angle), cy + r * Math.sin(angle)];
}

/** Donut segment path. Angles in radians, 0 = 12 o'clock. */
function arcPath(cx, cy, rOuter, rInner, start, end) {
    const a0 = start - Math.PI / 2;
    const a1 = end - Math.PI / 2;
    const [x0, y0] = polar(cx, cy, rOuter, a0);
    const [x1, y1] = polar(cx, cy, rOuter, a1);
    const [x2, y2] = polar(cx, cy, rInner, a1);
    const [x3, y3] = polar(cx, cy, rInner, a0);
    const large = end - start > Math.PI ? 1 : 0;
    return [
        `M ${x0} ${y0}`,
        `A ${rOuter} ${rOuter} 0 ${large} 1 ${x1} ${y1}`,
        `L ${x2} ${y2}`,
        `A ${rInner} ${rInner} 0 ${large} 0 ${x3} ${y3}`,
        'Z',
    ].join(' ');
}

/** Bar with a 4px rounded data-end and a square baseline end. */
function hBarPath(x, y, w, h, r = 4) {
    const rr = Math.min(r, Math.max(0, w), h / 2);
    if (w <= 0.5) return '';
    return [
        `M ${x} ${y}`,
        `H ${x + w - rr}`,
        `Q ${x + w} ${y} ${x + w} ${y + rr}`,
        `V ${y + h - rr}`,
        `Q ${x + w} ${y + h} ${x + w - rr} ${y + h}`,
        `H ${x}`,
        'Z',
    ].join(' ');
}

function niceMax(value) {
    if (value <= 0) return 1;
    const mag = Math.pow(10, Math.floor(Math.log10(value)));
    return Math.ceil(value / mag) * mag;
}

const formatAction = (a) =>
    (a || '').split('_').map((w) => w.charAt(0) + w.slice(1).toLowerCase()).join(' ');

// ─── Shared card chrome ──────────────────────────────────────────────

function Card({ title, subtitle, isDark, children, recommendation }) {
    const t = tokens(isDark);
    return (
        <div
            className={`rounded-xl border shadow-sm flex flex-col ${isDark ? 'bg-[#1e222b] border-[#2d3340]' : 'bg-white border-gray-200'}`}
        >
            <div className="px-5 pt-4 pb-2">
                <h3 className="text-sm font-bold" style={{ color: t.ink }}>{title}</h3>
                {subtitle && (
                    <p className="text-[11px] mt-0.5" style={{ color: t.muted }}>{subtitle}</p>
                )}
            </div>
            <div className="px-5 pb-3 flex-1">{children}</div>
            {recommendation && (
                <div
                    className="px-5 py-3 border-t flex items-start gap-2.5"
                    style={{ borderColor: t.grid }}
                >
                    <div className="shrink-0 mt-0.5" style={{ color: recommendation.tone }}>
                        <recommendation.Icon className="w-4 h-4" />
                    </div>
                    <div>
                        <p
                            className="text-[10px] font-bold uppercase tracking-wider"
                            style={{ color: t.muted }}
                        >
                            Recommended action
                        </p>
                        <p className="text-xs mt-0.5 leading-5" style={{ color: t.ink2 }}>
                            {recommendation.text}
                        </p>
                    </div>
                </div>
            )}
        </div>
    );
}

function DataTable({ columns, rows, isDark }) {
    const t = tokens(isDark);
    return (
        <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
                <thead>
                    <tr style={{ borderBottom: `1px solid ${t.grid}` }}>
                        {columns.map((c, i) => (
                            <th
                                key={c}
                                className={`py-2 font-bold ${i ? 'text-right' : ''}`}
                                style={{ color: t.muted }}
                            >
                                {c}
                            </th>
                        ))}
                    </tr>
                </thead>
                <tbody style={{ fontVariantNumeric: 'tabular-nums' }}>
                    {rows.length === 0 && (
                        <tr>
                            <td colSpan={columns.length} className="py-4 text-center" style={{ color: t.muted }}>
                                No data
                            </td>
                        </tr>
                    )}
                    {rows.map((r, i) => (
                        <tr key={i} style={{ borderBottom: `1px solid ${t.grid}` }}>
                            {r.map((cell, j) => (
                                <td
                                    key={j}
                                    className={`py-1.5 ${j ? 'text-right' : 'font-medium'}`}
                                    style={{ color: j ? t.ink2 : t.ink }}
                                >
                                    {cell}
                                </td>
                            ))}
                        </tr>
                    ))}
                </tbody>
            </table>
        </div>
    );
}

function Tooltip({ x, y, lines, isDark }) {
    const t = tokens(isDark);
    return (
        <div
            className="pointer-events-none absolute z-20 rounded-lg px-2.5 py-1.5 shadow-xl text-[11px] whitespace-nowrap"
            style={{
                left: x, top: y, transform: 'translate(-50%, -115%)',
                background: isDark ? '#0d0d0d' : '#0b0b0b',
                color: '#ffffff',
                border: `1px solid ${t.axis}`,
            }}
        >
            {lines.map((l, i) => (
                <div key={i} className={i === 0 ? 'font-bold' : 'opacity-80'}>{l}</div>
            ))}
        </div>
    );
}

// ═════════════════════════════════════════════════════════════════════
// 1. Risk posture donut
// ═════════════════════════════════════════════════════════════════════

function RiskPostureDonut({ tiers, total, isDark, showTable }) {
    const t = tokens(isDark);
    const [hover, setHover] = useState(null);

    const order = ['High', 'Medium', 'Low'];
    const present = order.filter((k) => tiers[k] > 0);
    const sum = order.reduce((a, k) => a + tiers[k], 0);

    if (showTable) {
        return (
            <DataTable
                isDark={isDark}
                columns={['Risk tier', 'Users', 'Share']}
                rows={order.map((k) => [
                    k, tiers[k], sum ? `${Math.round((tiers[k] / sum) * 100)}%` : '0%',
                ])}
            />
        );
    }

    const size = 168, cx = size / 2, cy = size / 2, rOuter = 74, rInner = 50;
    // A 2px surface gap between touching segments, expressed as an angle at the
    // mid-radius. Only applied when more than one segment is present.
    const gap = present.length > 1 ? 2 / ((rOuter + rInner) / 2) : 0;

    let angle = 0;
    const segments = present.map((k) => {
        const share = tiers[k] / sum;
        const start = angle;
        const end = angle + share * Math.PI * 2;
        angle = end;
        return { key: k, start, end, value: tiers[k], share };
    });

    return (
        <div className="relative flex items-center gap-5">
            <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} className="shrink-0" role="img"
                 aria-label={`Risk posture: ${order.map((k) => `${tiers[k]} ${k}`).join(', ')}`}>
                {sum === 0 && (
                    <circle cx={cx} cy={cy} r={(rOuter + rInner) / 2} fill="none"
                            stroke={t.grid} strokeWidth={rOuter - rInner} />
                )}
                {segments.map((s) => {
                    const half = gap / 2;
                    const a0 = s.start + half;
                    const a1 = Math.max(a0 + 0.001, s.end - half);
                    return (
                        <path
                            key={s.key}
                            d={arcPath(cx, cy, rOuter, rInner, a0, a1)}
                            fill={t.risk[s.key]}
                            opacity={hover && hover.key !== s.key ? 0.45 : 1}
                            onMouseEnter={() => setHover(s)}
                            onMouseLeave={() => setHover(null)}
                            style={{ transition: 'opacity 150ms' }}
                        />
                    );
                })}
                <text x={cx} y={cy - 2} textAnchor="middle" fontSize="26" fontWeight="700" fill={t.ink}>
                    {total}
                </text>
                <text x={cx} y={cy + 15} textAnchor="middle" fontSize="9" letterSpacing="1.1" fill={t.muted}>
                    MONITORED
                </text>
            </svg>

            {/* Legend with icon + label + direct value — status colour never
                carries meaning alone, and this is the sub-3:1 contrast relief. */}
            <div className="flex-1 space-y-2">
                {order.map((k) => {
                    const TierIcon = RISK_ICON[k];
                    const pct = sum ? Math.round((tiers[k] / sum) * 100) : 0;
                    return (
                        <div key={k} className="flex items-center gap-2.5">
                            <span style={{ color: t.risk[k] }} className="shrink-0">
                                <TierIcon className="w-4 h-4" />
                            </span>
                            <span className="text-xs font-medium flex-1" style={{ color: t.ink2 }}>
                                {k} risk
                            </span>
                            <span className="text-xs font-bold" style={{ color: t.ink }}>
                                {tiers[k]}
                            </span>
                            <span className="text-[11px] w-9 text-right" style={{ color: t.muted }}>
                                {pct}%
                            </span>
                        </div>
                    );
                })}
            </div>

            {hover && (
                <Tooltip
                    x={cx} y={cy - 40} isDark={isDark}
                    lines={[
                        `${hover.key} risk`,
                        `${hover.value} user${hover.value === 1 ? '' : 's'} · ${Math.round(hover.share * 100)}%`,
                    ]}
                />
            )}
        </div>
    );
}

// ═════════════════════════════════════════════════════════════════════
// 2. Risk trend over time (single series)
// ═════════════════════════════════════════════════════════════════════

function RiskTrend({ buckets, isDark, showTable }) {
    const t = tokens(isDark);
    const [hover, setHover] = useState(null);

    if (showTable) {
        return (
            <DataTable
                isDark={isDark}
                columns={['Hour', 'Events', 'Risk added']}
                rows={buckets.map((b) => [b.label, b.count, b.risk])}
            />
        );
    }

    const W = 420, H = 150;
    const pad = { l: 34, r: 16, t: 12, b: 26 };
    const pw = W - pad.l - pad.r;
    const ph = H - pad.t - pad.b;

    const max = niceMax(Math.max(1, ...buckets.map((b) => b.risk)));
    const xAt = (i) => pad.l + (buckets.length <= 1 ? pw / 2 : (i / (buckets.length - 1)) * pw);
    const yAt = (v) => pad.t + ph - (v / max) * ph;

    const line = buckets.map((b, i) => `${i ? 'L' : 'M'} ${xAt(i)} ${yAt(b.risk)}`).join(' ');
    const area = buckets.length
        ? `${line} L ${xAt(buckets.length - 1)} ${pad.t + ph} L ${xAt(0)} ${pad.t + ph} Z`
        : '';

    const ticks = [0, max / 2, max];
    const last = buckets.length ? buckets[buckets.length - 1] : null;

    return (
        <div className="relative">
            <svg width="100%" viewBox={`0 0 ${W} ${H}`} role="img"
                 aria-label="Risk accumulated per hour over the selected window">
                {/* Solid hairline gridlines, recessive */}
                {ticks.map((v, i) => (
                    <g key={i}>
                        <line x1={pad.l} x2={W - pad.r} y1={yAt(v)} y2={yAt(v)}
                              stroke={t.grid} strokeWidth="1" />
                        <text x={pad.l - 7} y={yAt(v) + 3} textAnchor="end" fontSize="9"
                              fill={t.muted} style={{ fontVariantNumeric: 'tabular-nums' }}>
                            {Math.round(v)}
                        </text>
                    </g>
                ))}
                <line x1={pad.l} x2={W - pad.r} y1={pad.t + ph} y2={pad.t + ph}
                      stroke={t.axis} strokeWidth="1" />

                {/* Area wash at ~10%, then the 2px line */}
                {area && <path d={area} fill={t.series} opacity="0.1" />}
                {buckets.length > 1 && (
                    <path d={line} fill="none" stroke={t.series} strokeWidth="2"
                          strokeLinejoin="round" strokeLinecap="round" />
                )}

                {/* End marker: >= 8px with a 2px surface ring */}
                {last && (
                    <circle cx={xAt(buckets.length - 1)} cy={yAt(last.risk)} r="4.5"
                            fill={t.series} stroke={t.surface} strokeWidth="2" />
                )}

                {/* Selective direct label: the endpoint only.
                    Clamped inside the plot — when the last value IS the maximum,
                    an unclamped label sits above the viewBox and gets cropped. */}
                {last && (
                    <text
                        x={xAt(buckets.length - 1)}
                        y={Math.max(pad.t + 8, yAt(last.risk) - 11)}
                        textAnchor="end"
                        fontSize="10" fontWeight="700" fill={t.ink}
                        style={{ fontVariantNumeric: 'tabular-nums' }}
                    >
                        {last.risk}
                    </text>
                )}

                {/* X labels, thinned so they never collide */}
                {buckets.map((b, i) => {
                    const step = Math.max(1, Math.ceil(buckets.length / 6));
                    if (i % step !== 0 && i !== buckets.length - 1) return null;
                    return (
                        <text key={i} x={xAt(i)} y={H - 8} textAnchor="middle" fontSize="9" fill={t.muted}>
                            {b.label}
                        </text>
                    );
                })}

                {/* Hover targets sized well beyond the mark */}
                {buckets.map((b, i) => (
                    <rect
                        key={`h${i}`}
                        x={xAt(i) - pw / (2 * Math.max(1, buckets.length - 1))}
                        y={pad.t}
                        width={Math.max(24, pw / Math.max(1, buckets.length - 1))}
                        height={ph}
                        fill="transparent"
                        onMouseEnter={() => setHover({ ...b, i })}
                        onMouseLeave={() => setHover(null)}
                    />
                ))}
                {hover && (
                    <line x1={xAt(hover.i)} x2={xAt(hover.i)} y1={pad.t} y2={pad.t + ph}
                          stroke={t.axis} strokeWidth="1" />
                )}
            </svg>
            {hover && (
                <Tooltip
                    x={`${(xAt(hover.i) / W) * 100}%`} y={0} isDark={isDark}
                    lines={[hover.label, `Risk added ${hover.risk}`, `${hover.count} event${hover.count === 1 ? '' : 's'}`]}
                />
            )}
        </div>
    );
}

// ═════════════════════════════════════════════════════════════════════
// 3 & 4. Horizontal magnitude bars (single series, one hue)
// ═════════════════════════════════════════════════════════════════════

function MagnitudeBars({ rows, isDark, showTable, columns, unit }) {
    const t = tokens(isDark);
    const [hover, setHover] = useState(null);

    if (showTable) {
        return (
            <DataTable
                isDark={isDark}
                columns={columns}
                rows={rows.map((r) => [r.label, r.value, r.note ?? ''])}
            />
        );
    }

    if (rows.length === 0) {
        return <p className="text-xs py-6 text-center" style={{ color: t.muted }}>No data in this window</p>;
    }

    const BAR = 16;              // <= 24px cap
    const GAP = 12;              // leaves air in the band; > 2px surface gap
    const labelW = 128;
    const valueW = 44;
    const W = 420;
    const plotW = W - labelW - valueW;
    const H = rows.length * (BAR + GAP);
    const max = niceMax(Math.max(...rows.map((r) => r.value)));

    return (
        <div className="relative">
            <svg width="100%" viewBox={`0 0 ${W} ${H}`} role="img" aria-label={columns.join(', ')}>
                {rows.map((r, i) => {
                    const y = i * (BAR + GAP) + GAP / 2;
                    const w = (r.value / max) * plotW;
                    const active = hover?.i === i;
                    return (
                        <g key={r.label}
                           onMouseEnter={() => setHover({ ...r, i, y })}
                           onMouseLeave={() => setHover(null)}>
                            {/* Hit target spanning the whole row, >= 24px tall */}
                            <rect x="0" y={i * (BAR + GAP)} width={W} height={BAR + GAP} fill="transparent" />
                            <text x="0" y={y + BAR - 3} fontSize="10.5" fill={t.ink2}>
                                {r.label.length > 20 ? `${r.label.slice(0, 19)}…` : r.label}
                            </text>
                            {/* Track, then the mark */}
                            <rect x={labelW} y={y} width={plotW} height={BAR} rx="2" fill={t.grid} opacity="0.5" />
                            <path d={hBarPath(labelW, y, w, BAR)} fill={t.series}
                                  opacity={hover && !active ? 0.5 : 1}
                                  style={{ transition: 'opacity 150ms' }} />
                            {/* Value at the tip */}
                            <text x={W - 4} y={y + BAR - 3} textAnchor="end" fontSize="10.5"
                                  fontWeight="700" fill={t.ink}
                                  style={{ fontVariantNumeric: 'tabular-nums' }}>
                                {r.value}
                            </text>
                        </g>
                    );
                })}
            </svg>
            {hover && (
                <Tooltip
                    x="50%" y={hover.y} isDark={isDark}
                    lines={[hover.label, `${hover.value} ${unit}`, ...(hover.note ? [hover.note] : [])]}
                />
            )}
        </div>
    );
}

// ═════════════════════════════════════════════════════════════════════
// Recommendation engine — reads the data, states an action
// ═════════════════════════════════════════════════════════════════════

const TONE = { critical: '#ef4444', warning: '#f59e0b', good: '#10b981', info: '#3b82f6' };

function postureRecommendation(tiers, users) {
    if (users.length === 0) {
        return {
            Icon: Icon.Info, tone: TONE.info,
            text: 'No monitored activity yet. Provision employees and generate telemetry from the Employee Simulator before drawing conclusions from this view.',
        };
    }
    if (tiers.High > 0) {
        const worst = users.filter((u) => u.riskLevel === 'High')
            .sort((a, b) => b.totalRisk - a.totalRisk).slice(0, 2);
        const names = worst.map((u) => `${u.name} (${u.totalRisk})`).join(' and ');
        return {
            Icon: Icon.AlertOctagon, tone: TONE.critical,
            text: `${tiers.High} user${tiers.High === 1 ? '' : 's'} in the High tier. Open ${names} first — highest accumulated risk — and confirm whether their recent high-weight actions were authorised before the 24-hour enforcement window closes.`,
        };
    }
    if (tiers.Medium > 0) {
        const m = users.filter((u) => u.riskLevel === 'Medium')
            .sort((a, b) => b.totalRisk - a.totalRisk)[0];
        return {
            Icon: Icon.Warning, tone: TONE.warning,
            text: `No High-tier users, but ${tiers.Medium} sitting at Medium. ${m.name} is closest to escalation (${m.totalRisk}) — review their action mix now, while it is still cheap to correct.`,
        };
    }
    return {
        Icon: Icon.Check, tone: TONE.good,
        text: 'All monitored users are in the Low tier. The useful next step is coverage, not triage: build behavioural baselines for anyone still scored on static weights so deviations become detectable.',
    };
}

function trendRecommendation(buckets) {
    const withRisk = buckets.filter((b) => b.risk > 0);
    if (withRisk.length === 0) {
        return {
            Icon: Icon.Check, tone: TONE.good,
            text: 'No risk accumulated in this window. Nothing to action.',
        };
    }
    const third = Math.max(1, Math.floor(buckets.length / 3));
    const early = buckets.slice(0, third).reduce((a, b) => a + b.risk, 0);
    const late = buckets.slice(-third).reduce((a, b) => a + b.risk, 0);
    const peak = buckets.reduce((a, b) => (b.risk > a.risk ? b : a), buckets[0]);

    if (late > early * 1.5 && late > 0) {
        return {
            Icon: Icon.AlertOctagon, tone: TONE.critical,
            text: `Risk is accelerating — the most recent third of the window carries ${late} against ${early} at the start. Treat this as an active episode rather than background noise: investigate the ${peak.label} peak and check whether one account is driving it.`,
        };
    }
    if (early > late * 1.5 && early > 0) {
        return {
            Icon: Icon.Check, tone: TONE.good,
            text: `Risk is subsiding (${early} early against ${late} late), so the ${peak.label} peak looks like a contained episode. Confirm it was resolved rather than merely stopped, then move on.`,
        };
    }
    return {
        Icon: Icon.Info, tone: TONE.info,
        text: `Risk is broadly flat across the window, peaking at ${peak.label} (${peak.risk}). A steady level is the baseline to compare against — investigate departures from it, not the level itself.`,
    };
}

function actionMixRecommendation(rows, weights) {
    if (rows.length === 0) {
        return { Icon: Icon.Info, tone: TONE.info, text: 'No actions recorded in this window.' };
    }
    // The action carrying the most total risk, not merely the most frequent.
    const byRisk = [...rows].map((r) => ({ ...r, load: r.value * (weights[r.raw] ?? 0) }))
        .sort((a, b) => b.load - a.load);
    const top = byRisk[0];

    if (!top || top.load === 0) {
        return {
            Icon: Icon.Check, tone: TONE.good,
            text: `Activity is entirely zero-weight actions (${rows[0].label} dominates at ${rows[0].value}). Normal operational traffic — no action needed.`,
        };
    }
    return {
        Icon: top.load >= 100 ? Icon.AlertOctagon : Icon.Warning,
        tone: top.load >= 100 ? TONE.critical : TONE.warning,
        text: `${top.label} contributes the most risk in this window (${top.value} events × weight ${weights[top.raw]} = ${top.load}). Verify these were authorised, and if they are routine for the roles performing them, raise it with the role-action matrix in the anomaly engine so legitimate work stops generating noise.`,
    };
}

function roleRecommendation(rows) {
    if (rows.length === 0) {
        return { Icon: Icon.Info, tone: TONE.info, text: 'No role data in this window.' };
    }
    const sorted = [...rows].sort((a, b) => b.value - a.value);
    const top = sorted[0];
    const others = sorted.slice(1);
    const median = others.length
        ? others.map((r) => r.value).sort((a, b) => a - b)[Math.floor(others.length / 2)]
        : 0;

    if (top.value === 0) {
        return {
            Icon: Icon.Check, tone: TONE.good,
            text: 'No role is carrying measurable risk per head in this window.',
        };
    }
    if (median > 0 && top.value >= median * 2) {
        return {
            Icon: Icon.Warning, tone: TONE.warning,
            text: `${top.label} carries ${(top.value / median).toFixed(1)}× the median risk per person (${top.value} against ${median}). That is a role-design signal, not an individual one — review whether that role's standing permissions are wider than its actual duties require.`,
        };
    }
    return {
        Icon: Icon.Info, tone: TONE.info,
        text: `${top.label} carries the highest risk per person (${top.value}), broadly in line with other roles. Keep monitoring rather than re-scoping permissions on this evidence.`,
    };
}

// ═════════════════════════════════════════════════════════════════════
// Main export
// ═════════════════════════════════════════════════════════════════════

const ACTION_WEIGHTS = {
    LOGIN: 0, LOGOUT: 0, VIEW_CUSTOMER: 0, DOWNLOAD_FILE: 10,
    DOWNLOAD_CONFIDENTIAL: 30, USB_CONNECTED: 20, FAILED_LOGIN: 15,
    CHANGE_PERMISSION: 35, DELETE_FILE: 40,
};

const WINDOWS = [
    { key: 6, label: '6h' },
    { key: 24, label: '24h' },
    { key: 72, label: '3d' },
];

export default function RiskCharts({ isDark, activities = [], users = [] }) {
    const t = tokens(isDark);
    // One filter row above everything it scopes — never per-card filters.
    const [windowHours, setWindowHours] = useState(24);
    const [showTable, setShowTable] = useState(false);

    // The window is relative to "now", but reading the clock during render is
    // impure — it makes the same props produce different output on a re-render.
    // Sample it in an effect instead and let the bucketing be a pure function of
    // (activities, windowHours, now).
    const [now, setNow] = useState(() => Date.now());
    useEffect(() => {
        const id = setInterval(() => setNow(Date.now()), 30000);
        return () => clearInterval(id);
    }, []);

    const scoped = useMemo(() => {
        const cutoff = now - windowHours * 3600 * 1000;
        return activities.filter((a) => {
            const raw = typeof a.timestamp === 'string' && !a.timestamp.endsWith('Z')
                ? `${a.timestamp}Z` : a.timestamp;
            const ts = new Date(raw).getTime();
            return Number.isFinite(ts) && ts >= cutoff;
        });
    }, [activities, windowHours, now]);

    const tiers = useMemo(() => {
        const out = { High: 0, Medium: 0, Low: 0 };
        users.forEach((u) => { out[u.riskLevel] = (out[u.riskLevel] || 0) + 1; });
        return out;
    }, [users]);

    const buckets = useMemo(() => {
        const bucketCount = windowHours <= 6 ? 6 : windowHours <= 24 ? 12 : 12;
        const span = (windowHours * 3600 * 1000) / bucketCount;
        const start = now - windowHours * 3600 * 1000;
        const out = Array.from({ length: bucketCount }, (_, i) => {
            const at = new Date(start + i * span);
            return {
                label: at.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
                count: 0, risk: 0,
            };
        });
        scoped.forEach((a) => {
            const raw = typeof a.timestamp === 'string' && !a.timestamp.endsWith('Z')
                ? `${a.timestamp}Z` : a.timestamp;
            const idx = Math.min(bucketCount - 1,
                Math.max(0, Math.floor((new Date(raw).getTime() - start) / span)));
            out[idx].count += 1;
            out[idx].risk += a.risk_score || 0;
        });
        return out;
    }, [scoped, windowHours, now]);

    const actionRows = useMemo(() => {
        const counts = {};
        scoped.forEach((a) => {
            const key = a.action?.value || a.action || 'UNKNOWN';
            counts[key] = (counts[key] || 0) + 1;
        });
        return Object.entries(counts)
            .map(([raw, value]) => ({
                raw, value, label: formatAction(raw),
                note: `weight ${ACTION_WEIGHTS[raw] ?? 0}`,
            }))
            .sort((a, b) => b.value - a.value)
            .slice(0, 7);
    }, [scoped]);

    const roleRows = useMemo(() => {
        const byRole = {};
        users.forEach((u) => {
            const r = u.role || 'Unknown';
            byRole[r] = byRole[r] || { risk: 0, heads: 0 };
            byRole[r].risk += u.totalRisk;
            byRole[r].heads += 1;
        });
        return Object.entries(byRole)
            .map(([label, v]) => ({
                label, value: Math.round(v.risk / v.heads),
                note: `${v.heads} user${v.heads === 1 ? '' : 's'}`,
            }))
            .sort((a, b) => b.value - a.value)
            .slice(0, 7);
    }, [users]);

    const btn = (active) =>
        `px-2.5 py-1 rounded-md text-[11px] font-bold transition ${
            active
                ? 'bg-blue-600 text-white'
                : isDark ? 'text-gray-400 hover:bg-[#2d3340]' : 'text-gray-500 hover:bg-gray-100'
        }`;

    return (
        <div className="mb-6">
            {/* ── Single filter row, scoping every card below ───────────── */}
            <div className="flex items-center justify-between mb-3">
                <h2 className="text-sm font-bold uppercase tracking-wider" style={{ color: t.muted }}>
                    Risk Analytics
                </h2>
                <div className="flex items-center gap-3">
                    <div
                        className="flex items-center gap-0.5 rounded-lg p-0.5"
                        style={{ background: isDark ? '#15171e' : '#f3f4f6' }}
                    >
                        {WINDOWS.map((w) => (
                            <button key={w.key} onClick={() => setWindowHours(w.key)}
                                    className={btn(windowHours === w.key)}>
                                {w.label}
                            </button>
                        ))}
                    </div>
                    <button
                        onClick={() => setShowTable(!showTable)}
                        className={btn(showTable)}
                        title="Every chart has a table-view twin"
                    >
                        {showTable ? 'Charts' : 'Tables'}
                    </button>
                </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                <Card
                    isDark={isDark}
                    title="Risk posture"
                    subtitle={`${users.length} monitored user${users.length === 1 ? '' : 's'} by risk tier`}
                    recommendation={postureRecommendation(tiers, users)}
                >
                    <RiskPostureDonut tiers={tiers} total={users.length} isDark={isDark} showTable={showTable} />
                </Card>

                <Card
                    isDark={isDark}
                    title="Risk accumulation"
                    subtitle={`Risk added per interval over the last ${windowHours}h`}
                    recommendation={trendRecommendation(buckets)}
                >
                    <RiskTrend buckets={buckets} isDark={isDark} showTable={showTable} />
                </Card>

                <Card
                    isDark={isDark}
                    title="Action mix"
                    subtitle={`${scoped.length} event${scoped.length === 1 ? '' : 's'} by type, last ${windowHours}h`}
                    recommendation={actionMixRecommendation(actionRows, ACTION_WEIGHTS)}
                >
                    <MagnitudeBars
                        rows={actionRows} isDark={isDark} showTable={showTable}
                        columns={['Action', 'Events', 'Risk weight']} unit="events"
                    />
                </Card>

                <Card
                    isDark={isDark}
                    title="Exposure by role"
                    subtitle="Average accumulated risk per person in each role"
                    recommendation={roleRecommendation(roleRows)}
                >
                    <MagnitudeBars
                        rows={roleRows} isDark={isDark} showTable={showTable}
                        columns={['Role', 'Risk per head', 'Headcount']} unit="risk per head"
                    />
                </Card>
            </div>
        </div>
    );
}
