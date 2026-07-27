import React, { useState } from 'react';

/**
 * EmbeddingHeatmap — 64-cell heatmap visualising the behavioural embedding vector.
 * Renders two rows: baseline (blue) vs current (cyan/red).
 *
 * Props:
 *   baseline  — array of 64 floats (0–1)
 *   current   — array of 64 floats (0–1) [optional]
 *   labels    — domain label + slot count for axis annotation
 *   cellSize  — cell size in px (default 16)
 */

const DOMAIN_LABELS = [
  { label: 'Identity',     slots: 10 },
  { label: 'Keyboard',     slots: 10 },
  { label: 'Mouse',        slots: 8  },
  { label: 'Application',  slots: 12 },
  { label: 'File',         slots: 12 },
  { label: 'Network',      slots: 6  },
  { label: 'Security',     slots: 6  },
];

function valueToBaselineColour(v) {
  // Deep blue (0) → bright cyan (1)
  const r = Math.round(10 + v * 30);
  const g = Math.round(80 + v * 130);
  const b = Math.round(180 + v * 75);
  return `rgb(${r},${g},${b})`;
}

function valueToDriftColour(v, drift) {
  // Normal: deep teal; high drift: red
  if (drift > 0.4) {
    const r = Math.round(180 + v * 75);
    const g = Math.round(40 + v * 40);
    const b = Math.round(40 + v * 20);
    return `rgb(${r},${g},${b})`;
  }
  const r = Math.round(20 + v * 60);
  const g = Math.round(180 + v * 75);
  const b = Math.round(160 + v * 95);
  return `rgb(${r},${g},${b})`;
}

function opacity(v) {
  return Math.max(0.15, v * 0.85 + 0.15);
}

export default function EmbeddingHeatmap({
  baseline = [],
  current = [],
  cellSize = 15,
  embeddingDrift = 0,
}) {
  const [tooltip, setTooltip] = useState(null); // { x, y, dim, baseVal, currVal }

  // Pad to 64 if shorter
  const b = [...baseline, ...Array(64).fill(0)].slice(0, 64);
  const c = current.length > 0 ? [...current, ...Array(64).fill(0)].slice(0, 64) : null;

  const gap = 2;
  const totalWidth = 64 * (cellSize + gap);

  // Domain boundary lines (cumulative slots)
  let domainBoundaries = [];
  let cumulative = 0;
  DOMAIN_LABELS.forEach(({ slots }) => {
    domainBoundaries.push(cumulative);
    cumulative += slots;
  });

  function handleMouseEnter(e, dim, baseVal, currVal) {
    const rect = e.currentTarget.getBoundingClientRect();
    setTooltip({ dim, baseVal, currVal, x: rect.left + cellSize / 2, y: rect.top });
  }

  function getDomain(dim) {
    let acc = 0;
    for (const { label, slots } of DOMAIN_LABELS) {
      if (dim < acc + slots) return label;
      acc += slots;
    }
    return 'Unknown';
  }

  const rows = c ? 2 : 1;
  const totalHeight = rows * (cellSize + gap) + (rows > 1 ? 6 : 0);

  return (
    <div className="relative">
      {/* Domain annotations above */}
      <div className="flex mb-1" style={{ width: totalWidth }}>
        {DOMAIN_LABELS.map(({ label, slots }, i) => (
          <div
            key={i}
            className="text-center truncate"
            style={{
              width: slots * (cellSize + gap) - gap,
              marginRight: gap,
              fontSize: '8px',
              color: 'rgba(150,160,180,0.7)',
              fontFamily: 'Inter, monospace',
              fontWeight: 600,
              letterSpacing: '0.04em',
              borderBottom: '1px solid rgba(99,102,241,0.3)',
              paddingBottom: 2,
            }}
          >
            {label}
          </div>
        ))}
      </div>

      {/* Baseline row */}
      <div className="mb-1">
        <div className="flex items-center gap-1 mb-0.5">
          <span style={{ fontSize: 9, color: 'rgba(100,140,220,0.8)', fontFamily: 'Inter, monospace', fontWeight: 700, width: 16 }}>B</span>
          <div className="flex" style={{ gap }}>
            {b.map((val, dim) => (
              <div
                key={dim}
                style={{
                  width: cellSize,
                  height: cellSize,
                  backgroundColor: valueToBaselineColour(val),
                  opacity: opacity(val),
                  borderRadius: 2,
                  cursor: 'pointer',
                  transition: 'transform 0.1s ease, opacity 0.2s ease',
                  border: domainBoundaries.includes(dim) ? '1px solid rgba(99,102,241,0.4)' : 'none',
                }}
                onMouseEnter={(e) => handleMouseEnter(e, dim, val, c ? c[dim] : null)}
                onMouseLeave={() => setTooltip(null)}
                title={`Dim ${dim} | ${getDomain(dim)} | ${val.toFixed(3)}`}
              />
            ))}
          </div>
        </div>

        {/* Row label */}
        {!c && (
          <div className="text-left" style={{ fontSize: 8, color: 'rgba(100,140,220,0.6)', marginLeft: 20, marginTop: 1 }}>
            Baseline Profile
          </div>
        )}
      </div>

      {/* Current session row (if available) */}
      {c && (
        <div>
          <div className="flex items-center gap-1 mb-0.5">
            <span style={{ fontSize: 9, color: embeddingDrift > 0.35 ? '#ef4444' : 'rgba(34,211,238,0.9)', fontFamily: 'Inter, monospace', fontWeight: 700, width: 16 }}>C</span>
            <div className="flex" style={{ gap }}>
              {c.map((val, dim) => {
                const drift = Math.abs(val - b[dim]);
                return (
                  <div
                    key={dim}
                    style={{
                      width: cellSize,
                      height: cellSize,
                      backgroundColor: valueToDriftColour(val, drift),
                      opacity: opacity(val),
                      borderRadius: 2,
                      cursor: 'pointer',
                      transition: 'transform 0.1s ease',
                      border: drift > 0.4
                        ? '1px solid rgba(239,68,68,0.7)'
                        : domainBoundaries.includes(dim)
                          ? '1px solid rgba(99,102,241,0.4)'
                          : 'none',
                      boxShadow: drift > 0.4 ? '0 0 4px rgba(239,68,68,0.4)' : 'none',
                    }}
                    onMouseEnter={(e) => handleMouseEnter(e, dim, b[dim], val)}
                    onMouseLeave={() => setTooltip(null)}
                  />
                );
              })}
            </div>
          </div>
          {/* Legend */}
          <div className="flex items-center gap-4 mt-1" style={{ marginLeft: 20 }}>
            <div className="flex items-center gap-1">
              <div style={{ width: 8, height: 8, backgroundColor: 'rgba(59,130,246,0.7)', borderRadius: 1 }} />
              <span style={{ fontSize: 8, color: 'rgba(130,150,180,0.7)', fontFamily: 'Inter' }}>B = Baseline</span>
            </div>
            <div className="flex items-center gap-1">
              <div style={{ width: 8, height: 8, backgroundColor: 'rgba(34,211,238,0.7)', borderRadius: 1 }} />
              <span style={{ fontSize: 8, color: 'rgba(130,150,180,0.7)', fontFamily: 'Inter' }}>C = Current</span>
            </div>
            <div className="flex items-center gap-1">
              <div style={{ width: 8, height: 8, backgroundColor: 'rgba(239,68,68,0.7)', borderRadius: 1, border: '1px solid rgba(239,68,68,0.9)' }} />
              <span style={{ fontSize: 8, color: 'rgba(239,68,68,0.8)', fontFamily: 'Inter' }}>High drift</span>
            </div>
          </div>
        </div>
      )}

      {/* Tooltip */}
      {tooltip && (
        <div
          className="fixed z-50 pointer-events-none"
          style={{
            left: tooltip.x,
            top: tooltip.y - 72,
            transform: 'translateX(-50%)',
            background: 'rgba(15,20,30,0.95)',
            border: '1px solid rgba(99,102,241,0.4)',
            borderRadius: 6,
            padding: '6px 10px',
            fontSize: 10,
            color: '#d0d8f0',
            fontFamily: 'Inter, monospace',
            whiteSpace: 'nowrap',
            backdropFilter: 'blur(8px)',
            boxShadow: '0 4px 20px rgba(0,0,0,0.5)',
          }}
        >
          <div><span style={{ color: '#818cf8' }}>Dim {tooltip.dim}</span> — {getDomain(tooltip.dim)}</div>
          <div>Baseline: <span style={{ color: '#60a5fa' }}>{tooltip.baseVal.toFixed(4)}</span></div>
          {tooltip.currVal !== null && (
            <>
              <div>Current: <span style={{ color: Math.abs(tooltip.currVal - tooltip.baseVal) > 0.3 ? '#ef4444' : '#34d399' }}>
                {tooltip.currVal.toFixed(4)}
              </span></div>
              <div>Drift: <span style={{ color: Math.abs(tooltip.currVal - tooltip.baseVal) > 0.3 ? '#ef4444' : '#6b7280' }}>
                {Math.abs(tooltip.currVal - tooltip.baseVal).toFixed(4)}
              </span></div>
            </>
          )}
        </div>
      )}
    </div>
  );

  function getDomain(dim) {
    let acc = 0;
    for (const { label, slots } of DOMAIN_LABELS) {
      if (dim < acc + slots) return label;
      acc += slots;
    }
    return 'Unknown';
  }
}
