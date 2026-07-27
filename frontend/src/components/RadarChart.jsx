import React, { useEffect, useRef } from 'react';

/**
 * RadarChart — Pure SVG radar chart with two polygons (baseline vs current session).
 * No dependencies. Animates on data change.
 *
 * Props:
 *   domains    — array of label strings (7 domains)
 *   baseline   — array of values 0–10 (one per domain)
 *   current    — array of values 0–10 (one per domain)
 *   size       — canvas size in px (default 280)
 */
export default function RadarChart({ domains = [], baseline = [], current = [], size = 280 }) {
  const canvasRef = useRef(null);
  const animRef = useRef(null);
  const progressRef = useRef(0);
  const prevCurrentRef = useRef(current.map(() => 0));

  const center = size / 2;
  const radius = (size / 2) * 0.70;
  const levels = 5; // concentric rings
  const n = domains.length;

  function getPoint(value, index, maxVal = 10) {
    const angle = (Math.PI * 2 * index) / n - Math.PI / 2;
    const r = (value / maxVal) * radius;
    return {
      x: center + r * Math.cos(angle),
      y: center + r * Math.sin(angle),
    };
  }

  function polygonPath(values, maxVal = 10) {
    if (!values || values.length === 0) return '';
    return values.map((v, i) => {
      const pt = getPoint(v, i, maxVal);
      return `${i === 0 ? 'M' : 'L'}${pt.x.toFixed(2)},${pt.y.toFixed(2)}`;
    }).join(' ') + ' Z';
  }

  function gridPath(level) {
    const r = ((level + 1) / levels) * radius;
    return Array.from({ length: n }, (_, i) => {
      const angle = (Math.PI * 2 * i) / n - Math.PI / 2;
      const x = center + r * Math.cos(angle);
      const y = center + r * Math.sin(angle);
      return `${i === 0 ? 'M' : 'L'}${x.toFixed(2)},${y.toFixed(2)}`;
    }).join(' ') + ' Z';
  }

  // Interpolate current values from previous for animation
  function lerp(a, b, t) { return a + (b - a) * t; }

  return (
    <svg
      width={size}
      height={size}
      viewBox={`0 0 ${size} ${size}`}
      className="overflow-visible"
      style={{ filter: 'drop-shadow(0 0 12px rgba(99,102,241,0.3))' }}
    >
      {/* Grid rings */}
      {Array.from({ length: levels }, (_, i) => (
        <path
          key={`ring-${i}`}
          d={gridPath(i)}
          fill="none"
          stroke="rgba(99,102,241,0.15)"
          strokeWidth="1"
        />
      ))}

      {/* Axis lines */}
      {domains.map((_, i) => {
        const outer = getPoint(10, i, 10);
        return (
          <line
            key={`axis-${i}`}
            x1={center}
            y1={center}
            x2={outer.x}
            y2={outer.y}
            stroke="rgba(99,102,241,0.2)"
            strokeWidth="1"
          />
        );
      })}

      {/* Baseline polygon (blue) */}
      {baseline.length > 0 && (
        <>
          <path
            d={polygonPath(baseline)}
            fill="rgba(59,130,246,0.12)"
            stroke="rgba(59,130,246,0.6)"
            strokeWidth="1.5"
            strokeDasharray="4 2"
            className="transition-all duration-700 ease-in-out"
          />
          {baseline.map((v, i) => {
            const pt = getPoint(v, i);
            return (
              <circle
                key={`baseline-dot-${i}`}
                cx={pt.x}
                cy={pt.y}
                r={3}
                fill="#3b82f6"
                opacity={0.7}
              />
            );
          })}
        </>
      )}

      {/* Current polygon (red/cyan gradient) */}
      {current.length > 0 && (
        <>
          <defs>
            <radialGradient id="currentFill" cx="50%" cy="50%" r="50%">
              <stop offset="0%" stopColor="rgba(239,68,68,0.25)" />
              <stop offset="100%" stopColor="rgba(239,68,68,0.05)" />
            </radialGradient>
          </defs>
          <path
            d={polygonPath(current)}
            fill="url(#currentFill)"
            stroke="rgba(239,68,68,0.85)"
            strokeWidth="2"
            className="transition-all duration-700 ease-in-out"
          />
          {current.map((v, i) => {
            const pt = getPoint(v, i);
            const isDeviated = baseline[i] !== undefined && Math.abs(v - baseline[i]) > 2;
            return (
              <circle
                key={`current-dot-${i}`}
                cx={pt.x}
                cy={pt.y}
                r={isDeviated ? 5 : 3.5}
                fill={isDeviated ? '#ef4444' : '#f97316'}
                stroke={isDeviated ? 'rgba(239,68,68,0.4)' : 'none'}
                strokeWidth={isDeviated ? 3 : 0}
              >
                {isDeviated && (
                  <animate
                    attributeName="r"
                    values="5;7;5"
                    dur="1.5s"
                    repeatCount="indefinite"
                  />
                )}
              </circle>
            );
          })}
        </>
      )}

      {/* Domain labels */}
      {domains.map((label, i) => {
        const angle = (Math.PI * 2 * i) / n - Math.PI / 2;
        const labelRadius = radius * 1.22;
        const x = center + labelRadius * Math.cos(angle);
        const y = center + labelRadius * Math.sin(angle);
        const isDeviated = current[i] !== undefined && baseline[i] !== undefined
          && Math.abs(current[i] - baseline[i]) > 2;

        return (
          <text
            key={`label-${i}`}
            x={x}
            y={y}
            textAnchor="middle"
            dominantBaseline="middle"
            fontSize="9.5"
            fontWeight={isDeviated ? '700' : '500'}
            fill={isDeviated ? '#ef4444' : 'rgba(180,190,210,0.9)'}
            fontFamily="Inter, system-ui, sans-serif"
          >
            {label}
          </text>
        );
      })}

      {/* Level value labels (0, 2, 4, 6, 8, 10) */}
      {Array.from({ length: levels }, (_, i) => {
        const val = ((i + 1) / levels) * 10;
        const y = center - ((i + 1) / levels) * radius;
        return (
          <text
            key={`level-${i}`}
            x={center + 3}
            y={y}
            fontSize="7"
            fill="rgba(120,130,150,0.6)"
            fontFamily="Inter, system-ui, sans-serif"
          >
            {val.toFixed(0)}
          </text>
        );
      })}
    </svg>
  );
}
