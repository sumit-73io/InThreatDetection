import React, { useEffect, useRef, useState } from 'react';

/**
 * ThreatGauge — Animated SVG arc gauge for threat score 0–100.
 * Colour transitions: green (0–30) → amber (30–55) → orange (55–75) → red (75–100).
 *
 * Props:
 *   score    — number 0–100
 *   size     — diameter in px (default 160)
 *   label    — optional label below score
 *   animated — boolean, animate on mount/change
 */
export default function ThreatGauge({ score = 0, size = 160, label = 'Threat Score', animated = true }) {
  const [displayScore, setDisplayScore] = useState(0);
  const animFrameRef = useRef(null);
  const startTimeRef = useRef(null);
  const startScoreRef = useRef(0);

  // Colour zones
  function getColour(s) {
    if (s < 30) return '#22c55e';   // green
    if (s < 55) return '#f59e0b';   // amber
    if (s < 75) return '#f97316';   // orange
    return '#ef4444';               // red
  }

  function getGlowColour(s) {
    if (s < 30) return 'rgba(34,197,94,0.4)';
    if (s < 55) return 'rgba(245,158,11,0.4)';
    if (s < 75) return 'rgba(249,115,22,0.4)';
    return 'rgba(239,68,68,0.4)';
  }

  function getSeverityLabel(s) {
    if (s < 30) return 'NORMAL';
    if (s < 55) return 'ELEVATED';
    if (s < 75) return 'HIGH RISK';
    return 'CRITICAL';
  }

  useEffect(() => {
    if (!animated) {
      setDisplayScore(score);
      return;
    }
    const from = startScoreRef.current;
    startScoreRef.current = score;
    const duration = 800; // ms
    startTimeRef.current = performance.now();

    function animate(now) {
      const elapsed = now - startTimeRef.current;
      const t = Math.min(1, elapsed / duration);
      // Ease-out cubic
      const eased = 1 - Math.pow(1 - t, 3);
      setDisplayScore(Math.round(from + (score - from) * eased));
      if (t < 1) {
        animFrameRef.current = requestAnimationFrame(animate);
      }
    }
    if (animFrameRef.current) cancelAnimationFrame(animFrameRef.current);
    animFrameRef.current = requestAnimationFrame(animate);
    return () => cancelAnimationFrame(animFrameRef.current);
  }, [score, animated]);

  // SVG arc parameters
  const strokeWidth = size * 0.08;
  const r = (size - strokeWidth * 2) / 2 - 4;
  const cx = size / 2;
  const cy = size / 2;
  const startAngle = -210; // degrees (bottom-left)
  const endAngle = 30;     // degrees (bottom-right)
  const totalAngle = endAngle - startAngle; // 240 degrees

  function polarToXY(angleDeg, radius) {
    const angleRad = (angleDeg * Math.PI) / 180;
    return {
      x: cx + radius * Math.cos(angleRad),
      y: cy + radius * Math.sin(angleRad),
    };
  }

  function arcPath(fromDeg, toDeg, rad) {
    const from = polarToXY(fromDeg, rad);
    const to = polarToXY(toDeg, rad);
    const largeArc = toDeg - fromDeg > 180 ? 1 : 0;
    return `M ${from.x} ${from.y} A ${rad} ${rad} 0 ${largeArc} 1 ${to.x} ${to.y}`;
  }

  const currentAngle = startAngle + (displayScore / 100) * totalAngle;
  const colour = getColour(displayScore);
  const glowColour = getGlowColour(displayScore);
  const severityLabel = getSeverityLabel(displayScore);

  // Needle tip position
  const needleTip = polarToXY(currentAngle, r * 0.65);
  const needleBase1 = polarToXY(currentAngle - 90, strokeWidth * 0.3);
  const needleBase2 = polarToXY(currentAngle + 90, strokeWidth * 0.3);

  return (
    <div className="flex flex-col items-center gap-1">
      <svg width={size} height={size * 0.85} viewBox={`0 0 ${size} ${size * 0.85}`}>
        <defs>
          <filter id={`glow-${score}`} x="-50%" y="-50%" width="200%" height="200%">
            <feGaussianBlur stdDeviation="3" result="blur" />
            <feComposite in="SourceGraphic" in2="blur" operator="over" />
          </filter>
          <linearGradient id="gaugeTrack" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" stopColor="#22c55e" stopOpacity="0.3" />
            <stop offset="50%" stopColor="#f59e0b" stopOpacity="0.3" />
            <stop offset="100%" stopColor="#ef4444" stopOpacity="0.3" />
          </linearGradient>
        </defs>

        {/* Background track */}
        <path
          d={arcPath(startAngle, endAngle, r)}
          fill="none"
          stroke="rgba(255,255,255,0.06)"
          strokeWidth={strokeWidth}
          strokeLinecap="round"
        />

        {/* Colour zones (decorative) */}
        <path
          d={arcPath(startAngle, startAngle + totalAngle * 0.3, r)}
          fill="none" stroke="rgba(34,197,94,0.15)" strokeWidth={strokeWidth} strokeLinecap="butt"
        />
        <path
          d={arcPath(startAngle + totalAngle * 0.3, startAngle + totalAngle * 0.55, r)}
          fill="none" stroke="rgba(245,158,11,0.15)" strokeWidth={strokeWidth} strokeLinecap="butt"
        />
        <path
          d={arcPath(startAngle + totalAngle * 0.55, startAngle + totalAngle * 0.75, r)}
          fill="none" stroke="rgba(249,115,22,0.15)" strokeWidth={strokeWidth} strokeLinecap="butt"
        />
        <path
          d={arcPath(startAngle + totalAngle * 0.75, endAngle, r)}
          fill="none" stroke="rgba(239,68,68,0.15)" strokeWidth={strokeWidth} strokeLinecap="butt"
        />

        {/* Active arc */}
        {displayScore > 0 && (
          <path
            d={arcPath(startAngle, currentAngle, r)}
            fill="none"
            stroke={colour}
            strokeWidth={strokeWidth}
            strokeLinecap="round"
            style={{ filter: `drop-shadow(0 0 6px ${glowColour})`, transition: 'stroke 0.5s ease' }}
          />
        )}

        {/* Tick marks */}
        {Array.from({ length: 11 }, (_, i) => {
          const tickAngle = startAngle + (i / 10) * totalAngle;
          const outer = polarToXY(tickAngle, r + strokeWidth * 0.5);
          const inner = polarToXY(tickAngle, r - strokeWidth * 0.5);
          return (
            <line
              key={i}
              x1={inner.x} y1={inner.y}
              x2={outer.x} y2={outer.y}
              stroke="rgba(255,255,255,0.15)"
              strokeWidth={i % 5 === 0 ? 2 : 1}
            />
          );
        })}

        {/* Needle */}
        <polygon
          points={`${needleTip.x},${needleTip.y} ${needleBase1.x},${needleBase1.y} ${cx},${cy} ${needleBase2.x},${needleBase2.y}`}
          fill={colour}
          opacity={0.9}
          style={{ filter: `drop-shadow(0 0 4px ${colour})`, transition: 'fill 0.5s ease' }}
        />
        <circle cx={cx} cy={cy} r={strokeWidth * 0.45} fill="#1e222b" stroke={colour} strokeWidth={2} />

        {/* Score text */}
        <text
          x={cx} y={cy * 0.65}
          textAnchor="middle"
          fontSize={size * 0.18}
          fontWeight="800"
          fill={colour}
          fontFamily="Inter, system-ui, sans-serif"
          style={{ transition: 'fill 0.5s ease' }}
        >
          {displayScore}
        </text>
        <text
          x={cx} y={cy * 0.65 + size * 0.14}
          textAnchor="middle"
          fontSize={size * 0.065}
          fontWeight="600"
          fill={colour}
          fontFamily="Inter, system-ui, sans-serif"
          opacity={0.8}
        >
          {severityLabel}
        </text>
      </svg>
      <span
        className="text-xs font-medium tracking-widest uppercase"
        style={{ color: 'rgba(150,160,180,0.7)', letterSpacing: '0.12em' }}
      >
        {label}
      </span>
    </div>
  );
}
