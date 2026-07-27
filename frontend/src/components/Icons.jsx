/**
 * Shared inline SVG icon set.
 *
 * These replace the emoji glyphs that previously carried visual meaning in the
 * sidebar, landing page feature cards, AI Twin domain panels and status badges.
 * Everything is stroke-based on a 24x24 grid and inherits `currentColor`, so an
 * icon picks up whatever text colour its container sets in either theme.
 *
 * Usage:  <Icon.Shield className="w-5 h-5" />
 */

function Svg({ children, className = 'w-5 h-5', strokeWidth = 1.8, ...rest }) {
    return (
        <svg
            className={className}
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth={strokeWidth}
            strokeLinecap="round"
            strokeLinejoin="round"
            aria-hidden="true"
            {...rest}
        >
            {children}
        </svg>
    );
}

// ─── Navigation ──────────────────────────────────────────────────────

export const Dashboard = (p) => (
    <Svg {...p}>
        <rect x="3" y="3" width="7" height="9" rx="1" />
        <rect x="14" y="3" width="7" height="5" rx="1" />
        <rect x="14" y="12" width="7" height="9" rx="1" />
        <rect x="3" y="16" width="7" height="5" rx="1" />
    </Svg>
);

export const Terminal = (p) => (
    <Svg {...p}>
        <rect x="2.5" y="4" width="19" height="16" rx="2" />
        <path d="M7 10l2.5 2L7 14" />
        <path d="M12.5 15h4.5" />
    </Svg>
);

export const Brain = (p) => (
    <Svg {...p}>
        <path d="M12 5.5a3 3 0 0 0-6 0 3 3 0 0 0-1.5 5.6A3 3 0 0 0 6 16.8a3 3 0 0 0 6 .7z" />
        <path d="M12 5.5a3 3 0 0 1 6 0 3 3 0 0 1 1.5 5.6A3 3 0 0 1 18 16.8a3 3 0 0 1-6 .7z" />
        <path d="M12 5.5v12" />
    </Svg>
);

export const Shield = (p) => (
    <Svg {...p}>
        <path d="M12 3l7.5 3v6c0 4.2-3 7.8-7.5 9-4.5-1.2-7.5-4.8-7.5-9V6z" />
    </Svg>
);

export const ShieldCheck = (p) => (
    <Svg {...p}>
        <path d="M12 3l7.5 3v6c0 4.2-3 7.8-7.5 9-4.5-1.2-7.5-4.8-7.5-9V6z" />
        <path d="M9 12l2.2 2.2L15.5 10" />
    </Svg>
);

export const Users = (p) => (
    <Svg {...p}>
        <circle cx="9" cy="8" r="3.2" />
        <path d="M3.5 20a5.5 5.5 0 0 1 11 0" />
        <path d="M16 5.3a3.2 3.2 0 0 1 0 5.4" />
        <path d="M17.5 14.4a5.5 5.5 0 0 1 3 5.6" />
    </Svg>
);

export const KeyRound = (p) => (
    <Svg {...p}>
        <circle cx="8" cy="12" r="4" />
        <path d="M12 12h9" />
        <path d="M17.5 12v3.5" />
        <path d="M20.5 12v2.5" />
    </Svg>
);

export const Logout = (p) => (
    <Svg {...p}>
        <path d="M14.5 4.5H18a2 2 0 0 1 2 2v11a2 2 0 0 1-2 2h-3.5" />
        <path d="M10 8l-4 4 4 4" />
        <path d="M6 12h9" />
    </Svg>
);

export const Plus = (p) => (
    <Svg {...p}>
        <path d="M12 5v14" />
        <path d="M5 12h14" />
    </Svg>
);

// ─── Theme ───────────────────────────────────────────────────────────

export const Sun = (p) => (
    <Svg {...p}>
        <circle cx="12" cy="12" r="4" />
        <path d="M12 2.5v2M12 19.5v2M2.5 12h2M19.5 12h2M5.3 5.3l1.4 1.4M17.3 17.3l1.4 1.4M18.7 5.3l-1.4 1.4M6.7 17.3l-1.4 1.4" />
    </Svg>
);

export const Moon = (p) => (
    <Svg {...p}>
        <path d="M20 14.5A8.5 8.5 0 0 1 9.5 4a8.5 8.5 0 1 0 10.5 10.5z" />
    </Svg>
);

// ─── Status ──────────────────────────────────────────────────────────

export const Check = (p) => (
    <Svg {...p}>
        <path d="M4.5 12.5l5 5 10-10" />
    </Svg>
);

export const Warning = (p) => (
    <Svg {...p}>
        <path d="M12 4l8.5 15h-17z" />
        <path d="M12 9.5v4" />
        <path d="M12 16.5h.01" />
    </Svg>
);

export const AlertOctagon = (p) => (
    <Svg {...p}>
        <path d="M8.2 3h7.6L21 8.2v7.6L15.8 21H8.2L3 15.8V8.2z" />
        <path d="M12 8v4.5" />
        <path d="M12 16h.01" />
    </Svg>
);

export const Info = (p) => (
    <Svg {...p}>
        <circle cx="12" cy="12" r="9" />
        <path d="M12 11v5.5" />
        <path d="M12 7.8h.01" />
    </Svg>
);

export const Lock = (p) => (
    <Svg {...p}>
        <rect x="4.5" y="10.5" width="15" height="10" rx="2" />
        <path d="M8 10.5V7.5a4 4 0 0 1 8 0v3" />
    </Svg>
);

export const Refresh = (p) => (
    <Svg {...p}>
        <path d="M20 12a8 8 0 1 1-2.4-5.7" />
        <path d="M20 4v4h-4" />
    </Svg>
);

export const Ban = (p) => (
    <Svg {...p}>
        <circle cx="12" cy="12" r="8.5" />
        <path d="M6 18L18 6" />
    </Svg>
);

// ─── Behavioural domains (AI Twin) ───────────────────────────────────

export const Identity = (p) => (
    <Svg {...p}>
        <rect x="2.5" y="5" width="19" height="14" rx="2" />
        <circle cx="8.5" cy="11" r="2.2" />
        <path d="M5 16.2a4 4 0 0 1 7 0" />
        <path d="M15 10h4M15 13.5h4" />
    </Svg>
);

export const Keyboard = (p) => (
    <Svg {...p}>
        <rect x="2.5" y="6" width="19" height="12" rx="2" />
        <path d="M6 9.5h.01M9.5 9.5h.01M13 9.5h.01M16.5 9.5h.01M6 13h.01M18 13h.01" />
        <path d="M9.5 13h5" />
    </Svg>
);

export const Mouse = (p) => (
    <Svg {...p}>
        <rect x="7.5" y="3" width="9" height="18" rx="4.5" />
        <path d="M12 7v3.5" />
    </Svg>
);

export const AppGrid = (p) => (
    <Svg {...p}>
        <rect x="3.5" y="3.5" width="7" height="7" rx="1.5" />
        <rect x="13.5" y="3.5" width="7" height="7" rx="1.5" />
        <rect x="3.5" y="13.5" width="7" height="7" rx="1.5" />
        <rect x="13.5" y="13.5" width="7" height="7" rx="1.5" />
    </Svg>
);

export const Folder = (p) => (
    <Svg {...p}>
        <path d="M3 7.5a2 2 0 0 1 2-2h3.8l2 2.5H19a2 2 0 0 1 2 2v8.5a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z" />
    </Svg>
);

export const Network = (p) => (
    <Svg {...p}>
        <circle cx="12" cy="5" r="2.5" />
        <circle cx="5" cy="19" r="2.5" />
        <circle cx="19" cy="19" r="2.5" />
        <path d="M12 7.5v4.5M12 12l-5.5 4.8M12 12l5.5 4.8" />
    </Svg>
);

// ─── Analytics / reporting ───────────────────────────────────────────

export const Activity = (p) => (
    <Svg {...p}>
        <path d="M3 12.5h3.5l2.5-6 3.5 12 2.5-6H21" />
    </Svg>
);

export const Search = (p) => (
    <Svg {...p}>
        <circle cx="10.5" cy="10.5" r="6.5" />
        <path d="M15.5 15.5L21 21" />
    </Svg>
);

export const Bolt = (p) => (
    <Svg {...p}>
        <path d="M13.5 2.5L5 13.5h5.5L9.5 21.5 19 10h-5.8z" />
    </Svg>
);

export const Clipboard = (p) => (
    <Svg {...p}>
        <rect x="5.5" y="4.5" width="13" height="16" rx="2" />
        <path d="M9.5 4.5V3.2a1 1 0 0 1 1-1h3a1 1 0 0 1 1 1v1.3z" />
    </Svg>
);

export const Download = (p) => (
    <Svg {...p}>
        <path d="M12 3.5v11" />
        <path d="M8 11l4 4 4-4" />
        <path d="M4.5 19.5h15" />
    </Svg>
);

export const Document = (p) => (
    <Svg {...p}>
        <path d="M6 3h7l5 5v13a1 1 0 0 1-1 1H6a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1z" />
        <path d="M13 3v5h5" />
    </Svg>
);

export const Printer = (p) => (
    <Svg {...p}>
        <path d="M7 9V3.5h10V9" />
        <rect x="3.5" y="9" width="17" height="7" rx="2" />
        <path d="M7 14h10v6.5H7z" />
    </Svg>
);

export const Sparkles = (p) => (
    <Svg {...p}>
        <path d="M12 3l1.6 4.4L18 9l-4.4 1.6L12 15l-1.6-4.4L6 9l4.4-1.6z" />
        <path d="M18.5 16.5l.7 1.8 1.8.7-1.8.7-.7 1.8-.7-1.8-1.8-.7 1.8-.7z" />
    </Svg>
);

export const Microscope = (p) => (
    <Svg {...p}>
        <path d="M9 3.5h3l1 6h-5z" />
        <path d="M10.5 9.5a5 5 0 0 1 4 8" />
        <path d="M5 20.5h14" />
        <path d="M7 20.5a5.5 5.5 0 0 1 4-9" />
    </Svg>
);

export const Tools = (p) => (
    <Svg {...p}>
        <path d="M14.5 6.5a3.5 3.5 0 0 1 5 4.6L11 20.5l-3-3 8.5-8.6a3.5 3.5 0 0 1-2-2.4z" />
        <path d="M6.5 3.5l3 3-2 2-3-3z" />
    </Svg>
);

export const Building = (p) => (
    <Svg {...p}>
        <path d="M4 20.5V6l8-3 8 3v14.5" />
        <path d="M9 20.5v-5h6v5" />
        <path d="M8.5 10h2M13.5 10h2" />
    </Svg>
);

export const Cloud = (p) => (
    <Svg {...p}>
        <path d="M7.5 18.5a4 4 0 0 1-.4-8A5.5 5.5 0 0 1 18 11.2a3.7 3.7 0 0 1-.5 7.3z" />
    </Svg>
);

export const Desktop = (p) => (
    <Svg {...p}>
        <rect x="2.5" y="4" width="19" height="12" rx="2" />
        <path d="M9 20h6M12 16v4" />
    </Svg>
);

export const Plug = (p) => (
    <Svg {...p}>
        <path d="M9 3.5v5M15 3.5v5" />
        <path d="M6.5 8.5h11v3a5.5 5.5 0 0 1-11 0z" />
        <path d="M12 17v3.5" />
    </Svg>
);

export const Link = (p) => (
    <Svg {...p}>
        <path d="M10 13.5a3.5 3.5 0 0 0 5 0l3-3a3.5 3.5 0 0 0-5-5l-1 1" />
        <path d="M14 10.5a3.5 3.5 0 0 0-5 0l-3 3a3.5 3.5 0 0 0 5 5l1-1" />
    </Svg>
);

export const HeartBroken = (p) => (
    <Svg {...p}>
        <path d="M12 20.5S3.5 15 3.5 9.2A4.7 4.7 0 0 1 12 6.5a4.7 4.7 0 0 1 8.5 2.7c0 5.8-8.5 11.3-8.5 11.3z" />
        <path d="M12 6.5l-1.8 4.2 3.2 1.6-1.9 3.7" />
    </Svg>
);

export default {
    Dashboard, Terminal, Brain, Shield, ShieldCheck, Users, KeyRound, Logout, Plus,
    Sun, Moon,
    Check, Warning, AlertOctagon, Info, Lock, Refresh, Ban,
    Identity, Keyboard, Mouse, AppGrid, Folder, Network,
    Activity, Search, Bolt, Clipboard, Download, Document, Printer, Sparkles,
    Microscope, Tools, Building, Cloud, Desktop, Plug, Link, HeartBroken,
};
