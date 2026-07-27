import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';

/**
 * Theme provider for the SOC console.
 *
 * Resolution order for the active theme:
 *   1. An explicit choice the operator made previously (localStorage).
 *   2. Otherwise the operating system's `prefers-color-scheme`.
 *   3. Otherwise dark, which is the design default for a SOC terminal.
 *
 * While the operator has NOT made an explicit choice, the console keeps
 * following the OS live — so flipping the OS to light mode flips the console
 * too. The moment they use the toggle, that becomes a pin and the OS is
 * ignored until they reset it via `followSystem()`.
 *
 * The resolved theme is published two ways so both styling strategies work:
 *   - a `dark` class on <html>, for Tailwind's `dark:` variant
 *   - `style.colorScheme`, so native scrollbars, form controls and the
 *     browser's own UI match instead of staying stuck in light mode
 */

const STORAGE_KEY = 'InthreatDetection_theme';
const LIGHT_QUERY = '(prefers-color-scheme: light)';

const ThemeContext = createContext(null);

function readStoredTheme() {
    try {
        const stored = window.localStorage.getItem(STORAGE_KEY);
        return stored === 'dark' || stored === 'light' ? stored : null;
    } catch {
        // localStorage can throw in private-mode / blocked-storage contexts.
        return null;
    }
}

function readSystemTheme() {
    if (typeof window === 'undefined' || !window.matchMedia) return 'dark';
    return window.matchMedia(LIGHT_QUERY).matches ? 'light' : 'dark';
}

function applyTheme(theme) {
    const root = document.documentElement;
    root.classList.toggle('dark', theme === 'dark');
    root.dataset.theme = theme;
    root.style.colorScheme = theme;
}

export function ThemeProvider({ children }) {
    // Seed from storage/OS during the first render so there is no flash of the
    // wrong theme before the first effect runs.
    const [pinned, setPinned] = useState(readStoredTheme);
    const [systemTheme, setSystemTheme] = useState(readSystemTheme);

    const theme = pinned ?? systemTheme;

    // Keep <html> in sync with the resolved theme.
    useEffect(() => {
        applyTheme(theme);
    }, [theme]);

    // Track OS changes. We always listen, but the value only wins when the
    // operator has not pinned a theme.
    useEffect(() => {
        if (!window.matchMedia) return undefined;
        const mq = window.matchMedia(LIGHT_QUERY);
        const onChange = (e) => setSystemTheme(e.matches ? 'light' : 'dark');
        mq.addEventListener('change', onChange);
        return () => mq.removeEventListener('change', onChange);
    }, []);

    // Mirror the pin across browser tabs so two open consoles agree.
    useEffect(() => {
        const onStorage = (e) => {
            if (e.key !== STORAGE_KEY) return;
            setPinned(e.newValue === 'dark' || e.newValue === 'light' ? e.newValue : null);
        };
        window.addEventListener('storage', onStorage);
        return () => window.removeEventListener('storage', onStorage);
    }, []);

    const setTheme = useCallback((next) => {
        if (next !== 'dark' && next !== 'light') return;
        setPinned(next);
        try {
            window.localStorage.setItem(STORAGE_KEY, next);
        } catch {
            // Persistence is best-effort; the in-memory pin still applies.
        }
    }, []);

    const toggleTheme = useCallback(() => {
        setTheme(theme === 'dark' ? 'light' : 'dark');
    }, [theme, setTheme]);

    // Drop the pin and go back to tracking the operating system.
    const followSystem = useCallback(() => {
        setPinned(null);
        try {
            window.localStorage.removeItem(STORAGE_KEY);
        } catch {
            // no-op
        }
        setSystemTheme(readSystemTheme());
    }, []);

    const value = useMemo(() => ({
        theme,
        isDark: theme === 'dark',
        isFollowingSystem: pinned === null,
        setTheme,
        toggleTheme,
        followSystem,
    }), [theme, pinned, setTheme, toggleTheme, followSystem]);

    return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>;
}

export function useTheme() {
    const ctx = useContext(ThemeContext);
    if (!ctx) {
        throw new Error('useTheme must be used inside a <ThemeProvider>');
    }
    return ctx;
}

export default ThemeContext;
