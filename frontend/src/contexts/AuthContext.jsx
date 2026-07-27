import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';
import { getMe } from '../services/api';

/**
 * Identity + authorization state for the console.
 *
 * Two distinct questions this answers, which must not be conflated:
 *
 *   can(perm)        Does my ROLE grant this permission at all?
 *   isElevated(perm) Do I ALSO hold an open PAM elevation window for it?
 *
 * Privileged actions need both. `can()` alone decides whether a control is
 * rendered; `isElevated()` decides whether it is armed or shows a "request
 * elevation" affordance. Rendering a control the operator can never use is
 * confusing, and hiding one they could unlock is worse.
 *
 * This is a UI convenience only. The server enforces the same two checks in
 * `require_permission`; nothing here is a security boundary.
 */

const AuthContext = createContext(null);

// Elevation windows expire on their own, so re-poll often enough that the UI
// does not offer an action that has just gone stale.
const REFRESH_INTERVAL_MS = 20000;

const TOKEN_KEY = 'InthreatDetection_token';

const hasToken = () => {
    try {
        return !!window.localStorage.getItem(TOKEN_KEY);
    } catch {
        return false;
    }
};

export function AuthProvider({ children }) {
    const [principal, setPrincipal] = useState(null);
    const [loading, setLoading] = useState(hasToken);
    const [error, setError] = useState(null);

    const refresh = useCallback(async () => {
        // Skip the round trip entirely when unauthenticated, so the landing and
        // login screens do not fire a guaranteed-401 request on every tick.
        if (!hasToken()) {
            setPrincipal(null);
            setLoading(false);
            return null;
        }
        try {
            const me = await getMe();
            setPrincipal(me);
            setError(null);
            return me;
        } catch (err) {
            // A 401 here means the token expired or was revoked. Surface it as
            // "no principal" rather than throwing, so callers degrade to a
            // read-only view instead of crashing the console.
            setPrincipal(null);
            setError(err?.response?.status === 401 ? 'unauthenticated' : 'unavailable');
            return null;
        } finally {
            setLoading(false);
        }
    }, []);

    useEffect(() => {
        refresh();
        const interval = setInterval(refresh, REFRESH_INTERVAL_MS);
        return () => clearInterval(interval);
    }, [refresh]);

    const value = useMemo(() => {
        const permissions = new Set(principal?.permissions ?? []);
        const elevated = new Set(principal?.elevated_permissions ?? []);

        return {
            principal,
            loading,
            error,
            refresh,

            role: principal?.role ?? null,
            displayName: principal?.display_name ?? null,
            isSuperAdmin: !!principal?.is_super_admin,

            permissions,
            elevatedPermissions: elevated,
            activeElevations: principal?.active_elevations ?? [],

            /** Does the caller's role grant this permission? */
            can: (perm) => permissions.has(perm),

            /** Does the caller hold an open elevation window for this permission? */
            isElevated: (perm) => elevated.has(perm),

            /**
             * Fully authorised right now: role grants it AND (if privileged)
             * an elevation window is open. Pass `privileged: false` for
             * permissions that need no elevation.
             */
            canUseNow: (perm, privileged = true) =>
                permissions.has(perm) && (!privileged || elevated.has(perm)),
        };
    }, [principal, loading, error, refresh]);

    return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
    const ctx = useContext(AuthContext);
    if (!ctx) {
        throw new Error('useAuth must be used inside an <AuthProvider>');
    }
    return ctx;
}

export default AuthContext;
