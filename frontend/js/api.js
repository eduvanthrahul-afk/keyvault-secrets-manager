// Keep local development requests stable even when the HTML is opened from a
// file path, Live Server, or another preview port.
const API_URL = (typeof window !== 'undefined' && window.location.port === '8080')
    ? ''
    : 'http://localhost:8080';

// XSS Shield: Global HTML Entity Escaping Utility
const esc = (str) => {
    if (!str) return '';
    return str.replace(/[&<>"']/g, (m) => ({
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;'
    })[m]);
};

// CSRF Handshake Helper
// XSRF Recovery: Persistent memory for cross-origin sync
let fallbackCsrfToken = null;

const getCookie = (name) => {
    // Priority 1: Direct Cookie access
    let value = "; " + document.cookie;
    let parts = value.split("; " + name + "=");
    if (parts.length === 2) {
        const token = parts.pop().split(";").shift();
        if (token) return token;
    }
    // Priority 2: In-memory fallback (if cookies are blocked by origin)
    if (name === 'XSRF-TOKEN') return fallbackCsrfToken;
    return null;
};

// Premium Notification System
const notifications = {
    showToast(title, message, type = 'success', duration = 4000) {
        let container = document.getElementById('toast-container');
        if (!container) {
            container = document.createElement('div');
            container.id = 'toast-container';
            document.body.appendChild(container);
        }

        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        toast.style.setProperty('--toast-dur', `${duration}ms`);

        const icon = type === 'success' ? 'fa-circle-check' : type === 'error' ? 'fa-circle-xmark' : 'fa-circle-info';

        toast.innerHTML = `
            <div class="toast-icon">
                <i class="fa-solid ${icon}"></i>
            </div>
            <div class="toast-content">
                <div class="toast-title">${esc(title)}</div>
                <div class="toast-message">${esc(message)}</div>
            </div>
            <div class="toast-close" onclick="this.parentElement.remove()">
                <i class="fa-solid fa-xmark"></i>
            </div>
        `;

        container.appendChild(toast);

        setTimeout(() => {
            toast.style.opacity = '0';
            toast.style.transform = 'translateX(20px)';
            setTimeout(() => toast.remove(), 300);
        }, duration);
    },

    confirm(title, message, confirmText = 'Confirm', type = 'danger') {
        return new Promise((resolve) => {
            const overlay = document.createElement('div');
            overlay.className = 'modal-overlay';
            overlay.style.display = 'flex';
            overlay.style.zIndex = '11000';

            const modal = document.createElement('div');
            modal.className = 'modal-content confirm-modal-content fade-in';

            const icon = type === 'danger' ? 'fa-triangle-exclamation' : 'fa-circle-question';

            modal.innerHTML = `
                <div class="confirm-icon-wrap" style="${type !== 'danger' ? 'background: rgba(59, 130, 246, 0.1); color: var(--info); border-color: rgba(59, 130, 246, 0.2);' : ''}">
                    <i class="fa-solid ${icon}"></i>
                </div>
                <h2 class="confirm-modal-title">${title}</h2>
                <div class="confirm-modal-text">${message}</div>
                <div class="confirm-actions">
                    <button class="btn btn-secondary" id="confirm-cancel">Cancel</button>
                    <button class="btn ${type === 'danger' ? 'btn-danger' : 'btn-primary'}" id="confirm-ok" style="${type === 'danger' ? 'background: var(--error); border-color: var(--error);' : ''}">${confirmText}</button>
                </div>
            `;

            overlay.appendChild(modal);
            document.body.appendChild(overlay);

            document.getElementById('confirm-cancel').onclick = () => {
                overlay.remove();
                resolve(false);
            };

            document.getElementById('confirm-ok').onclick = () => {
                overlay.remove();
                resolve(true);
            };

            overlay.onclick = (e) => {
                if (e.target === overlay) {
                    overlay.remove();
                    resolve(false);
                }
            };
        });
    },

    sessionExpired() {
        if (window.isSessionExpiredShowing) return;
        window.isSessionExpiredShowing = true;

        console.warn("[Security] Vault session lock triggered. Initializing restoration gateway...");

        const overlay = document.createElement('div');
        overlay.className = 'modal-overlay';
        overlay.style.cssText = 'display:flex; position:fixed; inset:0; z-index:99999; background:rgba(0,0,0,0.6); backdrop-filter:blur(24px); align-items:center; justify-content:center; padding:24px;';

        overlay.innerHTML = `
            <div class="modal-content confirm-modal-content fade-in" style="opacity:1; transform:scale(1);">
                <div class="confirm-icon-wrap" style="background: rgba(129, 140, 248, 0.1); color: var(--accent-1); border-color: rgba(129, 140, 248, 0.2);">
                    <i class="fa-solid fa-clock-rotate-left"></i>
                </div>
                <h2 class="confirm-modal-title">Session Vault Locked</h2>
                <div class="confirm-modal-text">Your secure cryptographic session has timed out. For your protection, workspace access has been suspended until you re-authenticate.</div>
                <div class="confirm-actions">
                    <button class="btn btn-primary" id="session-login-ok" style="width: 100%; border-radius:12px; padding:12px; font-weight:700;">Return to Access Control</button>
                </div>
            </div>
        `;

        document.body.appendChild(overlay);

        const btn = overlay.querySelector('#session-login-ok');
        if (btn) {
            btn.onclick = async () => {
                const email = localStorage.getItem('user_email');
                localStorage.clear();
                sessionStorage.clear();
                if (email) localStorage.setItem('last_user', email);

                if (typeof CryptoModule !== 'undefined' && CryptoModule.clearSessionVault) {
                    await CryptoModule.clearSessionVault();
                }
                window.location.href = 'login.html';
            };
        }
    }
};

const ApiClient = {
    async request(endpoint, method = 'GET', body = null, isRetry = false) {
        const headers = {
            'Content-Type': 'application/json'
        };

        const config = {
            method,
            headers,
            credentials: 'include'
        };

        const jwtToken = localStorage.getItem('jwt_token');
        if (jwtToken) {
            headers['Authorization'] = `Bearer ${jwtToken}`;
        }

        if (body) {
            config.body = JSON.stringify(body);
        }

        const response = await fetch(`${API_URL}${endpoint}`, config);

        // Security Check: Detect session loss (Blacklisted or Expired token)
        if (response.status === 401) {
            if (!window.location.pathname.includes('login.html') && !window.location.pathname.includes('register.html')) {
                notifications.sessionExpired();
                return null;
            }
        }

        // Security Update: Peek at the response headers to see if server sent a fresh CSRF token
        const serverCsrf = response.headers.get('XSRF-TOKEN') || response.headers.get('xsrf-token');
        if (serverCsrf) {
            console.log("[Security] Vault Registry Sync: Security token materialized from headers.");
            fallbackCsrfToken = serverCsrf;
        }

        // Auto-Recovery: Handle "Forbidden" (403) by retrying after priming the CSRF token
        if (response.status === 403 && !isRetry && method !== 'GET') {
            console.warn("[Security] Vault Encountered Lock: Initiating automated CSRF re-synchronization...");

            try {
                // Use a direct fetch for priming to bypass ApiClient's internal error handling and recursion.
                const syncResponse = await fetch(`${API_URL}/api/projects?_sync=${Date.now()}`, {
                    method: 'GET',
                    credentials: 'include'
                });

                if (syncResponse.ok) {
                    const newToken = syncResponse.headers.get('XSRF-TOKEN') || syncResponse.headers.get('xsrf-token');
                    if (newToken) {
                        console.log("[Security] Sync Successful: Fresh token acquired.");
                        fallbackCsrfToken = newToken;
                    }
                }

                await new Promise(r => setTimeout(r, 200));

                console.log(`[Security] Retrying original ${method} request to ${endpoint}...`);
                return await ApiClient.request(endpoint, method, body, true);
            } catch (syncErr) {
                console.warn("[Security] Background sync attempt failed. Attempting last-resort retry...", syncErr);
                return await ApiClient.request(endpoint, method, body, true);
            }
        }

        if (!response.ok) {
            let errorMsg = `Server error ${response.status}`;
            try {
                const error = await response.json();
                errorMsg = error.message || errorMsg;
            } catch (e) {
                // If not JSON, try to get raw text or just use status code
                const text = await response.text().catch(() => '');
                if (text && text.length < 100) errorMsg += `: ${text}`;
            }
            throw new Error(errorMsg);
        }

        const contentType = response.headers.get('content-type');
        if (response.status === 204 || !contentType || !contentType.includes('application/json')) {
            return null;
        }

        const text = await response.text();
        return text ? JSON.parse(text) : null;
    },

    auth: {
        login: async (credentials) => {
            const res = await ApiClient.request('/auth/login', 'POST', credentials);
            // Proactive Case: Prime CSRF for subsequent API mutations immediately after login
            ApiClient.request('/api/projects', 'GET').catch(() => { });
            return res;
        },
        register: async (userData) => {
            const res = await ApiClient.request('/auth/register', 'POST', userData);
            // Prime token after registration success
            ApiClient.request('/api/projects', 'GET').catch(() => { });
            return res;
        },
        requestOtp: (email) => ApiClient.request('/auth/otp/send', 'POST', { email }),
        verifyOtp: (email, code) => ApiClient.request('/auth/otp/verify', 'POST', { email, code }),
        refresh: () => ApiClient.request('/auth/refresh', 'POST').then(response => {
            if (response) {
                if (response.salt) sessionStorage.setItem('user_salt', response.salt);
                if (response.publicKey) sessionStorage.setItem('public_key', response.publicKey);
                if (response.encryptedPrivateKey) sessionStorage.setItem('encrypted_private_key', response.encryptedPrivateKey);
            }
            return response;
        }),
        logout: () => ApiClient.request('/auth/logout', 'POST'),
        updateIdentity: (data) => ApiClient.request('/auth/identity', 'PUT', data),
        getSalt: (email) => ApiClient.request(`/auth/salt?email=${encodeURIComponent(email)}`, 'GET')
    },

    projects: {
        getAll: () => ApiClient.request('/api/projects'),
        getNotificationSummary: () => ApiClient.request('/api/notifications/summary'),
        create: (data) => ApiClient.request('/api/projects', 'POST', data),
        update: (id, data) => ApiClient.request(`/api/projects/${id}`, 'PUT', data),
        delete: (id) => ApiClient.request(`/api/projects/${id}`, 'DELETE'),
        getMembers: (id) => ApiClient.request(`/api/projects/${id}/members`),
        getPublicKey: (id, email) => ApiClient.request(`/api/projects/${id}/members/public-key?email=${encodeURIComponent(email)}`),
        addMember: (id, email, role, encryptedProjectKey) => ApiClient.request(`/api/projects/${id}/members`, 'POST', { email, role, encryptedProjectKey }),
        removeMember: (id, email) => ApiClient.request(`/api/projects/${id}/members/remove`, 'POST', { email }),
        updateMemberRole: (id, email, role) => ApiClient.request(`/api/projects/${id}/members/role`, 'PUT', { email, role }),
        getAuditLogs: (id, days = 30) => ApiClient.request(`/api/projects/${id}/audit-logs?days=${days}`)
    },

    tokens: {
        getByProject: (projectId) => ApiClient.request(`/api/projects/${projectId}/tokens`),
        create: (projectId, data) => ApiClient.request(`/api/projects/${projectId}/tokens`, 'POST', data),
        delete: (tokenId) => ApiClient.request(`/api/tokens/${tokenId}`, 'DELETE'),
        verify: (data) => ApiClient.request('/api/tokens/verify', 'POST', data)
    },

    keys: {
        getByProject: (projectId) => ApiClient.request(`/api/projects/${projectId}/keys?_cb=${Date.now()}`),
        create: (data) => ApiClient.request('/api/keys', 'POST', data),
        update: (id, data) => ApiClient.request(`/api/keys/${id}`, 'PUT', data),
        delete: (id) => ApiClient.request(`/api/keys/${id}`, 'DELETE'),
        getHistory: (id) => ApiClient.request(`/api/keys/${id}/history`),
        rollback: (id, version) => ApiClient.request(`/api/keys/${id}/rollback/${version}`, 'POST')
    }
};

// Global UI Setup
document.addEventListener('DOMContentLoaded', () => {
    // Populate user email in sidebar
    const emailDisplay = document.getElementById('user-email-display');
    const storedEmail = localStorage.getItem('user_email');
    if (emailDisplay && storedEmail) {
        emailDisplay.textContent = storedEmail;
    }

    // Global Logout Handler
    const logoutBtn = document.getElementById('logout-btn');
    if (logoutBtn) {
        logoutBtn.onclick = async (e) => {
            e.preventDefault();
            const confirmed = await notifications.confirm('Sign Out', 'Are you sure you want to end your security session?', 'Sign Out', 'info');
            if (confirmed) {
                // UI Feedback: Immediate lock to prevent double-clicks
                logoutBtn.disabled = true;
                const originalContent = logoutBtn.innerHTML;
                logoutBtn.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin"></i> <span>Securing...</span>';

                try {
                    await ApiClient.auth.logout();
                } catch (err) {
                    console.error("Server logout failed", err);
                }
                localStorage.clear();
                sessionStorage.clear();
                if (typeof CryptoModule !== 'undefined' && CryptoModule.clearSessionVault) {
                    await CryptoModule.clearSessionVault();
                }

                // Final Redirect to Secure Gateway
                setTimeout(() => window.location.href = 'login.html', 600);
            }
        };
    }

    // Proactive CSRF Priming: Ensures the security handshake is ready before the user clicks a button.
    // We prime the token on every page load to ensure mutations work on the first click.
    if (localStorage.getItem('user_email')) {
        // Activity Shield: Track user interactions for inactivity detection
        let lastActivity = Date.now();
        const activityEvents = ['mousedown', 'mousemove', 'keydown', 'scroll', 'touchstart'];
        activityEvents.forEach(type => {
            document.addEventListener(type, () => { lastActivity = Date.now(); }, { passive: true });
        });

        setTimeout(() => {
            ApiClient.request(`/api/projects?_init=${Date.now()}`, 'GET').catch(() => { }); // Silent priming with cache-buster
        }, 300); // Shorter delay for faster readiness

        // SECURITY HEARTBEAT: High-precision session management
        let lastRefreshAttempt = 0;
        setInterval(async () => {
            const now = Date.now();
            const idleTime = now - lastActivity;
            const fifteenMinutes = 15 * 60 * 1000;
            const thirteenMinutes = 13 * 60 * 1000;

            if (idleTime > fifteenMinutes) {
                console.warn("[Security] Session inactivity threshold reached. Terminating vault access...");
                try {
                    await ApiClient.auth.logout();
                } catch (err) { }
                notifications.sessionExpired();
            } else if (idleTime < thirteenMinutes && (now - lastRefreshAttempt > thirteenMinutes)) {
                // Refresh the token before it expires, but only if the user is active
                lastRefreshAttempt = now;
                console.log("[Security] Session Heartbeat: Extending cryptographic access based on activity.");
                ApiClient.auth.refresh().catch(err => {
                    console.error("[Security] Session refresh fail:", err);
                });
            }
        }, 30000); // Check every 30 seconds for high precision
    }
});

// --- COMMAND PALETTE (Cmd + K) ---
document.addEventListener('DOMContentLoaded', () => {
    // Only run command palette in authorized contexts
    if (!localStorage.getItem('user_email')) return;

    // Create DOM
    const overlay = document.createElement('div');
    overlay.className = 'cmd-overlay';
    overlay.innerHTML = `
        <div class="cmd-palette">
            <div class="cmd-header">
                <i class="fa-solid fa-magnifying-glass"></i>
                <input type="text" class="cmd-input" placeholder="Search workspaces, commands..." autocomplete="off" spellcheck="false" id="cmd-input">
                <div class="cmd-shortcut">ESC</div>
            </div>
            <div class="cmd-list" id="cmd-list">
                <!-- Dynamically populated -->
            </div>
        </div>
    `;
    document.body.appendChild(overlay);

    const input = document.getElementById('cmd-input');
    const list = document.getElementById('cmd-list');

    let allProjectsCmd = [];
    let selectedIndex = 0;
    let currentItems = [];

    // Navigation and Action Commands
    const staticCommands = [
        { id: 'nav-dashboard', title: 'Go to Dashboard', sub: 'Overview of all workspaces', icon: 'fa-house', action: () => window.location.href = 'dashboard.html' },
        { id: 'nav-teams', title: 'Manage Teams', sub: 'Control user access and members', icon: 'fa-user-group', action: () => window.location.href = 'teams.html' },
        { id: 'nav-audit', title: 'View Audit Logs', sub: 'Security events and telemetry', icon: 'fa-shield-halved', action: () => window.location.href = 'audit.html' },
        { id: 'nav-settings', title: 'Account Settings', sub: 'Manage your profile and keys', icon: 'fa-gears', action: () => window.location.href = 'settings.html' },
        { id: 'action-sim-expiry', title: 'Debug: Simulate Session Lock', sub: 'Instantly test restoration UI', icon: 'fa-bug', action: () => notifications.sessionExpired() },
        { id: 'action-logout', title: 'Sign Out', sub: 'Lock vault and end session', icon: 'fa-arrow-right-from-bracket', action: () => document.getElementById('logout-btn')?.click() }
    ];

    const renderList = (searchQuery = '') => {
        list.innerHTML = '';
        currentItems = [];

        const q = searchQuery.toLowerCase();

        // Filter projects
        const matchedProjects = allProjectsCmd.filter(p => !q || p.name.toLowerCase().includes(q) || (p.tag && p.tag.toLowerCase().includes(q)));
        if (matchedProjects.length > 0) {
            const label = document.createElement('div');
            label.className = 'cmd-group-label';
            label.textContent = 'Workspaces';
            list.appendChild(label);

            matchedProjects.forEach(p => {
                currentItems.push({
                    title: p.name,
                    action: () => {
                        sessionStorage.setItem('current_project', JSON.stringify(p));
                        window.location.href = `project.html?id=${p.id}`;
                    }
                });

                const item = document.createElement('div');
                item.className = 'cmd-item';
                item.innerHTML = `
                    <div class="cmd-item-icon"><i class="fa-solid fa-folder-closed"></i></div>
                    <div class="cmd-item-content">
                        <div class="cmd-item-title">${esc(p.name)}</div>
                        <div class="cmd-item-sub">Workspace ${p.tag ? '· ' + esc(p.tag) : ''}</div>
                    </div>
                `;
                list.appendChild(item);
            });
        }

        // Filter commands
        const matchedCommands = staticCommands.filter(c => !q || c.title.toLowerCase().includes(q) || c.sub.toLowerCase().includes(q));
        if (matchedCommands.length > 0) {
            const label = document.createElement('div');
            label.className = 'cmd-group-label';
            label.textContent = 'Navigation & Actions';
            list.appendChild(label);

            matchedCommands.forEach(c => {
                currentItems.push({
                    title: c.title,
                    action: c.action
                });

                const item = document.createElement('div');
                item.className = 'cmd-item';
                item.innerHTML = `
                    <div class="cmd-item-icon"><i class="fa-solid ${c.icon}"></i></div>
                    <div class="cmd-item-content">
                        <div class="cmd-item-title">${c.title}</div>
                        <div class="cmd-item-sub">${c.sub}</div>
                    </div>
                `;
                list.appendChild(item);
            });
        }

        if (currentItems.length === 0) {
            list.innerHTML = `
                <div style="padding: 32px; text-align: center; color: var(--text-muted);">
                    <i class="fa-solid fa-magnifying-glass" style="font-size: 24px; margin-bottom: 12px; opacity: 0.5;"></i>
                    <div>No matching results found</div>
                </div>
            `;
        }

        selectedIndex = 0;
        updateSelection();
    };

    const updateSelection = () => {
        const DOMItems = list.querySelectorAll('.cmd-item');
        DOMItems.forEach((el, index) => {
            if (index === selectedIndex) {
                el.classList.add('selected');
                el.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
            } else {
                el.classList.remove('selected');
            }
        });
    };

    const openPalette = async () => {
        overlay.classList.add('active');
        input.value = '';
        input.focus();

        // Fetch projects quietly if not cached
        if (allProjectsCmd.length === 0) {
            try {
                allProjectsCmd = await ApiClient.projects.getAll();
            } catch (err) { }
        }
        renderList();
    };

    const closePalette = () => {
        overlay.classList.remove('active');
        input.blur();
    };

    // Keyboard Bindings
    document.addEventListener('keydown', (e) => {
        if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
            e.preventDefault();
            if (overlay.classList.contains('active')) {
                closePalette();
            } else {
                openPalette();
            }
        }

        if (!overlay.classList.contains('active')) return;

        if (e.key === 'Escape') {
            e.preventDefault();
            closePalette();
        } else if (e.key === 'ArrowDown') {
            e.preventDefault();
            if (selectedIndex < currentItems.length - 1) selectedIndex++;
            updateSelection();
        } else if (e.key === 'ArrowUp') {
            e.preventDefault();
            if (selectedIndex > 0) selectedIndex--;
            updateSelection();
        } else if (e.key === 'Enter') {
            e.preventDefault();
            if (currentItems[selectedIndex]) {
                currentItems[selectedIndex].action();
                closePalette();
            }
        }
    });

    // Input Binding
    input.addEventListener('input', (e) => renderList(e.target.value));

    // Pointer Bindings
    overlay.addEventListener('click', (e) => {
        if (e.target === overlay) closePalette();
    });

    list.addEventListener('mouseover', (e) => {
        const item = e.target.closest('.cmd-item');
        if (item) {
            const DOMItems = Array.from(list.querySelectorAll('.cmd-item'));
            const idx = DOMItems.indexOf(item);
            if (idx !== -1 && idx !== selectedIndex) {
                selectedIndex = idx;
                updateSelection();
            }
        }
    });

    list.addEventListener('click', (e) => {
        const item = e.target.closest('.cmd-item');
        if (item) {
            if (currentItems[selectedIndex]) {
                currentItems[selectedIndex].action();
                closePalette();
            }
        }
    });
});

