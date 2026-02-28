const API_URL = 'http://localhost:8080';

const ApiClient = {
    async request(endpoint, method = 'GET', body = null) {
        const token = localStorage.getItem('jwt_token');
        const headers = {
            'Content-Type': 'application/json'
        };

        if (token) {
            headers['Authorization'] = `Bearer ${token}`;
        }

        const config = {
            method,
            headers
        };

        if (body) {
            config.body = JSON.stringify(body);
        }

        const response = await fetch(`${API_URL}${endpoint}`, config);

        if (response.status === 401) {
            // handle unauthorized
            if (!window.location.pathname.includes('login.html') && !window.location.pathname.includes('register.html')) {
                window.location.href = 'login.html';
                return null;
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
        login: (credentials) => ApiClient.request('/auth/login', 'POST', credentials),
        register: (userData) => ApiClient.request('/auth/register', 'POST', userData),
        refresh: () => ApiClient.request('/auth/refresh', 'POST').then(response => {
            if (response && response.token) {
                localStorage.setItem('jwt_token', response.token);
                localStorage.setItem('user_salt', response.salt);
            }
            return response;
        })
    },

    projects: {
        getAll: () => ApiClient.request('/api/projects'),
        create: (data) => ApiClient.request('/api/projects', 'POST', data),
        update: (id, data) => ApiClient.request(`/api/projects/${id}`, 'PUT', data),
        delete: (id) => ApiClient.request(`/api/projects/${id}`, 'DELETE'),
        getMembers: (id) => ApiClient.request(`/api/projects/${id}/members`),
        addMember: (id, email, role) => ApiClient.request(`/api/projects/${id}/members`, 'POST', { email, role }),
        removeMember: (id, email) => ApiClient.request(`/api/projects/${id}/members/remove`, 'POST', { email }),
        updateMemberRole: (id, email, role) => ApiClient.request(`/api/projects/${id}/members/role`, 'PUT', { email, role }),
        getAuditLogs: (id) => ApiClient.request(`/api/projects/${id}/audit-logs`)
    },

    keys: {
        getByProject: (projectId) => ApiClient.request(`/api/projects/${projectId}/keys`),
        create: (data) => ApiClient.request('/api/keys', 'POST', data),
        update: (id, data) => ApiClient.request(`/api/keys/${id}`, 'PUT', data),
        delete: (id) => ApiClient.request(`/api/keys/${id}`, 'DELETE')
    }
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
                <div class="toast-title">${title}</div>
                <div class="toast-message">${message}</div>
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

            // Close on outside click
            overlay.onclick = (e) => {
                if (e.target === overlay) {
                    overlay.remove();
                    resolve(false);
                }
            };
        });
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
                localStorage.clear();
                sessionStorage.clear();
                if (typeof CryptoModule !== 'undefined' && CryptoModule.clearSessionVault) {
                    await CryptoModule.clearSessionVault();
                }
                window.location.href = 'login.html';
            }
        };
    }
});

