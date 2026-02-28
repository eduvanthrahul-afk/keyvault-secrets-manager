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

        if (response.status === 401 || response.status === 403) {
            // handle unauthorized
            if (!window.location.pathname.includes('login.html')) {
                // window.location.href = 'login.html';
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
        addMember: (id, email) => ApiClient.request(`/api/projects/${id}/members`, 'POST', { email }),
        removeMember: (id, email) => ApiClient.request(`/api/projects/${id}/members/remove`, 'POST', { email })
    },

    keys: {
        getByProject: (projectId) => ApiClient.request(`/api/projects/${projectId}/keys`),
        create: (data) => ApiClient.request('/api/keys', 'POST', data),
        update: (id, data) => ApiClient.request(`/api/keys/${id}`, 'PUT', data),
        delete: (id) => ApiClient.request(`/api/keys/${id}`, 'DELETE')
    }
};
