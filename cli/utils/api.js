const axios = require('axios');

const BASE_URL = 'http://localhost:8080/api';
const AUTH_URL = 'http://localhost:8080/auth';

function getClient(token) {
    return axios.create({
        headers: {
            'Authorization': token ? `Bearer ${token}` : '',
            'Content-Type': 'application/json'
        }
    });
}

const api = {
    auth: {
        login: async (email, password) => {
            const res = await axios.post(`${AUTH_URL}/login`, { email, password });
            return res.data;
        },
        getSalt: async (email) => {
            const res = await axios.get(`${AUTH_URL}/salt`, { params: { email } });
            return res.data;
        }
    },
    projects: {
        getAll: async (token) => {
            const res = await getClient(token).get(`${BASE_URL}/projects`);
            return res.data;
        },
        getMembers: async (token, projectId) => {
            const res = await getClient(token).get(`${BASE_URL}/projects/${projectId}/members`);
            return res.data;
        }
    },
    keys: {
        getByProject: async (token, projectId) => {
            const res = await getClient(token).get(`${BASE_URL}/projects/${projectId}/keys`);
            return res.data;
        }
    },
    tokens: {
        verify: async (tokenId, tokenHash, environment = null) => {
            const res = await axios.post(`${BASE_URL}/tokens/verify`, { tokenId, tokenHash, environment });
            return res.data;
        }
    }
};

module.exports = api;
