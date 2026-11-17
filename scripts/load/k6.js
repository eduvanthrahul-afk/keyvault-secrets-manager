// k6 load test: the two hot paths of a secrets manager.
//   1. CI/CD fetching an environment with an access token  (GET /api/v1/service/secrets)
//   2. A signed-in developer listing secrets               (GET /api/environments/{id}/secrets)
// Seed first:  npm run load:seed  (writes scripts/load/.seed.json)
// Then:        k6 run scripts/load/k6.js     or   docker run --rm -i --network host -v "$PWD:/w" -w /w grafana/k6 run scripts/load/k6.js
import http from 'k6/http';
import { check } from 'k6';

const seed = JSON.parse(open('./.seed.json'));
const BASE = __ENV.KEYVAULT_URL || seed.baseUrl;

export const options = {
  scenarios: {
    ci_token_fetch: { executor: 'constant-arrival-rate', rate: 150, timeUnit: '1s', duration: '60s', preAllocatedVUs: 50, exec: 'tokenFetch' },
    developer_list: { executor: 'constant-arrival-rate', rate: 50, timeUnit: '1s', duration: '60s', preAllocatedVUs: 20, exec: 'userList' },
  },
  thresholds: {
    'http_req_failed': ['rate<0.01'],
    'http_req_duration{scenario:ci_token_fetch}': ['p(95)<150'],
    'http_req_duration{scenario:developer_list}': ['p(95)<200'],
  },
};

export function tokenFetch() {
  const r = http.get(`${BASE}/api/v1/service/secrets`, { headers: { Authorization: seed.serviceAuthorization } });
  check(r, { 'token fetch 200': (x) => x.status === 200 });
}

export function userList() {
  const r = http.get(`${BASE}/api/environments/${seed.environmentId}/secrets`, { headers: { Cookie: seed.cookie } });
  check(r, { 'list 200': (x) => x.status === 200 });
}
