// CyberTwin SOC - k6 HTTP API load test
//
// Run:
//   k6 run -e BASE_URL=http://localhost:8000 \
//          -e CYBERTWIN_TOKEN=<JWT> \
//          --vus 50 --duration 60s \
//          benchmarks/k6_api.js
//
// Output (with --summary-export=results.json) is consumed by
// benchmarks/results/k6-api-p95.md.

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Trend, Counter } from 'k6/metrics';

const BASE_URL = __ENV.BASE_URL || 'http://localhost:8000';
const TOKEN = __ENV.CYBERTWIN_TOKEN || '';
const HEADERS = TOKEN ? { Authorization: `Bearer ${TOKEN}` } : {};

const healthLatency = new Trend('health_latency', true);
const meLatency = new Trend('me_latency', true);
const alertsLatency = new Trend('alerts_latency', true);
const errors = new Counter('http_errors');

export const options = {
    stages: [
        { duration: '15s', target: 25 },   // ramp up
        { duration: '60s', target: 50 },   // steady state
        { duration: '15s', target: 0 },    // ramp down
    ],
    thresholds: {
        http_req_duration: ['p(95)<500'],   // 95% of requests under 500 ms
        http_req_failed: ['rate<0.01'],     // < 1% errors
        http_errors: ['count<10'],
    },
};

export default function () {
    // 1. Health endpoint (no auth, should be fast)
    let res = http.get(`${BASE_URL}/api/health`);
    healthLatency.add(res.timings.duration);
    if (!check(res, { 'health 200': (r) => r.status === 200 })) errors.add(1);

    if (TOKEN) {
        // 2. /api/auth/me (auth, light)
        res = http.get(`${BASE_URL}/api/auth/me`, { headers: HEADERS });
        meLatency.add(res.timings.duration);
        if (!check(res, { 'me 200': (r) => r.status === 200 })) errors.add(1);

        // 3. /api/alerts (auth, heavy DB read)
        res = http.get(`${BASE_URL}/api/alerts?limit=20`, { headers: HEADERS });
        alertsLatency.add(res.timings.duration);
        if (!check(res, { 'alerts 200': (r) => r.status === 200 })) errors.add(1);
    }

    sleep(1);
}
