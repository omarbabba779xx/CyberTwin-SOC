// CyberTwin SOC -- k6 API benchmark
//
// Ramps up traffic against /api/health and /api/ingest/event and prints
// per-endpoint p95/p99 latencies. Intended to validate the
// "API p95 < 500 ms" target.
//
// Run:
//   k6 run benchmarks/k6_api_test.js -e BASE=http://localhost:8000 -e TOKEN=$JWT

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Trend } from 'k6/metrics';

const BASE  = __ENV.BASE  || 'http://localhost:8000';
const TOKEN = __ENV.TOKEN || '';

export const options = {
  stages: [
    { duration: '30s', target: 25 },   // ramp up
    { duration: '1m',  target: 50 },   // sustained
    { duration: '30s', target: 0  },   // ramp down
  ],
  thresholds: {
    http_req_duration: ['p(95)<500', 'p(99)<1500'],
    http_req_failed:   ['rate<0.01'],
  },
};

const healthLatency  = new Trend('latency_health',  true);
const ingestLatency  = new Trend('latency_ingest',  true);

const HEADERS = TOKEN
  ? { 'Authorization': `Bearer ${TOKEN}`, 'Content-Type': 'application/json' }
  : { 'Content-Type': 'application/json' };

const SAMPLE_EVENT = {
  System: { EventID: 4625, Computer: 'WS-001', TimeCreated: new Date().toISOString() },
  EventData: { TargetUserName: 'alice', IpAddress: '10.0.0.42' },
};

export default function () {
  // 1. Health (anonymous)
  const r1 = http.get(`${BASE}/api/health`);
  healthLatency.add(r1.timings.duration);
  check(r1, { 'health 200': r => r.status === 200 });

  // 2. Ingestion (auth required)
  if (TOKEN) {
    const r2 = http.post(
      `${BASE}/api/ingest/event`,
      JSON.stringify({ event: SAMPLE_EVENT, source_type: 'windows_event' }),
      { headers: HEADERS },
    );
    ingestLatency.add(r2.timings.duration);
    check(r2, { 'ingest 200': r => r.status === 200 });
  }

  sleep(0.1);
}
