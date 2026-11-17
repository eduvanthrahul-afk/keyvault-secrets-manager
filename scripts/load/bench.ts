// Dependency-free closed-loop benchmark (Node fetch with keep-alive). Same scenarios as k6.js,
// for machines without k6. Usage: npm run load:bench [-- seconds concurrency]
import { readFileSync } from 'node:fs';

const seed = JSON.parse(readFileSync(new URL('./.seed.json', import.meta.url), 'utf8'));
const seconds = Number(process.argv[2] ?? 30);
const concurrency = Number(process.argv[3] ?? 32);

async function scenario(name: string, path: string, headers: Record<string, string>) {
  const latencies: number[] = [];
  let errors = 0;
  const end = performance.now() + seconds * 1000;
  // warm-up
  for (let i = 0; i < 50; i++) await (await fetch(seed.baseUrl + path, { headers })).arrayBuffer();
  const t0 = performance.now();
  await Promise.all(Array.from({ length: concurrency }, async () => {
    while (performance.now() < end) {
      const s = performance.now();
      try {
        const r = await fetch(seed.baseUrl + path, { headers });
        await r.arrayBuffer();
        if (r.status !== 200) errors++;
      } catch {
        errors++;
      }
      latencies.push(performance.now() - s);
    }
  }));
  const elapsed = (performance.now() - t0) / 1000;
  latencies.sort((a, b) => a - b);
  const p = (q: number) => latencies[Math.min(latencies.length - 1, Math.floor(q * latencies.length))]!.toFixed(1);
  return { scenario: name, requests: latencies.length, rps: Math.round(latencies.length / elapsed), p50: p(0.5), p95: p(0.95), p99: p(0.99), errors };
}

const results = [
  await scenario('CI token fetch (60 secrets)', '/api/v1/service/secrets', { Authorization: seed.serviceAuthorization }),
  await scenario('Developer list (60 secrets)', `/api/environments/${seed.environmentId}/secrets`, { Cookie: seed.cookie }),
];
console.log(`\n${seconds}s per scenario, ${concurrency} concurrent connections\n`);
console.table(results);
