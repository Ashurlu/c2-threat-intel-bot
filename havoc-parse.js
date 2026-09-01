// n8n Code node: Havoc parse
// typeVersion: 2

const resp = $input.first().json;

if (resp.query_status !== 'ok' || !Array.isArray(resp.data)) {
  return [{ json: { ip: null, family: 'Havoc', error: resp.query_status } }];
}

const out = [];
const seen = new Set();

for (const d of resp.data) {
  let ip = d.ioc || '';
  let port = null;

  if (d.ioc_type === 'ip:port') {
    const parts = ip.split(':');
    ip = parts[0];
    port = parts[1];
  } else if (d.ioc_type !== 'ip') {
    continue;   // domain/hash-ları at
  }

  if (!/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip)) continue;
  if (seen.has(ip)) continue;
  seen.add(ip);

  out.push({ json: {
    ip,
    family: d.malware_printable || 'Havoc',
    feedPort: port,
    firstSeen: d.first_seen,
    confidence: d.confidence_level,
    choice: 'havoc',
  }});
}

return out.slice(0, 25);
