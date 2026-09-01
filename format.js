// n8n Code node: Format
// typeVersion: 2

const items = $input.all();
const tarix = new Date().toISOString().split('T')[0];

const esc = (s) => String(s == null ? 'N/A' : s)
  .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

const results = items.filter(i => i.json.active === true);

if (results.length === 0) {
  return [{ json: { text: `🔍 <b>C2 Scan — ${tarix}</b>\nAktiv server tapılmadı.` } }];
}

let mesaj = `🚨 <b>Havoc C2 Threat Intel — ${tarix}</b>\n`;
mesaj += `📊 Yoxlanıldı: <b>${items.length}</b> | Aktiv: <b>${results.length}</b>\n\n`;

for (let i = 0; i < Math.min(results.length, 10); i++) {
  const d = results[i].json;
  mesaj += `<b>#${i + 1}</b> — ${esc(d.family)}\n`;
  mesaj += `🌐 IP: <code>${esc(d.ip)}</code>\n`;
  mesaj += `🔌 Portlar: <code>${esc(d.ports)}</code>\n`;
  mesaj += `🔗 Hostname: ${esc(d.hostnames)}\n`;
  mesaj += `🏷 Domen: ${esc(d.domain)}\n`;
  mesaj += `📡 NS: ${esc(d.ns)}\n`;
  mesaj += `🔤 PTR: ${esc(d.ptr)}\n`;
  mesaj += `🏢 ASN/Org: ${esc(d.asn)} — ${esc(d.org)}\n`;
  mesaj += `📍 Yer: ${esc(d.city)}, ${esc(d.country)}\n`;
  mesaj += `⚠️ Vulns: ${esc(d.vulns)}\n`;
  mesaj += `🧩 Tags: ${esc(d.tags)}\n`;
  mesaj += `───────────────\n\n`;
}

if (mesaj.length > 4000) {
  mesaj = mesaj.substring(0, 3900) + '\n\n... <i>davam edir</i>';
}

return [{ json: { text: mesaj } }];
