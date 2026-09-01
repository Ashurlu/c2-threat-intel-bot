// n8n Code node: Question
// typeVersion: 2

const esc = (s) => String(s ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');

const raw = String($input.first().json.data || '');
const lines = raw.split('\n').filter(l => l.trim() && !l.startsWith('#'));

const counts = { cobalt: 0, havoc: 0, other: 0 };
const otherFamilies = {};

for (const line of lines) {
  const p = line.split(',');
  const ip = (p[0] || '').trim();
  const family = (p[1] || '').trim() || 'Unknown';
  if (!/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip)) continue;

  const f = family.toLowerCase();
  if (f.includes('cobalt')) counts.cobalt++;
  else if (f.includes('havoc')) counts.havoc++;
  else {
    counts.other++;
    otherFamilies[family] = (otherFamilies[family] || 0) + 1;
  }
}

const top = Object.entries(otherFamilies)
  .sort((a, b) => b[1] - a[1]).slice(0, 5)
  .map(([k, v]) => `• ${esc(k)}: ${v}`).join('\n');

const tarix = new Date().toISOString().split('T')[0];
const cem = counts.cobalt + counts.havoc + counts.other;

let text = `<b>C2 feed yükləndi — ${tarix}</b>\n`;
text += `Cobalt Strike: <b>${counts.cobalt}</b>\n`;
text += `Havoc: <i>ThreatFox-dan</i>\n`;
text += `Digər: <b>${counts.other}</b>\n`;
if (top) text += `\n<i>Digər ailələr:</i>\n${top}\n`;
text += `\nHansını analiz edim?\nDüymə bas, ya da yaz: <code>cobalt</code> / <code>havoc</code> / <code>hamısı</code>`;

return [{ json: { text, counts } }];
