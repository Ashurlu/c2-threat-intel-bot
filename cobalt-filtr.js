// n8n Code node: Cobalt filtr
// typeVersion: 2

const choice = $('Choices').first().json.choice;
const raw = String($input.first().json.data || '');
const lines = raw.split('\n').filter(l => l.trim() && !l.startsWith('#'));

const all = [];
for (const line of lines) {
  const p = line.split(',');
  const ip = (p[0] || '').trim();
  const family = (p[1] || '').trim() || 'Unknown';
  if (!/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip)) continue;
  all.push({ ip, family });
}

let sel;
if (choice === 'cobalt')     sel = all.filter(i => i.family.toLowerCase().includes('cobalt'));
else if (choice === 'havoc') sel = all.filter(i => i.family.toLowerCase().includes('havoc'));
else                         sel = all;

if (choice === 'havoc' && sel.length === 0) {
  sel = ['192.236.148.154','198.73.57.171','213.80.120.130','108.20.196.123',
         '141.98.157.64','216.245.176.232','136.175.187.81','136.175.187.101',
         '185.230.185.11'].map(ip => ({ ip, family: 'Havoc C2 (manual)' }));
}

const LIMIT = 25;
return sel.slice(0, LIMIT).map(r => ({
  json: { ...r, choice, totalFound: sel.length }
}));
