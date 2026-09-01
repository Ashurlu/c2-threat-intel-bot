# Havoc / Cobalt Strike C2 Threat-Intel Telegram Bot (n8n)

An n8n workflow that runs as a Telegram bot for on-demand C2 (command &
control) infrastructure threat intel. You message the bot, it pulls a live
IP feed (ThreatFox + a CSV feed of Cobalt Strike/Havoc IPs), lets you pick
which malware family to investigate, enriches each IP with open-source
recon data (Shodan InternetDB, ip-api.com geolocation, Google DNS), and
sends back a formatted report.

This repo contains the exported n8n workflow (`workflow.json`) plus each
`Code` node's JavaScript pulled out into its own file under `code-nodes/`
for easier reading, diffing, and reuse outside of n8n.

---
<img width="1348" height="447" alt="Screenshot 2026-09-02 002352" src="https://github.com/user-attachments/assets/f02b22fd-5fea-46e5-892e-e031000314a0" />

## How it works, node by node

The workflow has two entry points: a manual test trigger, and a Telegram
trigger that reacts to messages/button presses. From there it walks through
filtering, enrichment, and reporting.

### 1. `When clicking 'Execute workflow'` — Manual Trigger
Lets you run the workflow by hand from the n8n editor for testing, instead
of waiting for a real Telegram message.

### 2. `Telegram Trigger` — Telegram Trigger node
Listens for incoming Telegram `message` and `callback_query` (button press)
updates from your bot. This is the real-world entry point once the bot is
live.

### 3. `Feed + Cobalt Strike data` — HTTP Request
Pulls a public C2 IP feed (CSV of Cobalt Strike / Havoc IPs) from
`raw.githubusercontent.com/drb-ra/C2IntelFeeds`.

### 4. `Question` — Code node
Parses the raw CSV feed, tallies how many IPs belong to Cobalt Strike vs.
Havoc vs. other families, and builds an HTML-formatted Telegram summary
message asking the user which family to investigate.

```javascript
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
```

### 5. `send to telegram` — Telegram node
Sends the summary text from step 4, along with an inline keyboard (buttons
for "Cobalt", "Havoc", "Hamısı"/All), back to the chat.

### 6. `Choices` — Code node
Parses whatever the user typed or clicked. Enforces an allow-list of
Telegram user IDs so random people who find the bot can't drive it, then
normalizes the input into a `choice` of `cobalt`, `havoc`, or `all`.

```javascript
// n8n Code node: Choices
// typeVersion: 2

const u = $input.first().json;
let raw = '', chatId = null, callbackId = null, userId = null;

if (u.callback_query) {
  raw = u.callback_query.data || '';
  chatId = u.callback_query.message.chat.id;
  callbackId = u.callback_query.id;
  userId = u.callback_query.from.id;
} else if (u.message) {
  raw = u.message.text || '';
  chatId = u.message.chat.id;
  userId = u.message.from.id;
}

// Yalnız sən istifadə edə biləsən
const ICAZE = [123456789]; // <-- replace 123456789 with your own numeric Telegram user ID
if (!ICAZE.includes(Number(userId))) {
  return [{ json: { choice: 'denied', chatId, callbackId } }];
}

const s = raw.toLowerCase().trim().replace(/^\//, '');
let choice = 'unknown';
if (s.includes('cobalt') || s === 'cs' || s === '1') choice = 'cobalt';
else if (s.includes('havoc') || s === '2') choice = 'havoc';
else if (s.includes('ham') || s.includes('all') || s === '3') choice = 'all';

return [{ json: { choice, chatId, callbackId, rawInput: raw } }];
```

> **Setup note:** replace `123456789` in the `ICAZE` array with your own
> numeric Telegram user ID (you can get this from a bot like `@userinfobot`).
> Without this, nobody — including you — will be authorized to use the bot
> until you set it.

### 7. `Switch` — Switch node
Branches the flow based on the `choice` value produced by step 6:
`havoc` → ThreatFox branch, `cobalt`/`other` → GitHub CSV branch, anything
else → falls through to a fallback message.

### 8. `ThreatFox - Havoc` — HTTP Request
Queries the [ThreatFox](https://threatfox.abuse.ch/) API for Havoc C2 IOCs
(`malware: win.havoc`).

> **Setup note:** this node sends an `Auth-Key` header. Get a free API key
> from ThreatFox and paste it in where the workflow currently has
> `YOUR_THREATFOX_API_KEY`.

### 9. `Havoc parse` — Code node
Extracts unique IPs (and ports, when present) from the ThreatFox API
response, filtering out anything that isn't a valid IPv4 address.

```javascript
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
```

### 10. `GitHub - CSV` — HTTP Request
A second pull of the same CSV feed used in step 3, feeding the
Cobalt-Strike-specific branch of the workflow.

### 11. `Cobalt filtr` — Code node
Filters the CSV feed down to whichever family the user picked. Includes a
small manual fallback list of known Havoc IPs in case the live feed comes
back empty for that family.

```javascript
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
```

### 12. `Enrich` — Code node
The core recon step. For each candidate IP it:
- Queries **Shodan InternetDB** (no API key required) for open ports,
  hostnames, known vulnerabilities, and tags.
- Queries **ip-api.com** for reverse DNS (PTR), ASN, organization, and
  geolocation.
- Resolves the **NS records** of the associated domain via Google's DNS
  API, to help spot bulletproof/fast-flux hosting.
- Rate-limits itself (1.5s between IPs) to stay under ip-api's free-tier
  limit.

```javascript
// n8n Code node: Enrich
// typeVersion: 2

const items = $input.all();
const out = [];

const sleep = (ms) => new Promise(r => setTimeout(r, ms));

for (const item of items) {
  const ip = item.json.ip;
  const family = item.json.family || 'Unknown';

  let ports = [], hostnames = [], vulns = [], cpes = [], tags = [];

  // 1) Shodan InternetDB — açar tələb etmir, port/hostname/vuln verir
  try {
    const db = await this.helpers.httpRequest({
      method: 'GET',
      url: `https://internetdb.shodan.io/${ip}`,
      json: true,
      timeout: 10000,
    });
    ports     = db.ports     || [];
    hostnames = db.hostnames || [];
    vulns     = db.vulns     || [];
    cpes      = db.cpes      || [];
    tags      = db.tags      || [];
  } catch (e) {
    // 404 = InternetDB-də qeyd yoxdur, normaldır
  }

  // 2) ip-api.com — PTR, ASN, ölkə, org
  let ptr = 'N/A', country = 'N/A', city = 'N/A', org = 'N/A', asn = 'N/A';
  try {
    const geo = await this.helpers.httpRequest({
      method: 'GET',
      url: `http://ip-api.com/json/${ip}?fields=status,country,city,isp,org,as,reverse,query`,
      json: true,
      timeout: 10000,
    });
    if (geo.status === 'success') {
      ptr     = geo.reverse || 'N/A';
      country = geo.country || 'N/A';
      city    = geo.city    || 'N/A';
      org     = geo.org || geo.isp || 'N/A';
      asn     = geo.as      || 'N/A';
    }
  } catch (e) {}

  // 3) Nameserver-lər — hostname varsa, domenin NS qeydlərini çək
  let domain = 'N/A', ns = 'N/A';
  const source = hostnames.length ? hostnames[0] : (ptr !== 'N/A' ? ptr : null);
  if (source) {
    domain = source.split('.').slice(-2).join('.');
    try {
      const dns = await this.helpers.httpRequest({
        method: 'GET',
        url: `https://dns.google/resolve?name=${domain}&type=NS`,
        json: true,
        timeout: 10000,
      });
      if (dns.Answer && dns.Answer.length) {
        ns = dns.Answer.map(a => a.data.replace(/\.$/, '')).join(', ');
      }
    } catch (e) {}
  }

  out.push({
    json: {
      ip,
      family,
      ports:     ports.length     ? ports.join(', ')          : 'N/A',
      hostnames: hostnames.length ? hostnames.join(', ')      : 'N/A',
      domain,
      ns,
      ptr,
      vulns:     vulns.length     ? vulns.slice(0, 8).join(', ') : 'N/A',
      cpes:      cpes.length      ? cpes.slice(0, 5).join(', ')  : 'N/A',
      tags:      tags.length      ? tags.join(', ')           : 'N/A',
      country, city, org, asn,
      active: ports.length > 0,
    }
  });

  await sleep(1500); // ip-api limiti: 45 sorğu/dəqiqə
}

return out;
```

### 13. `Format` — Code node
Takes the enriched results, keeps only IPs that showed active ports, and
builds the final HTML-formatted Telegram report (top 10 results, truncated
if it would exceed Telegram's 4096-character message limit).

```javascript
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
```

### 14. `Result` — Telegram node
Sends the final report from step 13 back to the chat.

### 15. `Send a text message2` — Telegram node
A secondary send node used by the `Switch` node's fallback branch (e.g. for
an unrecognized choice).

---

## Setup: importing into your own n8n instance

1. In n8n: **Workflows → Import from File**, and select `workflow.json`.
2. Create a **Telegram credential** (n8n → Credentials → New → Telegram
   API) using your bot token from [@BotFather](https://t.me/BotFather), and
   attach it to the four Telegram nodes (`Telegram Trigger`,
   `send to telegram`, `Send a text message2`, `Result`).
3. Replace the placeholders left in the workflow:
   - `YOUR_TELEGRAM_CHAT_ID` (in the three Telegram-send nodes) — your
     personal or group chat ID.
   - `123456789` inside the `Choices` code node's `ICAZE` array — your
     numeric Telegram **user** ID (not the same as chat ID) — this is what
     actually restricts who can drive the bot.
   - `YOUR_THREATFOX_API_KEY` in the `ThreatFox - Havoc` node's `Auth-Key`
     header — get a free key from
     [threatfox.abuse.ch](https://threatfox.abuse.ch/).
4. Activate the workflow so the Telegram Trigger's webhook goes live.

## Repo contents

```
.
├── README.md
├── workflow.json          # full n8n workflow, secrets replaced with placeholders
└── code-nodes/
    ├── question.js
    ├── choices.js
    ├── havoc-parse.js
    ├── cobalt-filtr.js
    ├── enrich.js
    └── format.js
```

## Data sources used

- [ThreatFox](https://threatfox.abuse.ch/) (abuse.ch) — malware C2 IOC feed
- [drb-ra/C2IntelFeeds](https://github.com/drb-ra/C2IntelFeeds) — public
  Cobalt Strike / C2 IP CSV feed
- [Shodan InternetDB](https://internetdb.shodan.io/) — free, no-key-required
  host recon
- [ip-api.com](https://ip-api.com/) — free IP geolocation/ASN lookup
- [Google Public DNS-over-HTTPS](https://developers.google.com/speed/public-dns/docs/doh)
  — NS record lookups

## Disclaimer

This tooling is intended for **defensive threat-intelligence purposes** —
identifying and tracking known-malicious C2 infrastructure using public
threat feeds. All IP/IOC data comes from public, community-maintained
threat-intel sources (ThreatFox, C2IntelFeeds), not from any offensive
capability of this workflow itself.
