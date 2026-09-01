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
