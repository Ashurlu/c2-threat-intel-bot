# Havoc / Cobalt Strike C2 Threat-Intel Bot (n8n)

An n8n workflow that lets you query a Telegram bot for live C2 infrastructure
intel (ThreatFox feed + a CSV/GitHub feed), filters it by malware family,
enriches each IP with Shodan InternetDB / ip-api / DNS data, and returns a
formatted report to Telegram.

## Pipeline overview

| # | Node name | Type | Purpose |
|---|-----------|------|---------|
| 1 | `When clicking 'Execute workflow'` | Manual Trigger | Manual test entrypoint |
| 2 | `Telegram Trigger` | Telegram Trigger | Receives `/message` and `callback_query` updates from the bot |
| 3 | `Feed + Cobalt Strike data` | HTTP Request | Pulls the raw C2 IP feed (CSV) |
| 4 | `Question` | Code | Summarizes feed counts (Cobalt/Havoc/other) and prompts the user to pick a family |
| 5 | `send to telegram` | Telegram | Sends the summary + inline keyboard back to the user |
| 6 | `Choices` | Code | Parses the user's reply/button press, enforces an allow-listed Telegram user ID, maps input to `cobalt` / `havoc` / `all` |
| 7 | `Switch` | Switch | Branches the flow based on `choice` |
| 8 | `ThreatFox - Havoc` | HTTP Request | Queries the ThreatFox API for Havoc C2 IOCs |
| 9 | `Havoc parse` | Code | Extracts unique IPs (+ port) from the ThreatFox response |
| 10 | `GitHub - CSV` | HTTP Request | Pulls a secondary Cobalt Strike IP list from a GitHub-hosted CSV |
| 11 | `Cobalt filtr` | Code | Filters the CSV feed by chosen family, with a manual Havoc fallback list |
| 12 | `Enrich` | Code | Enriches each IP via Shodan InternetDB, ip-api.com geolocation, and Google DNS (NS lookup) |
| 13 | `Format` | Code | Builds the final HTML-formatted Telegram report |
| 14 | `Result` | Telegram | Sends the final report |
| 15 | `Send a text message2` | Telegram | Secondary/manual test send node |

## Code nodes

Each `Code` node's JavaScript is extracted into `code-nodes/` for review and
version control:

- `code-nodes/question.js`
- `code-nodes/choices.js`
- `code-nodes/havoc-parse.js`
- `code-nodes/cobalt-filtr.js`
- `code-nodes/enrich.js`
- `code-nodes/format.js`

## Importing back into n8n

1. In n8n: **Workflows → Import from File**.
2. Select `workflow.json`.
3. Re-attach your Telegram credential (`Telegram account`) — credentials are
   never exported in the JSON, only a reference ID/name.

## ⚠️ Before making this repo public

The exported `workflow.json` has a few things hardcoded that you may want to
scrub or move to n8n environment variables / a `.env`-style credential first:

- **Your personal Telegram chat ID** (`2059539236`) appears in the `chatId`
  parameter of the `Send a text message2`, `send to telegram`, and `Result`
  nodes.
- **The same ID is hardcoded as the sole allow-listed user** inside
  `code-nodes/choices.js` (the `ICAZE` array) — this is what restricts who
  can drive the bot.
- The Telegram **credential reference** (`id: 9gISyTx3WlldgqdE`, name
  `Telegram account`) is just a pointer to a credential stored in your n8n
  instance, not the token itself, so that part is safe to publish.

If you want this public, consider replacing the chat ID with a placeholder
(e.g. `YOUR_TELEGRAM_CHAT_ID`) and documenting it as a required config value
instead.
