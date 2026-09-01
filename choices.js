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
const ICAZE = [2059539236];
if (!ICAZE.includes(Number(userId))) {
  return [{ json: { choice: 'denied', chatId, callbackId } }];
}

const s = raw.toLowerCase().trim().replace(/^\//, '');
let choice = 'unknown';
if (s.includes('cobalt') || s === 'cs' || s === '1') choice = 'cobalt';
else if (s.includes('havoc') || s === '2') choice = 'havoc';
else if (s.includes('ham') || s.includes('all') || s === '3') choice = 'all';

return [{ json: { choice, chatId, callbackId, rawInput: raw } }];
