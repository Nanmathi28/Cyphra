export type QrKind =
  | 'url'
  | 'upi'
  | 'wifi'
  | 'contact'
  | 'email'
  | 'telephone'
  | 'sms'
  | 'text'
  | 'unsupported'
  | 'empty';

export type QrField = { label: string; value: string; sensitive?: boolean };

export type ClassifiedQr = {
  kind: QrKind;
  raw: string;
  title: string;
  message?: string;
  fields: QrField[];
  url?: string;
};

function maskValue(value: string, visible = 2): string {
  const trimmed = value.trim();
  if (trimmed.length <= visible) return '*'.repeat(Math.max(4, trimmed.length));
  return `${trimmed.slice(0, visible)}${'*'.repeat(Math.min(10, trimmed.length - visible))}`;
}

function decodeWifiValue(value: string): string {
  return value.replace(/\\([\\;,:"'])/g, '$1');
}

function parseWifi(raw: string): QrField[] {
  const fields = new Map<string, string>();
  const segments: string[] = [];
  let current = '';
  let escaped = false;
  for (const character of raw.slice(raw.indexOf(':') + 1)) {
    if (escaped) {
      current += `\\${character}`;
      escaped = false;
    } else if (character === '\\') {
      escaped = true;
    } else if (character === ';') {
      segments.push(current);
      current = '';
    } else {
      current += character;
    }
  }
  if (current) segments.push(current);
  for (const item of segments) {
    const separator = item.indexOf(':');
    if (separator > 0) fields.set(item.slice(0, separator).toUpperCase(), decodeWifiValue(item.slice(separator + 1)));
  }
  return [
    { label: 'Network name', value: fields.get('S') || 'Not provided' },
    { label: 'Security', value: fields.get('T') || 'Not specified' },
    { label: 'Password', value: fields.has('P') ? maskValue(fields.get('P') || '') : 'Not provided', sensitive: true },
    { label: 'Hidden network', value: fields.get('H')?.toLowerCase() === 'true' ? 'Yes' : 'No' },
  ];
}

function parseUpi(raw: string): { fields: QrField[]; message: string } {
  try {
    const parsed = new URL(raw);
    const params = parsed.searchParams;
    const payeeId = params.get('pa')?.trim() || '';
    const payeeName = params.get('pn')?.trim() || '';
    const amount = params.get('am')?.trim() || '';
    const validPayeeId = /^[^\s@]+@[^\s@]+$/.test(payeeId);
    const validAmount = !amount || /^\d+(?:\.\d{1,2})?$/.test(amount);
    return {
      fields: [
        { label: 'Payee name', value: payeeName || 'Not provided' },
        { label: 'UPI ID', value: payeeId ? maskValue(payeeId, 2) : 'Not provided', sensitive: true },
        { label: 'Amount', value: amount ? `${params.get('cu') || 'INR'} ${amount}` : 'Not specified' },
        { label: 'Reference', value: params.get('tn')?.trim() || 'Not provided' },
      ],
      message: validPayeeId && validAmount
        ? 'Review these payment details carefully. NIVARA cannot independently verify the recipient identity or guarantee payment safety.'
        : 'Some payment fields are missing or malformed. Do not rely on this QR alone to verify payment details. NIVARA cannot verify the recipient identity or guarantee payment safety.',
    };
  } catch {
    return {
      fields: [{ label: 'Payment data', value: 'Could not parse payment parameters.' }],
      message: 'This UPI payload is malformed. No payment action was taken.',
    };
  }
}

function parseVcard(raw: string): QrField[] {
  const read = (name: string) => {
    const match = raw.match(new RegExp(`^${name}(?:;[^:]*)?:(.*)$`, 'im'));
    return match?.[1]?.trim() || '';
  };
  const email = read('EMAIL');
  const telephone = read('TEL');
  return [
    { label: 'Name', value: read('FN') || read('N') || 'Not provided' },
    { label: 'Organization', value: read('ORG') || 'Not provided' },
    { label: 'Email', value: email ? maskValue(email.split('@')[0], 1) + (email.includes('@') ? `@${email.split('@')[1]}` : '') : 'Not provided', sensitive: true },
    { label: 'Telephone', value: telephone ? maskValue(telephone, 2) : 'Not provided', sensitive: true },
  ];
}

export function classifyQrContent(input: string): ClassifiedQr {
  const raw = input.trim();
  if (!raw) return { kind: 'empty', raw: input, title: 'Empty QR code', fields: [] };

  if (/^https?:\/\//i.test(raw)) {
    try {
      const parsed = new URL(raw);
      if (parsed.hostname && (parsed.protocol === 'http:' || parsed.protocol === 'https:')) {
        return { kind: 'url', raw: input, url: raw, title: 'Web address', fields: [{ label: 'URL', value: raw }] };
      }
    } catch {
      return { kind: 'unsupported', raw: input, title: 'Invalid web address', message: 'This looks like a web address but is not a valid HTTP or HTTPS URL.', fields: [] };
    }
    return { kind: 'unsupported', raw: input, title: 'Invalid web address', message: 'Only complete HTTP and HTTPS addresses can be analyzed.', fields: [] };
  }

  if (/^upi:\/\/pay(?:\?|$)/i.test(raw)) {
    const payment = parseUpi(raw);
    return { kind: 'upi', raw: input, title: 'UPI payment review', fields: payment.fields, message: payment.message };
  }
  if (/^WIFI:/i.test(raw)) return { kind: 'wifi', raw: input, title: 'Wi-Fi network', fields: parseWifi(raw), message: 'NIVARA will not connect to this network. Review the details before using them.' };
  if (/^BEGIN:VCARD(?:\r?\n|$)/i.test(raw)) return { kind: 'contact', raw: input, title: 'Contact card', fields: parseVcard(raw), message: 'Contact details are displayed for review only. NIVARA will not add this contact.' };

  if (/^mailto:/i.test(raw)) {
    try {
      const parsed = new URL(raw);
      const recipient = decodeURIComponent(parsed.pathname);
      return { kind: 'email', raw: input, title: 'Email details', fields: [
        { label: 'Recipient', value: recipient ? maskValue(recipient.split('@')[0], 1) + (recipient.includes('@') ? `@${recipient.split('@')[1]}` : '') : 'Not provided', sensitive: true },
        { label: 'Subject', value: parsed.searchParams.get('subject') || 'Not provided' },
        { label: 'Message', value: parsed.searchParams.get('body') || 'Not provided' },
      ], message: 'NIVARA will not compose or send an email.' };
    } catch {
      return { kind: 'email', raw: input, title: 'Email details', fields: [{ label: 'Decoded content', value: raw }], message: 'The email payload could not be fully parsed. No email was created.' };
    }
  }
  if (/^tel:/i.test(raw)) {
    const number = raw.slice(raw.indexOf(':') + 1);
    return { kind: 'telephone', raw: input, title: 'Telephone number', fields: [{ label: 'Number', value: maskValue(number, 2), sensitive: true }], message: 'NIVARA will not place a call.' };
  }
  if (/^(?:sms|smsto):/i.test(raw)) {
    const payload = raw.slice(raw.indexOf(':') + 1);
    const separator = payload.indexOf(':');
    return { kind: 'sms', raw: input, title: 'Text message details', fields: [
      { label: 'Recipient', value: maskValue(separator < 0 ? payload : payload.slice(0, separator), 2), sensitive: true },
      { label: 'Message', value: separator < 0 ? 'Not provided' : payload.slice(separator + 1) },
    ], message: 'NIVARA will not compose or send a text message.' };
  }

  const scheme = raw.match(/^([a-z][a-z\d+.-]*):/i)?.[1];
  if (scheme) return { kind: 'unsupported', raw: input, title: 'Unsupported QR format', message: `This QR uses the ${scheme}: format. NIVARA can review web addresses and selected common QR formats, but cannot safely interpret this one.`, fields: [{ label: 'Decoded content', value: raw }] };
  return { kind: 'text', raw: input, title: 'Plain text', fields: [{ label: 'Decoded text', value: raw }], message: 'Review the text before acting on it. NIVARA will not open links found in the text.' };
}

export async function analyzeQrOnlyIfUrl<T>(
  content: ClassifiedQr,
  analyze: (url: string) => Promise<T>,
): Promise<T | undefined> {
  if (content.kind !== 'url' || !content.url) return undefined;
  return analyze(content.url);
}
