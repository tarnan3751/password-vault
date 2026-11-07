// Strict JSON scanner for the plaintext of meta / item / roster boxes
// (crypto.md §5.3). JSON.parse cannot be used: it accepts duplicate members,
// rounds big integers, drops the raw text of unknown members, and cannot tell
// a lone-surrogate escape from a character. This scanner validates the text
// and splits an object into (raw key text, raw value text) members so that
// unknown members can be carried over BYTE FOR BYTE.
//
// It works on a JS string obtained from STRICT UTF-8 decoding (invalid bytes
// and encoded surrogates are rejected before scanning), so every character it
// sees is a valid Unicode scalar value. It is iterative: nesting depth is
// unlimited and cannot overflow the call stack.

/** The plaintext violates the decoding rules; callers show the entry as unreadable. */
export class UnreadableError extends Error {
  constructor(why: string) {
    super(`unreadable: ${why}`);
    this.name = 'UnreadableError';
  }
}

export const MAX_SAFE_INT = Number.MAX_SAFE_INTEGER; // 2^53 - 1

export interface RawMember {
  /** decoded key (escapes resolved), used for matching */
  key: string;
  /** the key exactly as written, quotes included */
  rawKey: string;
  /** the value exactly as written, from its first to its last character */
  value: string;
}

/** An unknown top-level member, kept as raw text (spec §5.3, README "Canonical encoding"). */
export interface ExtraMember {
  rawKey: string;
  rawValue: string;
}

const strictUtf8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

/** Strict UTF-8: rejects invalid sequences, overlongs and encoded surrogates; keeps a BOM (the scanner then rejects it). */
export function decodeUtf8Strict(b: Uint8Array): string {
  try {
    return strictUtf8.decode(b);
  } catch {
    throw new UnreadableError('not valid UTF-8');
  }
}

class Scanner {
  readonly s: string;
  i = 0;
  constructor(s: string) {
    this.s = s;
  }
  skipWS(): void {
    for (;;) {
      const c = this.s.charCodeAt(this.i);
      if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) this.i++;
      else return;
    }
  }
  /** current char code, or -1 at the end */
  peek(): number {
    return this.i < this.s.length ? this.s.charCodeAt(this.i) : -1;
  }
  hex4(): number {
    if (this.i + 4 > this.s.length) throw new Error('short \\u escape');
    let r = 0;
    for (let k = 0; k < 4; k++) {
      const c = this.s.charCodeAt(this.i + k);
      const v = c >= 48 && c <= 57 ? c - 48 : c >= 97 && c <= 102 ? c - 87 : c >= 65 && c <= 70 ? c - 55 : -1;
      if (v < 0) throw new Error('bad \\u escape');
      r = (r << 4) | v;
    }
    this.i += 4;
    return r;
  }
  str(): string {
    if (this.peek() !== 0x22) throw new Error('expected string');
    this.i++;
    let out = '';
    let run = this.i;
    for (;;) {
      if (this.i >= this.s.length) throw new Error('unterminated string');
      const c = this.s.charCodeAt(this.i);
      if (c === 0x22) {
        out += this.s.slice(run, this.i);
        this.i++;
        return out;
      }
      if (c < 0x20) throw new Error('control character in string');
      if (c !== 0x5c) {
        this.i++;
        continue;
      }
      out += this.s.slice(run, this.i);
      this.i++;
      if (this.i >= this.s.length) throw new Error('unterminated escape');
      const e = this.s[this.i++]!;
      switch (e) {
        case '"': case '\\': case '/': out += e; break;
        case 'b': out += '\b'; break;
        case 'f': out += '\f'; break;
        case 'n': out += '\n'; break;
        case 'r': out += '\r'; break;
        case 't': out += '\t'; break;
        case 'u': {
          let r = this.hex4();
          if (r >= 0xdc00 && r <= 0xdfff) throw new Error('lone low surrogate escape');
          if (r >= 0xd800 && r <= 0xdbff) {
            if (this.s[this.i] !== '\\' || this.s[this.i + 1] !== 'u') throw new Error('lone high surrogate escape');
            this.i += 2;
            const lo = this.hex4();
            if (lo < 0xdc00 || lo > 0xdfff) throw new Error('lone high surrogate escape');
            r = 0x10000 + ((r - 0xd800) << 10) + (lo - 0xdc00);
          }
          out += String.fromCodePoint(r);
          break;
        }
        default:
          throw new Error('invalid escape');
      }
      run = this.i;
    }
  }
  digits(): boolean {
    const st = this.i;
    while (this.peek() >= 48 && this.peek() <= 57) this.i++;
    return this.i > st;
  }
  number(): void {
    if (this.peek() === 0x2d) this.i++;
    const c = this.peek();
    if (c === 48) this.i++;
    else if (c >= 49 && c <= 57) this.digits();
    else throw new Error('bad number');
    if (this.peek() === 0x2e) {
      this.i++;
      if (!this.digits()) throw new Error('bad number');
    }
    const e = this.peek();
    if (e === 0x65 || e === 0x45) {
      this.i++;
      const sg = this.peek();
      if (sg === 0x2b || sg === 0x2d) this.i++;
      if (!this.digits()) throw new Error('bad number');
    }
  }
  literal(w: string): void {
    if (this.s.substr(this.i, w.length) !== w) throw new Error('bad literal');
    this.i += w.length;
  }
  memberStart(): void {
    this.str();
    this.skipWS();
    if (this.peek() !== 0x3a) throw new Error("expected ':'");
    this.i++;
  }
  /** Validates and skips one JSON value starting at the current position (iterative). */
  skipValue(): void {
    const stack: number[] = [];
    for (;;) {
      this.skipWS();
      const c = this.peek();
      let complete = true;
      if (c === 0x7b) {
        this.i++;
        this.skipWS();
        if (this.peek() === 0x7d) this.i++;
        else {
          stack.push(0x7b);
          this.memberStart();
          complete = false;
        }
      } else if (c === 0x5b) {
        this.i++;
        this.skipWS();
        if (this.peek() === 0x5d) this.i++;
        else {
          stack.push(0x5b);
          complete = false;
        }
      } else if (c === 0x22) this.str();
      else if (c === 0x2d || (c >= 48 && c <= 57)) this.number();
      else if (c === 0x74) this.literal('true');
      else if (c === 0x66) this.literal('false');
      else if (c === 0x6e) this.literal('null');
      else throw new Error('unexpected character');
      if (!complete) continue;
      for (;;) {
        if (stack.length === 0) return;
        this.skipWS();
        const top = stack[stack.length - 1]!;
        const d = this.peek();
        if (d === 0x2c) {
          this.i++;
          this.skipWS();
          if (top === 0x7b) this.memberStart();
          break;
        }
        if ((top === 0x7b && d === 0x7d) || (top === 0x5b && d === 0x5d)) {
          this.i++;
          stack.pop();
          continue;
        }
        throw new Error("expected ',' or closing bracket");
      }
    }
  }
  /** members of an object whose '{' was consumed */
  members(): RawMember[] {
    const out: RawMember[] = [];
    this.skipWS();
    if (this.peek() === 0x7d) {
      this.i++;
      return out;
    }
    for (;;) {
      this.skipWS();
      const ks = this.i;
      const key = this.str();
      const rawKey = this.s.slice(ks, this.i);
      this.skipWS();
      if (this.peek() !== 0x3a) throw new Error("expected ':'");
      this.i++;
      this.skipWS();
      const vs = this.i;
      this.skipValue();
      out.push({ key, rawKey, value: this.s.slice(vs, this.i) });
      this.skipWS();
      const d = this.peek();
      if (d === 0x2c) this.i++;
      else if (d === 0x7d) {
        this.i++;
        return out;
      } else throw new Error("expected ',' or '}'");
    }
  }
}

function wrap<T>(f: () => T): T {
  try {
    return f();
  } catch (e) {
    if (e instanceof UnreadableError) throw e;
    throw new UnreadableError(e instanceof Error ? e.message : 'malformed JSON');
  }
}

/** Parses the top-level object of a plaintext (already UTF-8 decoded); trailing data other than JSON whitespace is an error. */
export function parseObjectText(text: string): RawMember[] {
  return wrap(() => {
    const sc = new Scanner(text);
    sc.skipWS();
    if (sc.peek() !== 0x7b) throw new UnreadableError('not a JSON object');
    sc.i++;
    const ms = sc.members();
    sc.skipWS();
    if (sc.i !== text.length) throw new UnreadableError('trailing data after the object');
    return ms;
  });
}


/** Splits the raw text of an array value into the raw text of its elements. */
export function parseArray(v: string): string[] {
  return wrap(() => {
    const sc = new Scanner(v);
    if (sc.peek() !== 0x5b) throw new UnreadableError('expected an array');
    sc.i++;
    sc.skipWS();
    const out: string[] = [];
    if (sc.peek() === 0x5d) return out;
    for (;;) {
      sc.skipWS();
      const st = sc.i;
      sc.skipValue();
      out.push(v.slice(st, sc.i));
      sc.skipWS();
      const d = sc.peek();
      if (d === 0x2c) sc.i++;
      else if (d === 0x5d) return out;
      else throw new UnreadableError('bad array');
    }
  });
}

export function asObject(v: string): RawMember[] {
  return wrap(() => {
    const sc = new Scanner(v);
    if (sc.peek() !== 0x7b) throw new UnreadableError('expected an object');
    sc.i++;
    return sc.members();
  });
}

export function asString(v: string): string {
  return wrap(() => {
    const sc = new Scanner(v);
    if (sc.peek() !== 0x22) throw new UnreadableError('expected a string');
    return sc.str();
  });
}

export function asBool(v: string): boolean {
  if (v === 'true') return true;
  if (v === 'false') return false;
  throw new UnreadableError('expected a boolean');
}

/** 0 | [1-9][0-9]*, at most 2^53 - 1. */
export function asInt(v: string): number {
  if (!/^(?:0|[1-9][0-9]{0,15})$/.test(v)) throw new UnreadableError('expected an integer in 0..2^53-1');
  const n = Number(v);
  if (n > MAX_SAFE_INT) throw new UnreadableError('expected an integer in 0..2^53-1');
  return n;
}

export function asStringArray(v: string): string[] {
  return parseArray(v).map(asString);
}

/**
 * Assigns known members (a duplicate known name invalidates the document) and
 * collects the rest in order. Returns a Map: keys come from untrusted text.
 */
export function splitMembers(ms: RawMember[], known: ReadonlySet<string>): { assigned: Map<string, string>; extra: RawMember[] } {
  const assigned = new Map<string, string>();
  const extra: RawMember[] = [];
  for (const m of ms) {
    if (known.has(m.key)) {
      if (assigned.has(m.key)) throw new UnreadableError(`duplicate member "${m.key}"`);
      assigned.set(m.key, m.value);
    } else extra.push(m);
  }
  return { assigned, extra };
}

/** Entries of an array of objects: known members only, duplicates of known names rejected, unknown ones dropped. */
export function decodeEntries(raw: string, known: ReadonlySet<string>): Map<string, string>[] {
  return parseArray(raw).map((e) => splitMembers(asObject(e), known).assigned);
}

/** Canonical JSON string literal (README "Strings"): same as JSON.stringify for well-formed strings. */
export function jsonString(s: string): string {
  return JSON.stringify(s.toWellFormed());
}

export function extrasFrom(ms: RawMember[]): ExtraMember[] {
  return ms.map((m) => ({ rawKey: m.rawKey, rawValue: m.value }));
}

/** Re-validates carried-over members before they are written back. */
export function validateExtra(e: ExtraMember): void {
  wrap(() => {
    const k = new Scanner(e.rawKey);
    k.str();
    if (k.i !== e.rawKey.length) throw new Error('invalid extra member name');
    const v = new Scanner(e.rawValue);
    v.skipValue();
    if (v.i !== e.rawValue.length || e.rawValue.length === 0 || /^[ \t\n\r]/.test(e.rawValue)) throw new Error('invalid extra member value');
  });
}

export function appendExtras(parts: string[], extra: readonly ExtraMember[]): void {
  for (const e of extra) {
    validateExtra(e);
    parts.push(e.rawKey + ':' + e.rawValue);
  }
}
