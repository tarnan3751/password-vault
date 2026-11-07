import { useEffect, useState } from 'preact/hooks';
import { generatePassword, type CharClass } from '../crypto/index.ts';
import { Check, Icon } from './kit.tsx';

const CLASS_LABELS: [CharClass, string][] = [['lower', 'a–z'], ['upper', 'A–Z'], ['digits', '0–9'], ['symbols', 'Symbols']];

/** Inline password generator with length and class options. */
export function Generator(p: { onUse: (pw: string) => void }) {
  const [length, setLength] = useState(20);
  const [classes, setClasses] = useState<Record<CharClass, boolean>>({ lower: true, upper: true, digits: true, symbols: true });
  const [noAmb, setNoAmb] = useState(false);
  const chosen = (Object.keys(classes) as CharClass[]).filter((c) => classes[c]);
  const make = () => (chosen.length ? generatePassword({ length: Math.max(length, chosen.length), classes: chosen, excludeAmbiguous: noAmb }) : '');
  const [pw, setPw] = useState(make);
  const regen = () => setPw(make());
  useEffect(regen, [length, classes, noAmb]);

  return (
    <div class="generator" role="group" aria-label="Password generator">
      <output class="gen-out mono" aria-live="polite">
        {pw || 'Choose at least one kind of character below'}
      </output>
      <div class="field">
        <label for="gen-len">
          Length: <strong>{length}</strong> characters
        </label>
        <input id="gen-len" type="range" min="8" max="64" value={length} onInput={(e) => setLength(Number(e.currentTarget.value))} />
      </div>
      <div class="gen-classes">
        {CLASS_LABELS.map(([c, label]) => (
          <Check label={label} checked={classes[c]} onChange={(v) => setClasses({ ...classes, [c]: v })} />
        ))}
        <Check label="No look-alikes (O/0, l/1)" checked={noAmb} onChange={setNoAmb} />
      </div>
      <div class="btn-row">
        <button type="button" class="btn" onClick={regen}>
          <Icon name="refresh" />
          Generate another
        </button>
        <button type="button" class="btn primary" disabled={!pw} onClick={() => p.onUse(pw)}>
          Use this password
        </button>
      </div>
    </div>
  );
}
