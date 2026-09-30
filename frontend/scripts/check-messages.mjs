// Every translation key a component asks for has to exist, in every locale.
//
// This is here because five column headers had shipped reading "siem.severity",
// "dspm.riskScore" and "mobile.lastSeen": next-intl renders the key itself when
// it cannot resolve it, so the page looks built rather than broken and nothing
// fails. They were found by looking at a screenshot, which is not a process.
//
// The check is deliberately literal: it reads the keys spelled out in the source
// and does not try to evaluate a computed one. A key built at runtime is the
// caller's to keep honest; a key written as a string is this file's.
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join } from 'node:path'

const MESSAGES = 'messages'
const locales = readdirSync(MESSAGES).filter((f) => f.endsWith('.json'))
const dicts = Object.fromEntries(
  locales.map((f) => [f.replace('.json', ''), JSON.parse(readFileSync(join(MESSAGES, f), 'utf8'))]),
)

function resolves(dict, dotted) {
  let cur = dict
  for (const part of dotted.split('.')) {
    if (typeof cur !== 'object' || cur === null || !(part in cur)) return false
    cur = cur[part]
  }
  return typeof cur === 'string'
}

function keysOf(obj, prefix = '') {
  return Object.entries(obj).flatMap(([k, v]) =>
    typeof v === 'object' && v !== null ? keysOf(v, `${prefix}${k}.`) : [`${prefix}${k}`],
  )
}

function* sources(dir) {
  for (const name of readdirSync(dir)) {
    const path = join(dir, name)
    if (statSync(path).isDirectory()) yield* sources(path)
    else if (name.endsWith('.tsx') || name.endsWith('.ts')) yield path
  }
}

const problems = []

// 1. Every literal key resolves, in every locale.
for (const file of sources('src')) {
  const src = readFileSync(file, 'utf8')
  const namespaces = [...src.matchAll(/useTranslations\(\s*'([^']+)'\s*\)/g)].map((m) => m[1])
  if (namespaces.length === 0) continue
  for (const m of src.matchAll(/\bt\(\s*'([^']+)'/g)) {
    for (const [locale, dict] of Object.entries(dicts)) {
      if (!namespaces.some((ns) => resolves(dict, `${ns}.${m[1]}`))) {
        problems.push(
          `${file}: t('${m[1]}') resolves under no namespace of ${namespaces.join(', ')} in ${locale}`,
        )
      }
    }
  }
}

// 2. The locales carry the same keys. One locale gaining a key alone is how the
//    other starts rendering identifiers to whoever reads in that language.
const [first, ...rest] = Object.keys(dicts)
const reference = new Set(keysOf(dicts[first]))
for (const locale of rest) {
  const theirs = new Set(keysOf(dicts[locale]))
  for (const k of reference) if (!theirs.has(k)) problems.push(`${locale}.json is missing ${k}, which ${first}.json has`)
  for (const k of theirs) if (!reference.has(k)) problems.push(`${first}.json is missing ${k}, which ${locale}.json has`)
}

if (problems.length > 0) {
  console.error(`${problems.length} translation problem(s):`)
  for (const p of problems) console.error('  ' + p)
  process.exit(1)
}
console.log(`messages: ${reference.size} keys, ${locales.length} locales, every literal key resolves`)
