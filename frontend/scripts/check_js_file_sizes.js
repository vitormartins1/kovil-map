const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const MODULE_ROOT = path.join(ROOT, 'src', 'modules');
const MAX_LINES = 2000;
const ALLOWLIST = new Map([
    ['src/modules/ui_recon.js', 6000],
    ['src/modules/ui_wardrive.js', 3800],
    ['src/modules/map.js', 2800],
    ['src/modules/ui.js', 2200],
    ['src/modules/ui_components/ui_cracking.js', 5000],
]);

function walk(dir, acc = []) {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        const abs = path.join(dir, entry.name);
        if (entry.isDirectory()) {
            walk(abs, acc);
            continue;
        }
        if (entry.isFile() && abs.endsWith('.js')) acc.push(abs);
    }
    return acc;
}

const offenders = [];
for (const absPath of walk(MODULE_ROOT)) {
    const relPath = path.relative(ROOT, absPath).replace(/\\/g, '/');
    const lineCount = fs.readFileSync(absPath, 'utf8').split('\n').length;
    const budget = ALLOWLIST.get(relPath) || MAX_LINES;
    if (lineCount > budget) {
        offenders.push({ relPath, lineCount, budget });
    }
}

if (offenders.length) {
    console.error('JavaScript module size guardrail failed:');
    for (const offender of offenders) {
        console.error(`- ${offender.relPath}: ${offender.lineCount} lines (budget ${offender.budget})`);
    }
    process.exit(1);
}

console.log('JavaScript module size guardrail passed.');
