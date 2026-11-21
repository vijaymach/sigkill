/*
 * ce.js - Cheat Engine style memory scanner, runs INSIDE the target process
 *         via frida-gadget. Non-root: no ptrace, the gadget owns the memory.
 *
 * rpc.exports: module, ranges, scan, next, write, read, freeze, unfreeze,
 *              list, clear, reset
 *
 * types: i8 i16 i32 i64 f32 f64 utf8 utf16
 * scan mode : eq (first scan always eq-for-value, or "unknown")
 * next modes: eq ne gt lt ge le inc dec changed unchanged unknown
 */

let T = {
    i8:   { size: 1, kind: 'int',  step: 1 },
    i16:  { size: 2, kind: 'int',  step: 2 },
    i32:  { size: 4, kind: 'int',  step: 4 },
    i64:  { size: 8, kind: 'int',  step: 8 },
    f32:  { size: 4, kind: 'float', step: 4 },
    f64:  { size: 8, kind: 'float', step: 8 },
    utf8: { size: 0, kind: 'string', step: 1 },
    utf16:{ size: 0, kind: 'string', step: 2 },
};

const CHUNK = 4 * 1024 * 1024;
const MAX_RESULTS = 200000;

let state = {
    type: 'i32',
    mode: 'unknown',
    target: null,
    results: [],       // [{addr, prev}]
    ranges: null,
    freezes: {},
};

function fmt(v) {
    return (v instanceof Int64 || typeof v === 'bigint') ? v.toString() : v;
}

function readAt(addr, type) {
    const t = T[type];
    if (t.kind === 'int') {
        if (t.size === 1) return addr.readS8();
        if (t.size === 2) return addr.readS16();
        if (t.size === 4) return addr.readS32();
        return addr.readS64();
    }
    if (t.size === 4) return addr.readFloat();
    if (t.size === 8) return addr.readDouble();
    return null;
}

function writeAt(addr, type, value) {
    const t = T[type];
    if (t.kind === 'int') {
        if (t.size === 1) return addr.writeS8(parseInt(value));
        if (t.size === 2) return addr.writeS16(parseInt(value));
        if (t.size === 4) return addr.writeS32(parseInt(value));
        return addr.writeS64(parseInt(value));
    }
    if (t.size === 4) return addr.writeFloat(parseFloat(value));
    if (t.size === 8) return addr.writeDouble(parseFloat(value));
    return null;
}

function cmp(cur, a, b) {
    if (cur instanceof Int64 || typeof cur === 'bigint') {
        a = BigInt(a); b = BigInt(b);
        return (cur < a ? -1 : cur > b ? 1 : 0);
    }
    return (cur < a ? -1 : cur > b ? 1 : 0);
}

/* mode decides whether a value survives the filter.
   prev = value recorded at the previous scan, target = user supplied. */
function keep(cur, prev, mode, target) {
    const hasT = target !== null && target !== undefined;
    if (mode === 'changed')   return cmp(cur, prev, prev) !== 0;
    if (mode === 'unchanged') return cmp(cur, prev, prev) === 0;
    if (mode === 'inc')       return cmp(cur, prev, prev) > 0;
    if (mode === 'dec')       return cmp(cur, prev, prev) < 0;
    if (!hasT) return mode === 'unknown' ? false : true;
    const c = cmp(cur, target, target);
    if (mode === 'eq') return c === 0;
    if (mode === 'ne') return c !== 0;
    if (mode === 'gt') return c > 0;
    if (mode === 'lt') return c < 0;
    if (mode === 'ge') return c >= 0;
    if (mode === 'le') return c <= 0;
    return false;
}

function scanRanges(name) {
    if (!name || name === 'all') return Process.enumerateRanges({ protection: 'rw-', coalesce: true });
    const mod = Process.findModuleByName(name);
    if (!mod) throw new Error('module not found: ' + name);
    return Process.enumerateRanges({ protection: 'rw-', coalesce: true })
        .filter(r => r.base.compare(mod.base) >= 0 &&
                     r.base.add(r.size).compare(mod.base.add(mod.size)) <= 0);
}

function stringNeedle(value, type) {
    if (type === 'utf8')  return Memory.allocUtf8String(String(value));
    return Memory.allocUtf16String(String(value));
}

function needleBytes(value, type) {
    const s = String(value);
    if (type === 'utf8') {
        const arr = [];
        for (let i = 0; i < s.length; i++) arr.push(s.charCodeAt(i) & 0xff);
        return arr;
    }
    const arr = [];
    for (let i = 0; i < s.length; i++) {
        const c = s.charCodeAt(i);
        arr.push(c & 0xff, (c >> 8) & 0xff);
    }
    return arr;
}

function encodeBytes(type, value) {
    const t = T[type];
    if (t.kind === 'string') return needleBytes(value, type);
    const buf = new ArrayBuffer(8);
    const dv = new DataView(buf);
    if (t.kind === 'int') {
        const n = Math.trunc(Number(value));
        if (t.size === 1) dv.setInt8(0, n);
        else if (t.size === 2) dv.setInt16(0, n, true);
        else if (t.size === 4) dv.setInt32(0, n, true);
        else dv.setBigInt64(0, BigInt(String(n)), true);
    } else {
        if (t.size === 4) dv.setFloat32(0, parseFloat(value), true);
        else dv.setFloat64(0, parseFloat(value), true);
    }
    return Array.from(new Uint8Array(buf, 0, t.size));
}

function hexPattern(bytes) {
    return bytes.map(b => b.toString(16).padStart(2, '0')).join(' ');
}

/* First scan runs through Memory.scan, which is native C. A JS loop over
   1.4 GB of rw- ranges takes minutes and can stall the host app; this
   covers the same ground in a fraction of the time. */
function firstScan(type, value, moduleName) {
    const t = T[type];
    const bytes = encodeBytes(type, value);
    const pat = hexPattern(bytes);
    const ranges = scanRanges(moduleName);
    const prev = (t.kind === 'string') ? value
               : (t.kind === 'float') ? parseFloat(value) : Number(value);

    const results = [];
    let truncated = false;

    for (const r of ranges) {
        if (truncated) break;
        try {
            Memory.scan(r.base, r.size, pat, {
                onMatch(addr) {
                    if (results.length >= MAX_RESULTS) { truncated = true; return; }
                    results.push({ addr: addr, prev: prev });
                },
                onError() {},
                onComplete() {}
            });
        } catch (e) { }
    }

    state = { type, mode: 'eq', target: prev, results: results,
              ranges: ranges.length, freezes: {} };
    return { count: results.length, truncated, ranges: ranges.length, pattern: pat };
}

function nextScan(mode, value) {
    const type = state.type;
    const t = T[type];
    const target = (value === null || value === undefined || value === '')
        ? null : (type.startsWith('utf') ? value : Number(value));
    const keep_ = [];
    for (const item of state.results) {
        let cur;
        try { cur = readAt(item.addr, type); } catch (e) { continue; }
        if (cur === null) continue;
        if (keep(cur, item.prev, mode, target)) keep_.push({ addr: item.addr, prev: cur });
        if (keep_.length >= MAX_RESULTS) break;
    }
    state.results = keep_;
    state.mode = mode;
    state.target = target;
    return { count: keep_.length };
}

function write(addr, type, value) {
    const a = ptr(addr);
    writeAt(a, type, value);
    return { addr: a.toString(), type, value: String(value), now: fmt(readAt(a, type)) };
}

function read(addr, type) {
    return { addr: addr, type, value: fmt(readAt(ptr(addr), type)) };
}

function freeze(addr, type, value) {
    const a = ptr(addr);
    const key = a.toString() + ':' + type;
    if (state.freezes[key]) clearInterval(state.freezes[key].timer);
    const writeOnce = () => { try { writeAt(a, type, value); } catch (e) {} };
    writeOnce();
    state.freezes[key] = { addr: a, type, value, timer: setInterval(writeOnce, 16) };
    return { frozen: key, count: Object.keys(state.freezes).length };
}

function unfreeze(addr) {
    let n = 0;
    for (const k of Object.keys(state.freezes)) {
        if (addr === undefined || k.startsWith(String(addr))) {
            clearInterval(state.freezes[k].timer);
            delete state.freezes[k];
            n++;
        }
    }
    return { cleared: n, count: Object.keys(state.freezes).length };
}

function list(limit) {
    const n = limit || 50;
    const out = [];
    for (let i = 0; i < state.results.length && i < n; i++) {
        const it = state.results[i];
        let cur = null;
        try { cur = readAt(it.addr, state.type); } catch (e) {}
        out.push({ addr: it.addr.toString(), value: fmt(cur) });
    }
    return { total: state.results.length, shown: out.length, type: state.type, rows: out };
}

function clear() {
    state.results = [];
    return { cleared: true };
}

function reset() {
    for (const k of Object.keys(state.freezes)) clearInterval(state.freezes[k].timer);
    state = { type: 'i32', mode: 'unknown', target: null, results: [], ranges: null, freezes: {} };
    return { reset: true };
}

function module(name) {
    if (name) {
        const m = Process.findModuleByName(name);
        if (!m) return { found: false, name: name };
        return { found: true, name: m.name, base: m.base.toString(), size: m.size, path: m.path };
    }
    const mods = Process.enumerateModules().slice().sort((a, b) => b.size - a.size);
    return {
        process: Process.id,
        arch: Process.arch,
        pointer_size: Process.pointerSize,
        module_count: mods.length,
        top: mods.slice(0, 15).map(m => ({
            name: m.name, base: m.base.toString(), size: m.size, path: m.path
        }))
    };
}

function ranges() {
    const rs = Process.enumerateRanges({ protection: 'rw-', coalesce: true });
    return {
        count: rs.length,
        total_mb: Math.round(rs.reduce((a, r) => a + r.size, 0) / 1e6),
        rows: rs.slice(0, 40).map(r => ({ base: r.base.toString(), size: r.size }))
    };
}

rpc.exports = { module, ranges, scan: firstScan, next: nextScan,
                write, read, freeze, unfreeze, list, clear, reset };
