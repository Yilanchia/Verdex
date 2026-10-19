import fs from "node:fs";

// Pure-Node binary AndroidManifest (AXML) decoder → attack-surface summary.
// No deps. Resolves attribute names via the resource-ID map (not just the
// string pool), so android: attrs decode correctly even when AAPT strips names.

const RES_STRING_POOL = 0x0001;
const RES_XML_RESOURCE_MAP = 0x0180;
const RES_XML_START_ELEMENT = 0x0102;
const RES_XML_END_ELEMENT = 0x0103;

// android: attribute resource IDs → names (the gotcha the user hit).
const ATTR_MAP = {
  0x0101021b: "versionCode", 0x0101021c: "versionName",
  0x01010010: "exported", 0x0101000f: "debuggable",
  0x0101028c: "allowBackup", 0x01010527: "networkSecurityConfig",
  0x0101021a: "usesCleartextTraffic", 0x01010003: "name",
  0x01010018: "authorities", 0x01010006: "permission",
  0x01010001: "label", 0x01010002: "icon", 0x0101020c: "process",
};

function readStringPool(buf, start) {
  const chunkSize = buf.readUInt32LE(start + 4);
  const stringCount = buf.readUInt32LE(start + 8);
  const flags = buf.readUInt32LE(start + 16);
  const stringsStart = buf.readUInt32LE(start + 20);
  const isUtf8 = (flags & (1 << 8)) !== 0;
  const offsetsBase = start + 28;
  const dataBase = start + stringsStart;
  const strings = [];
  for (let i = 0; i < stringCount; i++) {
    const off = buf.readUInt32LE(offsetsBase + i * 4);
    let p = dataBase + off;
    if (isUtf8) {
      let n = buf[p]; p += (n & 0x80) ? 2 : 1;          // utf16 char count (varint)
      let b = buf[p]; const twob = (b & 0x80) !== 0;
      b = twob ? ((b & 0x7f) << 8) | buf[p + 1] : b; p += twob ? 2 : 1; // byte count
      strings.push(buf.toString("utf8", p, p + b));
    } else {
      let n = buf.readUInt16LE(p); p += 2;
      if (n & 0x8000) { n = ((n & 0x7fff) << 16) | buf.readUInt16LE(p); p += 2; }
      strings.push(buf.toString("utf16le", p, p + n * 2));
    }
  }
  return { strings, chunkSize };
}

function readResourceMap(buf, start) {
  const chunkSize = buf.readUInt32LE(start + 4);
  const count = (chunkSize - 8) / 4;
  const ids = [];
  for (let i = 0; i < count; i++) ids.push(buf.readUInt32LE(start + 8 + i * 4));
  return { ids, chunkSize };
}

function typedValueToString(dataType, data, strings) {
  switch (dataType) {
    case 0x03: return strings[data] ?? "";            // string
    case 0x12: return data === 0 ? "false" : "true";  // boolean
    case 0x10: return String(data | 0);               // int dec
    case 0x11: return "0x" + (data >>> 0).toString(16); // int hex
    case 0x01: return "@ref/0x" + (data >>> 0).toString(16); // reference
    default: return String(data >>> 0);
  }
}

// Parse into a flat event list: { tag, attrs: { name: value } }.
export function decodeAxml(buf) {
  if (buf.length < 8) throw new Error("文件过小,不是 AXML");
  if (buf.readUInt16LE(0) !== 0x0003) throw new Error("不是二进制 AXML(魔数不符)");
  let strings = [];
  let resIds = [];
  const elements = [];
  let pos = 8;
  while (pos + 8 <= buf.length) {
    const type = buf.readUInt16LE(pos);
    const size = buf.readUInt32LE(pos + 4);
    if (size < 8) break;
    if (type === RES_STRING_POOL) { strings = readStringPool(buf, pos).strings; }
    else if (type === RES_XML_RESOURCE_MAP) { resIds = readResourceMap(buf, pos).ids; }
    else if (type === RES_XML_START_ELEMENT) {
      const nameIdx = buf.readUInt32LE(pos + 20);
      const attrCount = buf.readUInt16LE(pos + 28);
      const tag = strings[nameIdx] ?? "";
      const attrs = {};
      let ap = pos + 36;
      for (let i = 0; i < attrCount; i++) {
        const aNameIdx = buf.readUInt32LE(ap + 4);
        const aDataType = buf[ap + 15];
        const aData = buf.readUInt32LE(ap + 16);
        let aName = strings[aNameIdx] || "";
        if (!aName && resIds[aNameIdx] !== undefined) aName = ATTR_MAP[resIds[aNameIdx]] || `res_0x${resIds[aNameIdx].toString(16)}`;
        attrs[aName] = typedValueToString(aDataType, aData, strings);
        ap += 20;
      }
      elements.push({ tag, attrs });
    } else if (type === RES_XML_END_ELEMENT) { /* ignore for flat summary */ }
    pos += size;
  }
  return { elements };
}

export function manifestSummary(buf) {
  const { elements } = decodeAxml(buf);
  const manifest = elements.find((e) => e.tag === "manifest")?.attrs || {};
  const app = elements.find((e) => e.tag === "application")?.attrs || {};
  const permissions = elements.filter((e) => e.tag === "uses-permission").map((e) => e.attrs.name).filter(Boolean);
  const comps = { activity: [], service: [], receiver: [], provider: [] };
  for (const e of elements) {
    if (!(e.tag in comps)) continue;
    const exported = e.attrs.exported;
    comps[e.tag].push({ name: e.attrs.name, exported: exported === "true" ? true : exported === "false" ? false : null,
      ...(e.attrs.permission ? { permission: e.attrs.permission } : {}), ...(e.attrs.authorities ? { authorities: e.attrs.authorities } : {}) });
  }
  const exportedComps = [];
  for (const [kind, list] of Object.entries(comps)) for (const c of list) if (c.exported === true) exportedComps.push({ kind, ...c });
  return {
    package: manifest.package || elements[0]?.attrs?.package || null,
    version: { code: manifest.versionCode || null, name: manifest.versionName || null },
    permission_count: permissions.length,
    permissions,
    flags: {
      debuggable: app.debuggable === "true",
      allow_backup: app.allowBackup !== "false",
      uses_cleartext_traffic: app.usesCleartextTraffic === "true" ? true : app.usesCleartextTraffic === "false" ? false : null,
      network_security_config: app.networkSecurityConfig || null,
    },
    component_counts: Object.fromEntries(Object.entries(comps).map(([k, v]) => [k, v.length])),
    exported_components: exportedComps,
    attack_surface_note: exportedComps.length
      ? `${exportedComps.length} 个导出组件(无 permission 保护的可被其他应用调起,是攻击面入口)`
      : "未发现显式 exported=true 的组件",
  };
}

export function decodeManifestFile(file) {
  return manifestSummary(fs.readFileSync(file));
}
