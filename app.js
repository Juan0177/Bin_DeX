// Bin_DeX - Client-Side Binary Dump Analyzer & Visualizer
const fileInput = document.querySelector('#fileInput');
const dropZone = document.querySelector('#dropZone');
const status = document.querySelector('#status');
const hexContainer = document.querySelector('#hexContainer');
const hexView = document.querySelector('#hexView');
const strings = document.querySelector('#strings');
const stringFilter = document.querySelector('#stringFilter');
const searchInput = document.querySelector('#searchInput');
const searchPrevBtn = document.querySelector('#searchPrev');
const searchNextBtn = document.querySelector('#searchNext');
const searchMatchesLabel = document.querySelector('#searchMatches');
const copyHexButton = document.querySelector('#copyHex');
const exportJsonButton = document.querySelector('#exportJson');
const exportRawButton = document.querySelector('#exportRaw');
const exportStringsButton = document.querySelector('#exportStrings');
const jumpOffsetInput = document.querySelector('#jumpOffset');
const jumpButton = document.querySelector('#jumpBtn');
const jsonPreview = document.querySelector('#jsonPreview');
const prevPageBtn = document.querySelector('#prevPage');
const nextPageBtn = document.querySelector('#nextPage');
const pageInfo = document.querySelector('#pageInfo');
const rowsPerPageSelect = document.querySelector('#rowsPerPage');
const compressionBadge = document.querySelector('#compressionBadge');
const parserUsedBadge = document.querySelector('#parserUsedBadge');

const state = {
  rawBytes: null,
  payload: null,
  compression: null,
  fileName: '',
  lastJson: null,
  extractedStrings: [],
  currentPage: 0,
  rowsPerPage: 256,
  selectedOffset: 0,
  searchMatches: [],
  currentMatchIndex: -1
};

// Event Listeners
fileInput.addEventListener('change', event => {
  if (event.target.files && event.target.files[0]) {
    openFile(event.target.files[0]);
  }
});

dropZone.addEventListener('click', () => fileInput.click());
['dragenter', 'dragover'].forEach(type => dropZone.addEventListener(type, event => {
  event.preventDefault();
  dropZone.classList.add('is-over');
}));
['dragleave', 'drop'].forEach(type => dropZone.addEventListener(type, event => {
  event.preventDefault();
  dropZone.classList.remove('is-over');
}));
dropZone.addEventListener('drop', event => {
  if (event.dataTransfer && event.dataTransfer.files[0]) {
    openFile(event.dataTransfer.files[0]);
  }
});

stringFilter.addEventListener('input', () => {
  if (!state.payload) return;
  renderStringsList(state.extractedStrings, stringFilter.value.trim());
});

searchInput.addEventListener('keydown', event => {
  if (event.key === 'Enter') {
    if (event.shiftKey) {
      findPrevSearchMatch();
    } else {
      findNextSearchMatch();
    }
  }
});
searchInput.addEventListener('input', () => executeSearch(searchInput.value.trim()));
searchPrevBtn.addEventListener('click', findPrevSearchMatch);
searchNextBtn.addEventListener('click', findNextSearchMatch);

copyHexButton.addEventListener('click', copyHexDump);
exportJsonButton.addEventListener('click', exportJsonDump);
exportRawButton.addEventListener('click', exportRawDump);
exportStringsButton.addEventListener('click', exportStringsDump);

jumpButton.addEventListener('click', jumpToOffset);
jumpOffsetInput.addEventListener('keydown', event => {
  if (event.key === 'Enter') jumpToOffset();
});

prevPageBtn.addEventListener('click', () => {
  if (state.currentPage > 0) {
    state.currentPage--;
    renderHexPage();
  }
});

nextPageBtn.addEventListener('click', () => {
  const totalPages = getTotalPages();
  if (state.currentPage < totalPages - 1) {
    state.currentPage++;
    renderHexPage();
  }
});

rowsPerPageSelect.addEventListener('change', () => {
  const val = rowsPerPageSelect.value;
  state.rowsPerPage = val === 'all' ? 'all' : parseInt(val, 10);
  state.currentPage = 0;
  renderHexPage();
});

// File Loading & Pipeline
async function openFile(file) {
  if (!file) return;

  try {
    status.innerHTML = `<strong>Caricamento in corso:</strong> ${escapeHtml(file.name)}...`;
    const buffer = await file.arrayBuffer();
    const rawBytes = new Uint8Array(buffer);
    state.rawBytes = rawBytes;
    state.fileName = file.name;

    // Detect & decompress
    const compression = detectCompression(rawBytes);
    state.compression = compression;
    state.payload = compression ? await decompressPayload(rawBytes, compression) : rawBytes;

    // Update Metadata
    document.querySelector('#fileName').textContent = file.name;
    document.querySelector('#fileSize').textContent = formatBytes(file.size);
    document.querySelector('#byteCount').textContent = `${state.payload.length} byte`;
    document.querySelector('#uniqueBytes').textContent = new Set(state.payload).size;

    if (compression) {
      compressionBadge.textContent = `${compression} (${formatBytes(state.payload.length)})`;
      compressionBadge.classList.remove('d-none');
    } else {
      compressionBadge.classList.add('d-none');
    }

    status.innerHTML = `<strong>File aperto:</strong> ${escapeHtml(file.name)} ${compression ? `(Decompresso da ${compression})` : ''}`;

    // Extract Strings
    state.extractedStrings = extractPrintableStrings(state.payload);
    document.querySelector('#stringCount').textContent = state.extractedStrings.length;
    renderStringsList(state.extractedStrings, stringFilter.value.trim());

    // Reset pagination & inspector
    state.currentPage = 0;
    state.selectedOffset = 0;
    state.searchMatches = [];
    state.currentMatchIndex = -1;
    updateSearchMatchUI();

    renderHexPage();
    updateDataInspector(0);

    // Run Deserialization / JSON Preview
    await runJsonAnalysis(state.payload);
  } catch (error) {
    status.innerHTML = `<span class="text-danger">Errore apertura file: ${escapeHtml(error.message || error)}</span>`;
  }
}

function getTotalRows() {
  if (!state.payload) return 0;
  return Math.ceil(state.payload.length / 16);
}

function getRowsPerPageCount() {
  if (state.rowsPerPage === 'all') {
    return Math.max(1, getTotalRows());
  }
  return state.rowsPerPage;
}

function getTotalPages() {
  const totalRows = getTotalRows();
  if (totalRows === 0) return 1;
  const count = getRowsPerPageCount();
  return Math.max(1, Math.ceil(totalRows / count));
}

// Hex Rendering with Pagination
function renderHexPage() {
  const bytes = state.payload;
  if (!bytes || bytes.length === 0) {
    hexView.innerHTML = '<span class="text-secondary">File vuoto o nessun file aperto.</span>';
    pageInfo.textContent = 'Pagina 1 di 1';
    prevPageBtn.disabled = true;
    nextPageBtn.disabled = true;
    return;
  }

  const totalRows = getTotalRows();
  const rowsPerPageCount = getRowsPerPageCount();
  const totalPages = getTotalPages();

  if (state.currentPage >= totalPages) state.currentPage = totalPages - 1;
  if (state.currentPage < 0) state.currentPage = 0;

  const startRow = state.currentPage * rowsPerPageCount;
  const endRow = Math.min(totalRows, startRow + rowsPerPageCount);

  pageInfo.textContent = `Pagina ${state.currentPage + 1} di ${totalPages} (${startRow * 16} - ${Math.min(bytes.length, endRow * 16)} byte)`;
  prevPageBtn.disabled = state.currentPage <= 0;
  nextPageBtn.disabled = state.currentPage >= totalPages - 1;

  hexView.innerHTML = '';
  const fragment = document.createDocumentFragment();

  for (let rowIndex = startRow; rowIndex < endRow; rowIndex++) {
    const offset = rowIndex * 16;
    const chunk = bytes.slice(offset, Math.min(bytes.length, offset + 16));

    const hexParts = [];
    for (let i = 0; i < 16; i++) {
      if (i < chunk.length) {
        hexParts.push(chunk[i].toString(16).padStart(2, '0'));
      } else {
        hexParts.push('  ');
      }
      if (i === 7) hexParts.push(''); // space separator
    }

    const asciiParts = [];
    for (let i = 0; i < chunk.length; i++) {
      const b = chunk[i];
      asciiParts.push(b >= 32 && b <= 126 ? String.fromCharCode(b) : '.');
    }

    const offsetHex = offset.toString(16).padStart(8, '0');
    const hexString = hexParts.join(' ');
    const asciiString = asciiParts.join('');

    const rowDiv = document.createElement('div');
    rowDiv.className = 'hex-row';
    rowDiv.dataset.offset = offset;

    if (state.selectedOffset >= offset && state.selectedOffset < offset + 16) {
      rowDiv.classList.add('is-selected');
    }

    // Check search match
    if (state.searchMatches.some(mOffset => mOffset >= offset && mOffset < offset + 16)) {
      rowDiv.classList.add('is-match');
    }

    rowDiv.textContent = `${offsetHex}  ${hexString}  |${asciiString}|`;

    rowDiv.addEventListener('click', (e) => {
      // Calculate clicked byte offset approximation based on click position or row
      const clickedRowOffset = offset;
      selectOffset(clickedRowOffset);
    });

    fragment.appendChild(rowDiv);
  }

  hexView.appendChild(fragment);
}

function selectOffset(offset, scrollToView = false) {
  if (!state.payload || offset < 0 || offset >= state.payload.length) return;

  state.selectedOffset = offset;

  // Ensure current page contains this offset
  const targetRow = Math.floor(offset / 16);
  const rowsPerPageCount = getRowsPerPageCount();
  const targetPage = Math.floor(targetRow / rowsPerPageCount);

  if (targetPage !== state.currentPage) {
    state.currentPage = targetPage;
    renderHexPage();
  } else {
    // Update selection highlight
    document.querySelectorAll('.hex-row').forEach(row => {
      const rowOffset = parseInt(row.dataset.offset, 10);
      if (offset >= rowOffset && offset < rowOffset + 16) {
        row.classList.add('is-selected');
        if (scrollToView) {
          row.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
        }
      } else {
        row.classList.remove('is-selected');
      }
    });
  }

  updateDataInspector(offset);
  status.innerHTML = `<strong>Offset selezionato:</strong> 0x${offset.toString(16).toUpperCase()} (${offset})`;
}

function jumpToOffset() {
  if (!state.payload) {
    status.textContent = 'Apri prima un file.';
    return;
  }

  const raw = jumpOffsetInput.value.trim();
  if (!raw) return;

  const isHex = raw.toLowerCase().startsWith('0x');
  const normalized = isHex ? raw.slice(2) : raw;
  const offset = parseInt(normalized, isHex ? 16 : 10);

  if (isNaN(offset) || offset < 0 || offset >= state.payload.length) {
    status.innerHTML = `<span class="text-danger">Offset non valido (max: 0x${(state.payload.length - 1).toString(16)}).</span>`;
    return;
  }

  selectOffset(offset, true);
}

// Data Inspector Engine
function updateDataInspector(offset) {
  const bytes = state.payload;
  const offsetBadge = document.querySelector('#inspectorOffset');

  if (!bytes || bytes.length === 0 || offset < 0 || offset >= bytes.length) {
    offsetBadge.textContent = '0x0 (0)';
    resetDataInspectorValues();
    return;
  }

  offsetBadge.textContent = `0x${offset.toString(16).toUpperCase()} (${offset})`;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const remaining = bytes.length - offset;

  // uint8 / int8
  if (remaining >= 1) {
    const u8 = view.getUint8(offset);
    const i8 = view.getInt8(offset);
    document.querySelector('#inspUint8').textContent = u8;
    document.querySelector('#inspInt8').textContent = i8;
    document.querySelector('#inspBinary').textContent = '0b' + u8.toString(2).padStart(8, '0');
  } else {
    document.querySelector('#inspUint8').textContent = '-';
    document.querySelector('#inspInt8').textContent = '-';
    document.querySelector('#inspBinary').textContent = '-';
  }

  // uint16 / int16
  if (remaining >= 2) {
    document.querySelector('#inspUint16LE').textContent = view.getUint16(offset, true);
    document.querySelector('#inspUint16BE').textContent = view.getUint16(offset, false);
    document.querySelector('#inspInt16LE').textContent = view.getInt16(offset, true);
    document.querySelector('#inspInt16BE').textContent = view.getInt16(offset, false);
  } else {
    document.querySelector('#inspUint16LE').textContent = '-';
    document.querySelector('#inspUint16BE').textContent = '-';
    document.querySelector('#inspInt16LE').textContent = '-';
    document.querySelector('#inspInt16BE').textContent = '-';
  }

  // uint32 / int32 / float32
  if (remaining >= 4) {
    const u32LE = view.getUint32(offset, true);
    const u32BE = view.getUint32(offset, false);
    document.querySelector('#inspUint32LE').textContent = u32LE;
    document.querySelector('#inspUint32BE').textContent = u32BE;
    document.querySelector('#inspInt32LE').textContent = view.getInt32(offset, true);
    document.querySelector('#inspInt32BE').textContent = view.getInt32(offset, false);

    const f32LE = view.getFloat32(offset, true);
    const f32BE = view.getFloat32(offset, false);
    document.querySelector('#inspFloat32LE').textContent = Number.isFinite(f32LE) ? f32LE.toPrecision(6) : f32LE;
    document.querySelector('#inspFloat32BE').textContent = Number.isFinite(f32BE) ? f32BE.toPrecision(6) : f32BE;

    // Check timestamp (reasonable range: 2000 - 2045)
    let timeLabel = '-';
    if (u32LE >= 946684800 && u32LE <= 2367206400) {
      timeLabel = new Date(u32LE * 1000).toLocaleString('it-IT') + ' (LE)';
    } else if (u32BE >= 946684800 && u32BE <= 2367206400) {
      timeLabel = new Date(u32BE * 1000).toLocaleString('it-IT') + ' (BE)';
    }
    document.querySelector('#inspTime').textContent = timeLabel;
  } else {
    document.querySelector('#inspUint32LE').textContent = '-';
    document.querySelector('#inspUint32BE').textContent = '-';
    document.querySelector('#inspInt32LE').textContent = '-';
    document.querySelector('#inspInt32BE').textContent = '-';
    document.querySelector('#inspFloat32LE').textContent = '-';
    document.querySelector('#inspFloat32BE').textContent = '-';
    document.querySelector('#inspTime').textContent = '-';
  }
}

function resetDataInspectorValues() {
  ['inspUint8', 'inspInt8', 'inspUint16LE', 'inspUint16BE', 'inspInt16LE', 'inspInt16BE',
   'inspUint32LE', 'inspUint32BE', 'inspInt32LE', 'inspInt32BE', 'inspFloat32LE', 'inspFloat32BE',
   'inspBinary', 'inspTime'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.textContent = '-';
  });
}

// Extracted Strings Management & Interactive Clicking
function renderStringsList(list, query = '') {
  const filtered = query
    ? list.filter(value => value.toLowerCase().includes(query.toLowerCase()))
    : list;

  strings.innerHTML = '';

  if (!filtered.length) {
    strings.innerHTML = `<span class="empty">${query ? 'Nessuna stringa corrisponde al filtro.' : 'Nessuna stringa trovata.'}</span>`;
    return;
  }

  const fragment = document.createDocumentFragment();
  filtered.forEach(str => {
    const badge = document.createElement('span');
    badge.className = 'string';
    badge.title = 'Clicca per saltare all\'offset nell\'Hex';
    badge.textContent = str;

    badge.addEventListener('click', () => {
      findAndJumpToString(str);
    });

    fragment.appendChild(badge);
  });

  strings.appendChild(fragment);
}

function findAndJumpToString(str) {
  if (!state.payload) return;

  const targetBytes = new TextEncoder().encode(str);
  const foundOffset = findByteSequence(state.payload, targetBytes);

  if (foundOffset !== -1) {
    selectOffset(foundOffset, true);
    status.innerHTML = `<strong>Stringa trovata:</strong> "${escapeHtml(str)}" all'offset 0x${foundOffset.toString(16).toUpperCase()}`;
  } else {
    status.innerHTML = `Stringa "${escapeHtml(str)}" non localizzata esattamente nel payload binario.`;
  }
}

function findByteSequence(haystack, needle, startIndex = 0) {
  if (needle.length === 0 || haystack.length < needle.length) return -1;

  for (let i = startIndex; i <= haystack.length - needle.length; i++) {
    let match = true;
    for (let j = 0; j < needle.length; j++) {
      if (haystack[i + j] !== needle[j]) {
        match = false;
        break;
      }
    }
    if (match) return i;
  }
  return -1;
}

// Unified Search (Hex & Text)
function executeSearch(query) {
  if (!state.payload || !query) {
    state.searchMatches = [];
    state.currentMatchIndex = -1;
    updateSearchMatchUI();
    renderHexPage();
    return;
  }

  let needleBytes = null;

  // Test if input is hexadecimal (e.g., "1f 8b", "0x1f0x8b", "789c")
  const cleanedHex = query.replace(/^0x/i, '').replace(/[\s,]+/g, '');
  if (/^[0-9a-fA-F]+$/.test(cleanedHex) && cleanedHex.length >= 2 && cleanedHex.length % 2 === 0) {
    const bytes = [];
    for (let i = 0; i < cleanedHex.length; i += 2) {
      bytes.push(parseInt(cleanedHex.slice(i, i + 2), 16));
    }
    needleBytes = new Uint8Array(bytes);
  } else {
    needleBytes = new TextEncoder().encode(query);
  }

  // Scan all occurrences
  const matches = [];
  let scanIndex = 0;
  const maxMatches = 500;

  while (scanIndex < state.payload.length && matches.length < maxMatches) {
    const found = findByteSequence(state.payload, needleBytes, scanIndex);
    if (found === -1) break;
    matches.push(found);
    scanIndex = found + 1;
  }

  state.searchMatches = matches;
  state.currentMatchIndex = matches.length > 0 ? 0 : -1;
  updateSearchMatchUI();

  if (matches.length > 0) {
    selectOffset(matches[0], true);
  }
  renderHexPage();
}

function findNextSearchMatch() {
  if (!state.searchMatches.length) return;
  state.currentMatchIndex = (state.currentMatchIndex + 1) % state.searchMatches.length;
  updateSearchMatchUI();
  selectOffset(state.searchMatches[state.currentMatchIndex], true);
}

function findPrevSearchMatch() {
  if (!state.searchMatches.length) return;
  state.currentMatchIndex = (state.currentMatchIndex - 1 + state.searchMatches.length) % state.searchMatches.length;
  updateSearchMatchUI();
  selectOffset(state.searchMatches[state.currentMatchIndex], true);
}

function updateSearchMatchUI() {
  const count = state.searchMatches.length;
  if (count === 0) {
    searchMatchesLabel.textContent = '0/0';
    searchPrevBtn.disabled = true;
    searchNextBtn.disabled = true;
  } else {
    searchMatchesLabel.textContent = `${state.currentMatchIndex + 1}/${count}`;
    searchPrevBtn.disabled = false;
    searchNextBtn.disabled = false;
  }
}

// Decompression & Deserialization Engine
function detectCompression(bytes) {
  if (bytes.length >= 2 && bytes[0] === 0x1f && bytes[1] === 0x8b) return 'gzip';
  if (bytes.length >= 2 && bytes[0] === 0x78 && [0x01, 0x5e, 0x9c, 0xda].includes(bytes[1])) return 'zlib';
  return null;
}

async function decompressPayload(bytes, compression) {
  if (!window.pako) return bytes;
  try {
    if (compression === 'gzip') return pako.ungzip(bytes);
    if (compression === 'zlib') return pako.inflate(bytes);
  } catch (error) {
    console.warn('Decompression warning:', error);
    return bytes;
  }
  return bytes;
}

async function runJsonAnalysis(bytes) {
  try {
    const parsed = await analyzeBinaryDump(bytes);
    state.lastJson = normalizeStructuredResult(parsed);
    parserUsedBadge.textContent = state.lastJson.summary.parser_used || state.lastJson.status || '-';
    jsonPreview.textContent = JSON.stringify(state.lastJson, null, 2);
  } catch (error) {
    state.lastJson = null;
    parserUsedBadge.textContent = 'error';
    jsonPreview.textContent = JSON.stringify({
      status: 'error',
      message: error && error.message ? error.message : 'Unknown deserialization error'
    }, null, 2);
  }
}

async function analyzeBinaryDump(bytes) {
  const baseResult = {
    source_file: state.fileName || 'unknown.bin',
    status: 'partial_extraction',
    size_bytes: bytes.length,
    compression_detected: state.compression,
    parser_used: null,
    data: null,
    extracted_strings: []
  };

  const parsed = tryStructuredDeserialization(bytes);
  if (parsed) {
    baseResult.status = 'deserialized';
    baseResult.parser_used = parsed.parser;
    baseResult.data = parsed.data;
    return baseResult;
  }

  const heuristic = inferHeuristicStructure(bytes);
  if (heuristic && Object.keys(heuristic).length > 0) {
    baseResult.status = 'heuristic_structure';
    baseResult.parser_used = 'heuristic';
    baseResult.data = heuristic;
    return baseResult;
  }

  baseResult.extracted_strings = extractPrintableStrings(bytes);
  return baseResult;
}

function tryStructuredDeserialization(bytes) {
  if (!bytes || bytes.length === 0) return null;

  // 1. JSON plaintext check at offset 0
  const text = decodeText(bytes);
  if (text && /^[\s\[{]/.test(text)) {
    try {
      const parsed = JSON.parse(text);
      return { parser: 'json', data: parsed };
    } catch (_) {}
  }

  const parsers = [
    {
      name: 'messagepack',
      test: (buf) => {
        if (typeof window !== 'undefined' && window.msgpack) {
          const decoded = msgpack.decode(buf);
          if (decoded !== undefined && decoded !== null) return decoded;
        }
        return null;
      }
    },
    {
      name: 'cbor',
      test: (buf) => {
        if (typeof window !== 'undefined' && window.CBOR) {
          const rawBuf = buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
          const decoded = CBOR.decode(rawBuf);
          if (decoded !== undefined && decoded !== null) return decoded;
        }
        return null;
      }
    },
    {
      name: 'bson',
      test: (buf) => {
        if (typeof window !== 'undefined' && window.BSON && typeof window.BSON.deserialize === 'function') {
          const decoded = window.BSON.deserialize(buf);
          if (decoded !== undefined && decoded !== null) return decoded;
        }
        return null;
      }
    }
  ];

  // Generate candidate offsets
  const candidateOffsets = [0];
  const maxScan = Math.min(64, bytes.length - 4);
  for (let i = 1; i < maxScan; i++) {
    const b = bytes[i];
    if ((b >= 0x80 && b <= 0x8F) || b === 0xDE || b === 0xDF || b === 0xA7 || (b >= 0x90 && b <= 0x94)) {
      candidateOffsets.push(i);
    }
  }
  for (const commonOff of [4, 8, 11, 12, 16, 24, 32]) {
    if (commonOff < maxScan && !candidateOffsets.includes(commonOff)) {
      candidateOffsets.push(commonOff);
    }
  }
  candidateOffsets.sort((a, b) => a - b);

  // Pass 1: Look for structured dictionary/root object
  for (const offset of candidateOffsets) {
    const slice = offset === 0 ? bytes : bytes.slice(offset);
    for (const parser of parsers) {
      try {
        const decoded = parser.test(slice);
        if (decoded && typeof decoded === 'object' && !Array.isArray(decoded) && Object.keys(decoded).length > 0) {
          const label = offset === 0 ? parser.name : `${parser.name} (offset 0x${offset.toString(16).padStart(2, '0')})`;
          return { parser: label, data: cleanJsonValue(decoded) };
        }
      } catch (_) {}
    }
  }

  // Pass 2: Fallback to array/list
  for (const offset of candidateOffsets) {
    const slice = offset === 0 ? bytes : bytes.slice(offset);
    for (const parser of parsers) {
      try {
        const decoded = parser.test(slice);
        if (decoded && typeof decoded === 'object' && Object.keys(decoded).length > 0) {
          const label = offset === 0 ? parser.name : `${parser.name} (offset 0x${offset.toString(16).padStart(2, '0')})`;
          return { parser: label, data: cleanJsonValue(decoded) };
        }
      } catch (_) {}
    }
  }

  return null;
}

function decodeText(bytes) {
  try {
    return new TextDecoder('utf-8', { fatal: false }).decode(bytes);
  } catch (_) {
    return '';
  }
}

function extractPrintableStrings(bytes, minimumLength = 4) {
  const text = decodeText(bytes);
  const matches = text.match(/[\x20-\x7e]{4,}/g) || [];
  const unique = [];
  const seen = new Set();

  for (const item of matches) {
    const cleaned = item.trim();
    if (!cleaned || cleaned.length < minimumLength || seen.has(cleaned)) continue;
    seen.add(cleaned);
    unique.push(cleaned);
  }

  return unique;
}

function inferHeuristicStructure(bytes) {
  const rawStrings = extractPrintableStrings(bytes, 3);
  const obj = {};
  const hints = ['version', 'records', 'settings', 'mapLayerData', 'friendship_pop', 'unlock', 'map', 'layer', 'data', 'population', 'profile', 'meta'];
  const text = decodeText(bytes);
  const tokenMatches = text.match(/[A-Za-z_][A-Za-z0-9_]*/g) || [];

  for (let i = 0; i < tokenMatches.length; i++) {
    const token = tokenMatches[i];
    const lower = token.toLowerCase();
    const match = hints.find(hint => lower.includes(hint) || hint.includes(lower));
    if (!match) continue;

    const neighbors = [];
    for (let j = i + 1; j < Math.min(i + 6, tokenMatches.length); j++) {
      const next = tokenMatches[j];
      if (next && /^[A-Za-z0-9_]+$/.test(next) && next !== token) {
        neighbors.push(next);
      }
    }

    const value = buildHeuristicValue(neighbors, rawStrings, match, token);
    if (value !== undefined) obj[match] = value;
  }

  const directStrings = rawStrings.filter(value => /[A-Za-z_]/.test(value));
  for (const item of directStrings) {
    const lower = item.toLowerCase();
    const match = hints.find(hint => lower.includes(hint) || hint.includes(lower));
    if (!match || obj[match] !== undefined) continue;
    obj[match] = item;
  }

  return Object.keys(obj).length > 0 ? obj : null;
}

function buildHeuristicValue(neighbors, rawStrings, match, token) {
  const numbers = neighbors.filter(value => /^-?\d+$/.test(value) || /^0x[0-9a-fA-F]+$/i.test(value));
  if (numbers.length > 0) {
    const value = numbers[0];
    return /^0x[0-9a-fA-F]+$/i.test(value) ? parseInt(value, 16) : parseInt(value, 10);
  }

  const friendly = neighbors.filter(value => value.length >= 3 && /[a-zA-Z]/.test(value));
  if (friendly.length > 0) return friendly[0];

  const strings = rawStrings.filter(value => value.toLowerCase().includes(match) || value.toLowerCase().includes(token.toLowerCase()));
  if (strings.length > 0) return strings[0];

  return undefined;
}

function cleanJsonValue(value) {
  if (value && typeof value === 'object') {
    if (Array.isArray(value)) return value.map(cleanJsonValue);
    const obj = {};
    for (const key of Object.keys(value)) {
      obj[key] = cleanJsonValue(value[key]);
    }
    return obj;
  }
  if (value instanceof Uint8Array) return Array.from(value);
  if (typeof value === 'bigint') return value.toString();
  return value;
}

function normalizeStructuredResult(result) {
  const normalized = {
    source_file: result.source_file || 'unknown.bin',
    status: result.status || 'partial_extraction',
    summary: {
      size_bytes: result.size_bytes || 0,
      compression_detected: result.compression_detected || null,
      parser_used: result.parser_used || null,
      extracted_string_count: Array.isArray(result.extracted_strings) ? result.extracted_strings.length : 0
    }
  };

  if (result.data && typeof result.data === 'object') {
    normalized.data = cleanJsonValue(result.data);
    return normalized;
  }

  if (Array.isArray(result.extracted_strings) && result.extracted_strings.length) {
    normalized.extracted_strings = result.extracted_strings;
  }

  if (result.data !== null && result.data !== undefined) {
    normalized.data = result.data;
  }

  return normalized;
}

// Multi-Format Exporters
function copyHexDump() {
  if (!state.payload) {
    status.textContent = 'Nessun contenuto da copiare.';
    return;
  }

  // Generate full hex text for export
  const rows = [];
  const bytes = state.payload;
  for (let offset = 0; offset < bytes.length; offset += 16) {
    const chunk = bytes.slice(offset, offset + 16);
    const hex = Array.from(chunk, byte => byte.toString(16).padStart(2, '0')).join(' ');
    const padded = hex.padEnd(47, ' ');
    const ascii = Array.from(chunk, byte => byte >= 32 && byte <= 126 ? String.fromCharCode(byte) : '.').join('');
    rows.push(`${offset.toString(16).padStart(8, '0')}  ${padded}  |${ascii}|`);
  }

  const textToCopy = rows.join('\n');
  navigator.clipboard.writeText(textToCopy)
    .then(() => {
      status.innerHTML = '<strong>Dump esadecimale copiato negli appunti!</strong>';
    })
    .catch(() => {
      const helper = document.createElement('textarea');
      helper.value = textToCopy;
      document.body.appendChild(helper);
      helper.select();
      document.execCommand('copy');
      helper.remove();
      status.innerHTML = '<strong>Dump esadecimale copiato negli appunti!</strong>';
    });
}

async function exportJsonDump() {
  if (!state.payload) {
    status.textContent = 'Apri prima un file.';
    return;
  }

  try {
    const result = state.lastJson || normalizeStructuredResult(await analyzeBinaryDump(state.payload));
    const jsonText = JSON.stringify(result, null, 2);
    downloadBlob(new Blob([jsonText], { type: 'application/json' }), state.fileName ? `${state.fileName}.json` : 'dump.json');
    status.innerHTML = `<strong>JSON esportato con successo.</strong>`;
  } catch (error) {
    status.textContent = 'Esportazione JSON fallita: ' + (error && error.message ? error.message : 'errore sconosciuto');
  }
}

function exportRawDump() {
  if (!state.payload) {
    status.textContent = 'Apri prima un file.';
    return;
  }

  const blob = new Blob([state.payload], { type: 'application/octet-stream' });
  const rawName = state.fileName
    ? (state.compression ? `${state.fileName}.decompressed.bin` : `${state.fileName}.raw.bin`)
    : 'payload.bin';

  downloadBlob(blob, rawName);
  status.innerHTML = `<strong>Payload raw esportato:</strong> ${escapeHtml(rawName)}`;
}

function exportStringsDump() {
  if (!state.payload || !state.extractedStrings.length) {
    status.textContent = 'Nessuna stringa estratta da esportare.';
    return;
  }

  const content = state.extractedStrings.join('\n');
  const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
  const stringsName = state.fileName ? `${state.fileName}.strings.txt` : 'strings.txt';

  downloadBlob(blob, stringsName);
  status.innerHTML = `<strong>Elenco stringhe esportato:</strong> ${escapeHtml(stringsName)}`;
}

function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function formatBytes(size) {
  if (size < 1024) return `${size} B`;
  if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KB`;
  return `${(size / (1024 * 1024)).toFixed(1)} MB`;
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[char]));
}