// qrcode.js — Pure JS QR code generator for ECHO device UUIDs
// Version 3 (29x29), ECC Level L, Byte mode
// UUID = 36 chars = 36 bytes → needs ~308 data bits → Version 3-L has 440 bits (55 codewords)

const QRCode = {
  showModal(text, modalTitle) {
    this.closeModal();

    const overlay = document.createElement('div');
    overlay.className = 'modal-overlay';
    overlay.id = 'qrModal';
    overlay.addEventListener('click', (e) => {
      if (e.target === overlay) this.closeModal();
    });

    const content = document.createElement('div');
    content.className = 'modal-content';

    const title = document.createElement('h3');
    title.textContent = modalTitle || 'Your QR Code';
    content.appendChild(title);

    const canvas = document.createElement('canvas');
    this.renderToCanvas(canvas, text, 232);
    content.appendChild(canvas);

    const hint = document.createElement('p');
    hint.textContent = modalTitle === 'Invite Code'
      ? 'Share this code to invite someone. Code copied to clipboard.'
      : 'Show this to someone to add you as a buddy.';
    content.appendChild(hint);

    overlay.appendChild(content);
    document.body.appendChild(overlay);
  },

  closeModal() {
    const existing = document.getElementById('qrModal');
    if (existing) existing.remove();
  },

  renderToCanvas(canvas, text, size) {
    const modules = this.generate(text);
    const moduleCount = modules.length;
    const scale = Math.floor(size / moduleCount);
    const actualSize = scale * moduleCount;
    canvas.width = actualSize;
    canvas.height = actualSize;

    const ctx = canvas.getContext('2d');
    ctx.fillStyle = '#1c1c1e';
    ctx.fillRect(0, 0, actualSize, actualSize);

    ctx.fillStyle = '#4a9eff';
    for (let r = 0; r < moduleCount; r++) {
      for (let c = 0; c < moduleCount; c++) {
        if (modules[r][c]) {
          ctx.fillRect(c * scale, r * scale, scale, scale);
        }
      }
    }
  },

  // Generate QR matrix — Version 3 (29x29), ECC L, byte mode, mask 0
  generate(text) {
    const size = 29;
    const dataCapacityBits = 440; // 55 data codewords * 8
    const dataCodewords = 55;
    const eccCount = 15; // Version 3-L: 15 EC codewords

    const data = this.encodeData(text, dataCapacityBits, dataCodewords, eccCount);
    const matrix = Array.from({ length: size }, () => Array(size).fill(null));
    const reserved = Array.from({ length: size }, () => Array(size).fill(false));

    // Finder patterns (3 corners)
    this.placeFinderPattern(matrix, reserved, 0, 0);
    this.placeFinderPattern(matrix, reserved, size - 7, 0);
    this.placeFinderPattern(matrix, reserved, 0, size - 7);

    // Alignment patterns — Version 3 centers at [6, 22]
    // Skip if overlapping finder pattern
    this.placeAlignmentPattern(matrix, reserved, 22, 22);
    this.placeAlignmentPattern(matrix, reserved, 22, 6);
    this.placeAlignmentPattern(matrix, reserved, 6, 22);

    // Timing patterns
    for (let i = 8; i < size - 8; i++) {
      if (!reserved[6][i]) {
        matrix[6][i] = i % 2 === 0;
        reserved[6][i] = true;
      }
      if (!reserved[i][6]) {
        matrix[i][6] = i % 2 === 0;
        reserved[i][6] = true;
      }
    }

    // Dark module (always set)
    matrix[size - 8][8] = true;
    reserved[size - 8][8] = true;

    // Reserve format info areas (15 bits around top-left + split)
    for (let i = 0; i < 8; i++) {
      // Horizontal strip at row 8
      if (!reserved[8][i]) reserved[8][i] = true;
      if (i === 7 && !reserved[8][8]) reserved[8][8] = true;
      // Vertical strip at col 8
      if (!reserved[i][8]) reserved[i][8] = true;
      // Bottom-left vertical
      reserved[size - 1 - i][8] = true;
      // Top-right horizontal
      reserved[8][size - 1 - i] = true;
    }
    reserved[8][8] = true;

    // Place data bits
    this.placeData(matrix, reserved, data, size);

    // Apply mask 0: (row + col) % 2 === 0
    for (let r = 0; r < size; r++) {
      for (let c = 0; c < size; c++) {
        if (!reserved[r][c] && (r + c) % 2 === 0) {
          matrix[r][c] = !matrix[r][c];
        }
      }
    }

    // Format info: ECC L (01), mask 0 (000) → 01000
    // BCH encoded + XOR mask: 111011111000100
    const formatBits = [1,1,1,0,1,1,1,1,1,0,0,0,1,0,0];
    this.placeFormatInfo(matrix, formatBits, size);

    // Version info: Version 3 doesn't need version info (only V7+)

    return matrix;
  },

  encodeData(text, capacityBits, dataCodewords, eccCount) {
    const bytes = [];
    for (let i = 0; i < text.length; i++) {
      bytes.push(text.charCodeAt(i));
    }

    const bits = [];
    // Mode indicator: 0100 (byte mode)
    bits.push(0, 1, 0, 0);
    // Character count: 8 bits for byte mode in Versions 1-9
    const count = bytes.length;
    for (let i = 7; i >= 0; i--) bits.push((count >> i) & 1);
    // Data bytes
    for (const b of bytes) {
      for (let i = 7; i >= 0; i--) bits.push((b >> i) & 1);
    }

    // Terminator: up to 4 zero bits, but don't exceed capacity
    for (let i = 0; i < 4 && bits.length < capacityBits; i++) {
      bits.push(0);
    }

    // Pad to byte boundary
    while (bits.length % 8 !== 0 && bits.length < capacityBits) {
      bits.push(0);
    }

    // Convert to codewords
    const codewords = [];
    for (let i = 0; i < bits.length; i += 8) {
      let val = 0;
      for (let j = 0; j < 8 && i + j < bits.length; j++) {
        val = (val << 1) | bits[i + j];
      }
      codewords.push(val);
    }

    // Pad codewords to capacity
    const padBytes = [0xEC, 0x11];
    let padIdx = 0;
    while (codewords.length < dataCodewords) {
      codewords.push(padBytes[padIdx % 2]);
      padIdx++;
    }

    // Reed-Solomon ECC
    const ecc = this.reedSolomon(codewords.slice(0, dataCodewords), eccCount);

    // Final bit stream: data codewords + EC codewords
    const allBits = [];
    for (const cw of codewords.slice(0, dataCodewords)) {
      for (let i = 7; i >= 0; i--) allBits.push((cw >> i) & 1);
    }
    for (const cw of ecc) {
      for (let i = 7; i >= 0; i--) allBits.push((cw >> i) & 1);
    }

    return allBits;
  },

  // GF(256) field tables
  gfExp: null,
  gfLog: null,

  initGF() {
    if (this.gfExp) return;
    this.gfExp = new Array(512);
    this.gfLog = new Array(256);
    let x = 1;
    for (let i = 0; i < 255; i++) {
      this.gfExp[i] = x;
      this.gfLog[x] = i;
      x <<= 1;
      if (x >= 256) x ^= 0x11d;
    }
    for (let i = 255; i < 512; i++) {
      this.gfExp[i] = this.gfExp[i - 255];
    }
  },

  gfMul(a, b) {
    if (a === 0 || b === 0) return 0;
    return this.gfExp[this.gfLog[a] + this.gfLog[b]];
  },

  reedSolomon(data, eccCount) {
    this.initGF();
    let gen = [1];
    for (let i = 0; i < eccCount; i++) {
      const factor = [1, this.gfExp[i]];
      const newGen = new Array(gen.length + 1).fill(0);
      for (let j = 0; j < gen.length; j++) {
        for (let k = 0; k < factor.length; k++) {
          newGen[j + k] ^= this.gfMul(gen[j], factor[k]);
        }
      }
      gen = newGen;
    }

    const remainder = new Array(eccCount).fill(0);
    for (const d of data) {
      const factor = d ^ remainder[0];
      remainder.shift();
      remainder.push(0);
      for (let i = 0; i < eccCount; i++) {
        remainder[i] ^= this.gfMul(gen[i + 1], factor);
      }
    }
    return remainder;
  },

  placeFinderPattern(matrix, reserved, row, col) {
    for (let r = -1; r <= 7; r++) {
      for (let c = -1; c <= 7; c++) {
        const mr = row + r, mc = col + c;
        if (mr < 0 || mr >= matrix.length || mc < 0 || mc >= matrix.length) continue;
        const isOuter = r === -1 || r === 7 || c === -1 || c === 7;
        const isBorder = r === 0 || r === 6 || c === 0 || c === 6;
        const isInner = r >= 2 && r <= 4 && c >= 2 && c <= 4;
        matrix[mr][mc] = !isOuter && (isBorder || isInner);
        reserved[mr][mc] = true;
      }
    }
  },

  placeAlignmentPattern(matrix, reserved, row, col) {
    // Don't place if it overlaps a finder pattern
    if (row <= 8 && col <= 8) return;
    if (row <= 8 && col >= matrix.length - 8) return;
    if (row >= matrix.length - 8 && col <= 8) return;

    for (let r = -2; r <= 2; r++) {
      for (let c = -2; c <= 2; c++) {
        const mr = row + r, mc = col + c;
        if (mr < 0 || mr >= matrix.length || mc < 0 || mc >= matrix.length) continue;
        const isBorder = Math.abs(r) === 2 || Math.abs(c) === 2;
        const isCenter = r === 0 && c === 0;
        matrix[mr][mc] = isBorder || isCenter;
        reserved[mr][mc] = true;
      }
    }
  },

  placeData(matrix, reserved, bits, size) {
    let bitIdx = 0;
    let upward = true;

    for (let col = size - 1; col >= 0; col -= 2) {
      if (col === 6) col = 5; // Skip timing column

      const rows = upward
        ? Array.from({ length: size }, (_, i) => size - 1 - i)
        : Array.from({ length: size }, (_, i) => i);

      for (const row of rows) {
        for (let dc = 0; dc <= 1; dc++) {
          const c = col - dc;
          if (c < 0) continue;
          if (reserved[row][c]) continue;
          matrix[row][c] = bitIdx < bits.length ? bits[bitIdx] === 1 : false;
          bitIdx++;
        }
      }
      upward = !upward;
    }
  },

  placeFormatInfo(matrix, bits, size) {
    // Around top-left finder
    for (let i = 0; i < 6; i++) matrix[8][i] = bits[i] === 1;
    matrix[8][7] = bits[6] === 1;
    matrix[8][8] = bits[7] === 1;
    matrix[7][8] = bits[8] === 1;
    for (let i = 9; i < 15; i++) matrix[14 - i][8] = bits[i] === 1;

    // Bottom-left and top-right
    for (let i = 0; i < 8; i++) matrix[size - 1 - i][8] = bits[i] === 1;
    for (let i = 8; i < 15; i++) matrix[8][size - 15 + i] = bits[i] === 1;
  },
};
