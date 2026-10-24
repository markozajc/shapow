//SPDX-License-Identifier: AGPL-3.0-only
(function () {
	// polyfills
	if (!Uint8Array.prototype.setFromHex) {
		Uint8Array.prototype.setFromHex = function (string) {
			if (string.length % 2 !== 0) throw SyntaxError("hex-string must have an even number of characters");
			const len = Math.min(this.length * 2, string.length);
			for (let i = 0; i < len; i++) {
				const digit = Number.parseInt(string[i], 16);
				if (Number.isNaN(digit)) throw SyntaxError(`'${string[i]}' is not a valid hex-digit`);
				if (i % 2 === 0) this[i / 2] = digit << 4;
				else this[(i - 1) / 2] |= digit;
			}
			return { read: len, written: len / 2 };
		};
	}

	if (!Uint8Array.prototype.toHex) {
		Uint8Array.prototype.toHex = function () {
			let result = "";
			for (let i = 0; i < this.length; i++) {
				if (this[i] < 0x10) result += "0";
				result += this[i].toString(16);
			}
			return result;
		};
	}

	/**
	 * Adapted from https://github.com/kawanet/sha256-uint8array/blob/main/lib/sha256-uint8array.ts
	 * MIT License
	 *
	 * Copyright (c) 2020-2026 Yusuke Kawasaki
	 *
	 * Permission is hereby granted, free of charge, to any person obtaining a copy
	 * of this software and associated documentation files (the "Software"), to deal
	 * in the Software without restriction, including without limitation the rights
	 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
	 * copies of the Software, and to permit persons to whom the Software is
	 * furnished to do so, subject to the following conditions:
	 */
	const Hash = (function () {
		// first 32 bits of the fractional parts of the cube roots of the first 64 primes 2..311
		const K = [
			0x428a2f98 | 0,
			0x71374491 | 0,
			0xb5c0fbcf | 0,
			0xe9b5dba5 | 0,
			0x3956c25b | 0,
			0x59f111f1 | 0,
			0x923f82a4 | 0,
			0xab1c5ed5 | 0,
			0xd807aa98 | 0,
			0x12835b01 | 0,
			0x243185be | 0,
			0x550c7dc3 | 0,
			0x72be5d74 | 0,
			0x80deb1fe | 0,
			0x9bdc06a7 | 0,
			0xc19bf174 | 0,
			0xe49b69c1 | 0,
			0xefbe4786 | 0,
			0x0fc19dc6 | 0,
			0x240ca1cc | 0,
			0x2de92c6f | 0,
			0x4a7484aa | 0,
			0x5cb0a9dc | 0,
			0x76f988da | 0,
			0x983e5152 | 0,
			0xa831c66d | 0,
			0xb00327c8 | 0,
			0xbf597fc7 | 0,
			0xc6e00bf3 | 0,
			0xd5a79147 | 0,
			0x06ca6351 | 0,
			0x14292967 | 0,
			0x27b70a85 | 0,
			0x2e1b2138 | 0,
			0x4d2c6dfc | 0,
			0x53380d13 | 0,
			0x650a7354 | 0,
			0x766a0abb | 0,
			0x81c2c92e | 0,
			0x92722c85 | 0,
			0xa2bfe8a1 | 0,
			0xa81a664b | 0,
			0xc24b8b70 | 0,
			0xc76c51a3 | 0,
			0xd192e819 | 0,
			0xd6990624 | 0,
			0xf40e3585 | 0,
			0x106aa070 | 0,
			0x19a4c116 | 0,
			0x1e376c08 | 0,
			0x2748774c | 0,
			0x34b0bcb5 | 0,
			0x391c0cb3 | 0,
			0x4ed8aa4a | 0,
			0x5b9cca4f | 0,
			0x682e6ff3 | 0,
			0x748f82ee | 0,
			0x78a5636f | 0,
			0x84c87814 | 0,
			0x8cc70208 | 0,
			0x90befffa | 0,
			0xa4506ceb | 0,
			0xbef9a3f7 | 0,
			0xc67178f2 | 0,
		];

		// Hash block/allocation sizes.
		const inputBytes = 64;
		const inputWords = inputBytes / 4;
		const highIndex = inputWords - 2;
		const lowIndex = inputWords - 1;
		const workWords = 64;

		// Full 64-word message schedule. The flat layout costs 192 bytes over
		// a 16-word ring but frees the hot loop from masking every index.
		const W = new Int32Array(workWords);

		const swap32 = (c) =>
			((c << 24) & 0xff000000) | ((c << 8) & 0xff0000) | ((c >> 8) & 0xff00) | ((c >> 24) & 0xff);

		const ch = (x, y, z) => z ^ (x & (y ^ z));
		const maj = (x, y, z) => (x & y) | (z & (x | y));

		const sigma0 = (x) => ((x >>> 2) | (x << 30)) ^ ((x >>> 13) | (x << 19)) ^ ((x >>> 22) | (x << 10));
		const sigma1 = (x) => ((x >>> 6) | (x << 26)) ^ ((x >>> 11) | (x << 21)) ^ ((x >>> 25) | (x << 7));
		const gamma0 = (x) => ((x >>> 7) | (x << 25)) ^ ((x >>> 18) | (x << 14)) ^ (x >>> 3);
		const gamma1 = (x) => ((x >>> 17) | (x << 15)) ^ ((x >>> 19) | (x << 13)) ^ (x >>> 10);

		return class {
			// first 32 bits of the fractional parts of the square roots of the first 8 primes 2..19
			#A;
			#B;
			#C;
			#D;
			#E;
			#F;
			#G;
			#H;
			#byte;
			#word;
			#size;

			constructor() {
				const buffer = new ArrayBuffer(80);
				this.#byte = new Uint8Array(buffer);
				this.#word = new Int32Array(buffer);
				this.#init();
			}

			#init() {
				this.#A = 0x6a09e667 | 0;
				this.#B = 0xbb67ae85 | 0;
				this.#C = 0x3c6ef372 | 0;
				this.#D = 0xa54ff53a | 0;
				this.#E = 0x510e527f | 0;
				this.#F = 0x9b05688c | 0;
				this.#G = 0x1f83d9ab | 0;
				this.#H = 0x5be0cd19 | 0;
				this.#size = 0;
			}

			reset() {
				this.#byte.fill(0); // also takes care of word
				this.#init();
			}

			update(data) {
				const byteOffset = data.byteOffset;
				const length = data.byteLength;
				let blocks = (length / inputBytes) | 0;
				let offset = 0;

				// longer than 1 block
				if (blocks && !(byteOffset & 3) && !(this.#size % inputBytes)) {
					const block = new Int32Array(data.buffer, byteOffset, blocks * inputWords);
					while (blocks--) {
						this.#int32(block, offset >> 2);
						offset += inputBytes;
					}
					this.#size += offset;
				}

				// data: TypedArray | DataView
				const BYTES_PER_ELEMENT = data.BYTES_PER_ELEMENT;
				if (BYTES_PER_ELEMENT !== 1 && data.buffer) {
					const rest = new Uint8Array(data.buffer, byteOffset + offset, length - offset);
					return this.#uint8(rest);
				}

				// no more bytes
				if (offset === length) return this;

				// data: Uint8Array | Int8Array
				return this.#uint8(data, offset);
			}

			#uint8(data, offset) {
				const byte = this.#byte;
				const word = this.#word;
				const length = data.length;
				offset = offset | 0;

				while (offset < length) {
					const start = this.#size % inputBytes;
					let index = start;

					while (offset < length && index < inputBytes) {
						byte[index++] = data[offset++];
					}

					if (index >= inputBytes) {
						this.#int32(word);
					}

					this.#size += index - start;
				}

				return this;
			}

			#int32(data, offset) {
				let A = this.#A;
				let B = this.#B;
				let C = this.#C;
				let D = this.#D;
				let E = this.#E;
				let F = this.#F;
				let G = this.#G;
				let H = this.#H;
				let i = 0;
				offset = offset | 0;

				// The 64 rounds run as two loops so the round body carries no
				// per-round branch: the first 16 load input words, the rest
				// extend the schedule with direct in-bounds indices into W.
				// Rounds go in pairs: the second reads the first through fresh
				// bindings, halving the a..h state rotation assignments.
				for (i = 0; i < inputWords; i += 2) {
					const w0 = (W[i] = swap32(data[offset++]));
					const T1 = (H + sigma1(E) + ch(E, F, G) + K[i] + w0) | 0;
					const T2 = (sigma0(A) + maj(A, B, C)) | 0;
					const E1 = (D + T1) | 0;
					const A1 = (T1 + T2) | 0;
					const w1 = (W[i + 1] = swap32(data[offset++]));
					const T3 = (G + sigma1(E1) + ch(E1, E, F) + K[i + 1] + w1) | 0;
					const T4 = (sigma0(A1) + maj(A1, A, B)) | 0;
					H = F;
					G = E;
					F = E1;
					E = (C + T3) | 0;
					D = B;
					C = A;
					B = A1;
					A = (T3 + T4) | 0;
				}

				for (i = inputWords; i < workWords; i += 2) {
					const w0 = (W[i] = (gamma1(W[i - 2]) + W[i - 7] + gamma0(W[i - 15]) + W[i - 16]) | 0);
					const T1 = (H + sigma1(E) + ch(E, F, G) + K[i] + w0) | 0;
					const T2 = (sigma0(A) + maj(A, B, C)) | 0;
					const E1 = (D + T1) | 0;
					const A1 = (T1 + T2) | 0;
					const w1 = (W[i + 1] = (gamma1(W[i - 1]) + W[i - 6] + gamma0(W[i - 14]) + W[i - 15]) | 0);
					const T3 = (G + sigma1(E1) + ch(E1, E, F) + K[i + 1] + w1) | 0;
					const T4 = (sigma0(A1) + maj(A1, A, B)) | 0;
					H = F;
					G = E;
					F = E1;
					E = (C + T3) | 0;
					D = B;
					C = A;
					B = A1;
					A = (T3 + T4) | 0;
				}

				this.#A = (A + this.#A) | 0;
				this.#B = (B + this.#B) | 0;
				this.#C = (C + this.#C) | 0;
				this.#D = (D + this.#D) | 0;
				this.#E = (E + this.#E) | 0;
				this.#F = (F + this.#F) | 0;
				this.#G = (G + this.#G) | 0;
				this.#H = (H + this.#H) | 0;
			}

			digest() {
				const byte = this.#byte;
				const word = this.#word;
				let i = (this.#size % inputBytes) | 0;
				byte[i++] = 0x80;

				// pad 0 for current word
				while (i & 3) {
					byte[i++] = 0;
				}
				i >>= 2;

				if (i > highIndex) {
					while (i < inputWords) {
						word[i++] = 0;
					}
					i = 0;
					this.#int32(word);
				}

				// pad 0 for rest words
				while (i < inputWords) {
					word[i++] = 0;
				}

				// input size
				const bits64 = this.#size * 8;
				const low32 = (bits64 & 0xffffffff) >>> 0;
				const high32 = (bits64 - low32) / 0x100000000;
				if (high32) word[highIndex] = swap32(high32);
				if (low32) word[lowIndex] = swap32(low32);

				this.#int32(word);

				return this.#bin();
			}

			#bin() {
				const word = this.#word;

				word[0] = swap32(this.#A);
				word[1] = swap32(this.#B);
				word[2] = swap32(this.#C);
				word[3] = swap32(this.#D);
				word[4] = swap32(this.#E);
				word[5] = swap32(this.#F);
				word[6] = swap32(this.#G);
				word[7] = swap32(this.#H);

				// this would normally return a slice(0, 32), but we only look at the first N bytes anyway
				return this.#byte;
			}
		};
	})();

	function checkDifficulty(data, difficulty, hash) {
		const digest = hash.update(data).digest();
		let i = 0;
		while (difficulty > 8) {
			if (digest[i++] !== 0) return false;
			difficulty -= 8;
		}

		return ((0b11111111 << (8 - difficulty)) & 0xff & digest[i]) === 0;
	}

	function solve(difficulty, serverData, nonceLength) {
		const serverDataLength = serverData.length / 2;
		const data = new Uint8Array(serverDataLength + nonceLength);
		data.setFromHex(serverData);

		const nonceBinary = new Uint8Array(data.buffer, serverDataLength);
		const nonce = new Uint32Array(data.buffer, serverDataLength);
		for (let i = 0; i < nonce.length; ++i) nonce[i] = Math.random() * 0xffff_ffff;

		const hash = new Hash();

		let iter = 0;
		while (true) {
			if (++iter % 25_000 === 0) {
				postMessage([0, iter, nonceBinary.toHex()]);
			}

			if (checkDifficulty(data, difficulty, hash)) break;

			hash.reset();

			for (let i = 0; i < nonce.length; ++i) if (nonce[i]++ !== 0xffff_ffff) break;
		}
		return [iter, data];
	}

	onmessage = (m) => {
		try {
			const [iter, data] = solve(m.data[0], m.data[1], m.data[2]);
			postMessage([2, iter, data.toHex()]);
		} catch (e) {
			console.error(e);
			postMessage([1, e.toString()]);
		}
	};
})();
