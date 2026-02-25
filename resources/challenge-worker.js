//SPDX-License-Identifier: AGPL-3.0-only
async function checkDifficulty(data, difficulty) {
	const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", data));
	let i = 0;
	while (difficulty > 8) {
		if (hash[i++] !== 0)
			return false;
		difficulty -= 8;
	}

	return (0b11111111 << 8 - difficulty & 0xFF & hash[i]) === 0;
}

async function solve(difficulty, serverData, nonceLength) {
	const serverDataLength = serverData.length / 2;
	const data = new Uint8Array(serverDataLength + nonceLength);
	data.setFromHex(serverData);

	const nonceBinary = new Uint8Array(data.buffer, serverDataLength);
	const nonce = new Uint32Array(data.buffer, serverDataLength);
	for (let i = 0; i < nonce.length; ++i)
		nonce[i] = Math.random () * 0xFFFF_FFFF;

	let iter = 0;
	while (true) {
		if (++iter % 5000 === 0) {
			postMessage([0, iter, nonceBinary.toHex()]);
		}

		if (await checkDifficulty(data, difficulty))
			break;

		for (let i = 0; i < nonce.length; ++i) {
			if (nonce[i]++ !== 0xFFFF_FFFF)
				break;
		}
	}
	return [iter, data];
}


if (!Uint8Array.prototype.setFromHex) {
	Uint8Array.prototype.setFromHex = function(string) {
		if (string.length % 2 != 0)
			throw SyntaxError("hex-string must have an even number of characters");
		len = Math.min(this.length * 2, string.length);
		for (let i = 0; i < len; i++) {
			const digit = parseInt(string[i], 16);
			if (isNaN(digit))
				throw SyntaxError(`'${string[i]}' is not a valid hex-digit`);
			if (i % 2 == 0)
				this[i / 2] = digit << 4;
			else
				this[(i-1) / 2] |= digit;
		}
		return {read: len, written: len / 2};
	}
}

if (!Uint8Array.prototype.toHex) {
	Uint8Array.prototype.toHex = function() {
		result = "";
		for (let i = 0; i < this.length; i++) {
			if (this[i] < 0x10)
				result += "0";
			result += this[i].toString(16);
		}
		return result;
	}
}

if (crypto.subtle) {
	onmessage = m => {
		solve(m.data[0], m.data[1], m.data[2]).then(result => {
			const [iter, data] = result;
			postMessage([2, iter, data.toHex()]);

		}).catch(e => {
			console.error(e);
			postMessage([1, e.toString()]);
		});
	};

} else {
	postMessage([1, "Hash API is not available, you are either using an outdated browser or not visiting through HTTPS."]);
}
