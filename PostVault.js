"use strict";

function PostVault(readyCallback) {
	const _PV_UPLOAD_SIZE_MAX = 4294967296; // 4 GiB
	const _PV_CHUNKSIZE = 16777216;
	const _PV_BLOCKSIZE = 16;
	const _PV_FLAG_U1 = 4096;
	const _PV_FLAG_REPLACE = 8192;
	const _PV_FLAG_U3 = 16384;
	const _PV_FLAG_U4 = 32768;

	const _PV_DOMAIN = document.head.querySelector("meta[name='postvault.domain']").content;
	const _PV_DOCSPK = document.head.querySelector("meta[name='postvault.spk']").content;

//	if (!_PV_DOMAIN || !new RegExp(/^[0-9a-z.-]{1,63}\.[0-9a-z-]{2,63}$/).test(_PV_DOMAIN) || !_PV_DOCSPK || !new RegExp("^[0-9A-f]{" + (sodium.crypto_box_PUBLICKEYBYTES * 2).toString() + "}$").test(_PV_DOCSPK)) {
//		readyCallback(false);
//		return;
//	}

	const _PV_SPK = sodium.from_hex(_PV_DOCSPK);

	function _pvFile(path, ts, blocks) {
		this.path = path;
		this.ts = ts;
		this.blocks = blocks;
	};

	let _own_umk;
	let _own_uak;
	let _own_uid;

	let _files = [new _pvFile("", 0, 0)];

	const _getBinTs = function() {
		const ts = BigInt(Date.now());

		return new Uint8Array([
			Number(ts & 255n),
			Number((ts >> 8n) & 255n),
			Number((ts >> 16n) & 255n),
			Number((ts >> 24n) & 255n),
			Number((ts >> 32n) & 255n)
		]);
	}

	const _fetchBinary = async function(urlBase, postData, callback) {
		const r = await fetch("http://" + _PV_DOMAIN + ":1307/" + sodium.to_base64(urlBase, sodium.base64_variants.URLSAFE), {
			method: postData? "POST" : "GET",
			cache: "no-store",
			credentials: "omit",
			headers: new Headers({
				"Accept": "",
				"Accept-Language": ""
			}),
			mode: "cors",
			redirect: "error",
			referrer: "",
			referrerPolicy: "no-referrer",
			body: (typeof(postData) === "object") ? postData : null
		});

		callback((r.statusText === "PV") ? new Uint8Array(await r.arrayBuffer()) : null);
	};

	const _fetchEncrypted = async function(slot, chunk, binTs, content, mfk, flagReplace, callback) {
		if ((slot && (typeof(slot) !== "number" || slot < 0 || slot > 255)) || (content && ((typeof(content) !== "object" && content !== "DELETE") || content.length > _PV_UPLOAD_SIZE_MAX))) {
			callback(0x04);
			return;
		}

		const aes_nonce = new Uint8Array(12); // 96 bits
		aes_nonce.set(binTs? binTs : _getBinTs());

		const aes_src = new Uint8Array(34);
		aes_src.set(new Uint8Array(new Uint16Array([slot | (flagReplace? _PV_FLAG_REPLACE : 0)]).buffer));
		if (mfk) aes_src.set(mfk, 2);

		const aes_enc = new Uint8Array(await window.crypto.subtle.encrypt({name: "AES-GCM", iv: aes_nonce}, await window.crypto.subtle.importKey("raw", _own_uak, {"name": "AES-GCM"}, false, ["encrypt"]), aes_src));

		const box_src = new Uint8Array(_own_uid.length + 6 + aes_enc.length);
		box_src.set(_own_uid);
		box_src.set(aes_nonce.slice(0, 5), _own_uid.length);
		box_src[_own_uid.length + 5] = chunk;
		box_src.set(aes_enc, _own_uid.length + 6);

		const box_keys = sodium.crypto_box_keypair();
		const box_nonce = new Uint8Array(sodium.crypto_box_NONCEBYTES);
		box_nonce.fill(0x01);
		const box_enc = sodium.crypto_box_easy(box_src, box_nonce, _PV_SPK, box_keys.privateKey);

		const box_wrap = new Uint8Array(box_enc.length + sodium.crypto_box_PUBLICKEYBYTES);
		box_wrap.set(box_enc);
		box_wrap.set(box_keys.publicKey, box_enc.length);

		box_nonce.fill(0x02);
		const postData = (content && (typeof(content) === "object")) ? sodium.crypto_box_easy(content, box_nonce, _PV_SPK, box_keys.privateKey) : content;

		_fetchBinary(box_wrap, postData, function(result_box) {
			if (!result_box) {callback(-1); return;}

			box_nonce.fill(0xFF);

			let dec;
			try {dec = sodium.crypto_box_open_easy(result_box, box_nonce, _PV_SPK, box_keys.privateKey);}
			catch(e) {callback(null); console.log("f"); return;}

			// TODO: 5 bytes: LastMod

			callback(dec.slice(5));
		});
	};

	const _genIndex = function() {
		let lenIndex = 2;
		for (let i = 0; i < 4096; i++) {
			lenIndex += (_files[i] && _files[i].blocks > 0) ? (9 + sodium.from_string(_files[i].path).length) : 1;
		}

		let lenPadding = (lenIndex % 16 === 0) ? 0 : 16 - (lenIndex % 16);
		lenIndex += lenPadding;

		const pvInfo = new Uint8Array(lenIndex);
		pvInfo[0] = lenPadding;
		pvInfo[1] = 0; // No name

		let n = 2;

		for (let i = 0; i < 4096; i++) {
			if (_files[i] && _files[i].blocks > 0) {
				const path = sodium.from_string(_files[i].path);

				pvInfo.set(new Uint8Array(new Uint32Array([_files[i].ts]).buffer), n);
				pvInfo.set(new Uint8Array(new Uint32Array([_files[i].blocks]).buffer), n + 4);
				pvInfo.set(new Uint8Array([path.length]), n + 8);
				pvInfo.set(path, n + 9);

				n += 9 + path.length;
			} else {
				pvInfo[n] = 0;
				n++;
			}
		}

		return pvInfo;
	};

	const _getFreeSlot = function() {
		for (let i = 1; i < 256; i++) {
			if (!_files[i]) return i;
		}

		return -1;
	};

	const _getMfk = function(fileBaseKey, chunk) {
		return sodium.crypto_kdf_derive_from_key(32, chunk, "PVf-MFK0", fileBaseKey);
	};

	const _getUfk = function(fileBaseKey, chunk) {
		return sodium.crypto_kdf_derive_from_key(sodium.crypto_aead_chacha20poly1305_KEYBYTES, chunk, "PVf-UFK0", fileBaseKey);
	};

	const _decryptMfk = async function(src, mfk, callback) {
		const mfk_key = await window.crypto.subtle.importKey("raw", mfk, {"name": "AES-CTR"}, false, ["decrypt"]);
		const firstBlock = src.slice(0, 16);
		const dec = new Uint8Array(src.length);
		dec.set(new Uint8Array(await window.crypto.subtle.decrypt({name: "AES-CTR", counter: new Uint8Array(16), length: 32}, mfk_key, firstBlock)).slice(0, 16));
		dec.set(new Uint8Array(await window.crypto.subtle.decrypt({name: "AES-CTR", counter: firstBlock, length: 32}, mfk_key, src.slice(16))), 16);
		callback(dec);
	}

	const _getFileBaseKey = function(slot, binTs, blocks) {
		const bytes = new Uint8Array([
			binTs[0],
			binTs[1],
			binTs[2],
			binTs[3],
			binTs[4],
			(slot) & 255,
			((slot >> 8) & 15) | ((blocks & 15) << 4),
			(blocks >> 4) & 255,
			(blocks >> 12) & 255,
			(blocks >> 20) & 255
		]);

		return sodium.crypto_generichash(sodium.crypto_kdf_KEYBYTES, bytes, _own_umk);
	}

	const _getNonce = function(len) {
		return sodium.crypto_generichash(len, _PV_SPK, null);
	}

	// Public functions

	this.getFileCount = function() {
		let count = 0;

		for (let i = 0; i < 256; i++) {
			if (_files[i].path) count++;
		}

		return count;
	};

	this.getFolderContents = function(basePath, wantFiles, wantFolders) {if(typeof(basePath)!=="string") return;
		if (basePath !== "" && !basePath.endsWith("/")) basePath += "/";
		if (basePath.startsWith("/")) basePath = basePath.substr(1);

		let list = [];

		_files.forEach(function(f, i) {
			if (i === 0) return;

			if (f.path.startsWith(basePath)) {
				const slash = f.path.substr(basePath.length).indexOf("/");
				if (wantFiles && slash === -1) {
					list.push(i);
				} else if (wantFolders && slash >= 0) {
					const fol = f.path.substr(basePath.length).substr(0, slash);
					if (list.indexOf(fol) === -1) list.push(fol);
				}
			}
		});

		return list;
	}

	this.getFilePath = function(num) {if(typeof(num)!=="number") return; return _files[num]? _files[num].path : null;};
	this.getFileSize = function(num) {if(typeof(num)!=="number") return; return _files[num]? _files[num].blocks * _PV_BLOCKSIZE : null;};
	this.getFileTime = function(num) {if(typeof(num)!=="number") return; return _files[num]? _files[num].ts : null;};

	this.getTotalFiles = function() {return _files.length;};
	this.getTotalSize = function() {
		let b = 0;
		_files.forEach(function(f) {b += f.blocks * _PV_BLOCKSIZE;});
		return b;
	}

	this.moveFile = function(num, newPath) {if(typeof(num)!=="number" || typeof(newPath)!=="string" || newPath.length<1 || !_files[num]) return false; _files[num].path = newPath; return true;};

	this.uploadIndex = function(callback) {if(typeof(callback)!=="function"){return;}
		const aead_src = _genIndex();
		const binTs = _getBinTs();
		const totalBlocks = (aead_src.length + sodium.crypto_aead_chacha20poly1305_ABYTES) / _PV_BLOCKSIZE;
		const fileBaseKey = _getFileBaseKey(0, binTs, totalBlocks);

		const aead_enc = sodium.crypto_aead_chacha20poly1305_encrypt(aead_src, null, null, _getNonce(sodium.crypto_aead_chacha20poly1305_NPUBBYTES), _getUfk(fileBaseKey, 0));

		_fetchEncrypted(0, 0, binTs, aead_enc, _getMfk(fileBaseKey, 0), true, function(status) {
			callback(typeof(status) === "number" ? status : status[0]);
		});
	};

	const _uploadChunks = async function(file, slot, binTs, totalBlocks, lenPadding, offset, totalChunks, chunk, progressCallback, endCallback) {
		progressCallback("Reading chunk " + (chunk + 1) + " of " + totalChunks, chunk * 2, totalChunks * 2);
		const contents = await file.slice(offset, offset + _PV_CHUNKSIZE - sodium.crypto_aead_chacha20poly1305_ABYTES);
		const contentsAb = await contents.arrayBuffer();

		let aead_src;
		if (chunk + 1 === totalChunks) {
			aead_src = new Uint8Array(contents.size + lenPadding);
			aead_src.set(new Uint8Array(contentsAb));
		} else aead_src = new Uint8Array(contentsAb);

		progressCallback("Encrypting chunk " + (chunk + 1) + " of " + totalChunks, chunk * 2 + 0.5, totalChunks * 2);
		const fileBaseKey = _getFileBaseKey(slot, binTs, totalBlocks);
		const aead_enc = sodium.crypto_aead_chacha20poly1305_encrypt(aead_src, null, null, _getNonce(sodium.crypto_aead_chacha20poly1305_NPUBBYTES), _getUfk(fileBaseKey, chunk));

		offset += _PV_CHUNKSIZE - sodium.crypto_aead_chacha20poly1305_ABYTES;

		progressCallback("Uploading chunk " + (chunk + 1) + " of " + totalChunks, chunk * 2 + 1, totalChunks * 2);
		_fetchEncrypted(slot, chunk, null, aead_enc, _getMfk(fileBaseKey, chunk), false, function(status) {
			if (typeof(status) === "number") {
				endCallback("Error: " + status);
			} else if (chunk + 1 === totalChunks) {
				endCallback("Done");
			} else {
				_uploadChunks(file, slot, binTs, totalBlocks, lenPadding, offset, totalChunks, chunk + 1, progressCallback, endCallback);
			}
		});
	}

	this.uploadFile = async function(folderPath, file, progressCallback, endCallback) {if(typeof(folderPath)!=="string" || typeof(file)!=="object" || typeof(endCallback)!=="function"){return;}
		if (folderPath.startsWith("/")) folderPath = folderPath.substr(1);
		if (folderPath !== "" && !folderPath.endsWith("/")) folderPath += "/";

		const slot = _getFreeSlot();
		if (slot < 0) {endCallback(-1); return;}

		let lenTotal = 2 + file.name.length + file.size;
		let lenPadding = (lenTotal % 16 === 0) ? 0 : 16 - (lenTotal & 15);
		lenTotal += lenPadding;

		let totalChunks = Math.ceil(lenTotal / _PV_CHUNKSIZE);
		lenTotal += totalChunks * sodium.crypto_aead_chacha20poly1305_ABYTES;

		if (totalChunks < Math.ceil(lenTotal / _PV_CHUNKSIZE) || lenTotal % _PV_CHUNKSIZE == 0) {
			lenTotal += sodium.crypto_aead_chacha20poly1305_ABYTES;
			totalChunks++;
		}

		const binTs = _getBinTs();
		const totalBlocks = lenTotal / _PV_BLOCKSIZE;
		const fileBaseKey = _getFileBaseKey(slot, binTs, totalBlocks);

		const contents = await file.slice(0, _PV_CHUNKSIZE - 2 - file.name.length - sodium.crypto_aead_chacha20poly1305_ABYTES);
		const contentsAb = await contents.arrayBuffer();

		const aead_src_len = ((totalChunks > 1) ? _PV_CHUNKSIZE : lenTotal) - sodium.crypto_aead_chacha20poly1305_ABYTES;
		const aead_src = new Uint8Array(aead_src_len);
		const filename = sodium.from_string(file.name);
		aead_src.set(new Uint8Array([lenPadding, filename.length]));
		aead_src.set(filename, 2);
		aead_src.set(new Uint8Array(contentsAb), 2 + filename.length);

		progressCallback("Encrypting chunk 1 of " + totalChunks, 0, totalChunks * 2);
		const aead_enc = sodium.crypto_aead_chacha20poly1305_encrypt(aead_src, null, null, _getNonce(sodium.crypto_aead_chacha20poly1305_NPUBBYTES), _getUfk(fileBaseKey, 0));

		progressCallback("Uploading chunk 1 of " + totalChunks, 0, totalChunks * 2);
		_fetchEncrypted(slot, 0, binTs, aead_enc, _getMfk(fileBaseKey, 0), true, function(status) {
			if (typeof(status) === "number") {
				endCallback("Error: " + status);
			} else {
				_files[slot] = new _pvFile(folderPath + file.name, Math.round(file.lastModified / 1000), totalBlocks);

				if (totalChunks === 1) {
					endCallback("Done");
				} else {
					_uploadChunks(file, slot, binTs, totalBlocks, lenPadding, contents.size, totalChunks, 1, progressCallback, endCallback);
				}
			}
		});
	};

	const downloadChunks = function(slot, chunk, totalChunks, lenPadding, writer, progressCallback, endCallback) {
		progressCallback("Downloading chunk " + (chunk + 1) + " of " + totalChunks, chunk * 2, totalChunks * 2);

		_fetchEncrypted(slot, chunk, null, null, null, null, function(resp) {
			if (typeof(resp) === "number") {writer.close(); endCallback("Fail: " + resp); return;}

			const binTs = resp.slice(0, 5);
			const totalBlocks = new Uint32Array(resp.slice(5, 9).buffer)[0];
			const fileBaseKey = _getFileBaseKey(slot, binTs, totalBlocks);

			progressCallback("Decrypting (AES) chunk " + (chunk + 1) + " of " + totalChunks, chunk * 2 + 1, totalChunks * 2);
			_decryptMfk(resp.slice(9), _getMfk(fileBaseKey, chunk), async function(dec) {
				progressCallback("Decrypting (ChaCha20) chunk " + (chunk + 1) + " of " + totalChunks, chunk * 2 + 1.333, totalChunks * 2);
				dec = sodium.crypto_aead_chacha20poly1305_decrypt(null, dec, null, _getNonce(sodium.crypto_aead_chacha20poly1305_NPUBBYTES), _getUfk(fileBaseKey, chunk));

				progressCallback("Writing chunk " + (chunk + 1) + " of " + totalChunks, chunk * 2 + 1.667, totalChunks * 2);
				if (chunk + 1 === totalChunks) {
					writer.write(dec.slice(0, dec.length - lenPadding));
					writer.close();
					endCallback("Done");
					return;
				}

				writer.write(dec);

				downloadChunks(slot, chunk + 1, totalChunks, lenPadding, writer, progressCallback, endCallback);
			});
		});
	};

	this.downloadFile = async function(slot, progressCallback, endCallback) {if(typeof(slot)!=="number" || typeof(endCallback)!=="function"){return;}
		const totalChunks = Math.ceil((_files[slot].blocks * _PV_BLOCKSIZE) / _PV_CHUNKSIZE);

		if (!window.showSaveFilePicker && totalChunks > 1) {
			endCallback("Your broswer lacks support for downloading large files");
			return;
		}

		let fileName = (_files[slot]) ? _files[slot].path : "Unknown";
		const fileHandle = (totalChunks > 1) ? await window.showSaveFilePicker({suggestedName: fileName}) : null;
		progressCallback("Downloading chunk 1 of " + totalChunks , 0, totalChunks * 2);

		_fetchEncrypted(slot, 0, null, null, null, null, function(resp) {
			if (typeof(resp) === "number") {endCallback("Error: " + resp); return;}

			const binTs = resp.slice(0, 5);
			const totalBlocks = new Uint32Array(resp.slice(5, 9).buffer)[0];
			const fileBaseKey = _getFileBaseKey(slot, binTs, totalBlocks);

			progressCallback("Decrypting (AES) chunk 1 of " + totalChunks, 1, totalChunks * 2);
			_decryptMfk(resp.slice(9), _getMfk(fileBaseKey, 0), async function(dec) {
				progressCallback("Decrypting (ChaCha20) chunk 1 of " + totalChunks, 1.333, totalChunks * 2);
				dec = sodium.crypto_aead_chacha20poly1305_decrypt(null, dec, null, _getNonce(sodium.crypto_aead_chacha20poly1305_NPUBBYTES), _getUfk(fileBaseKey, 0));
				progressCallback("Writing chunk 1 of " + totalChunks, 1.667, totalChunks * 2);

				fileName = sodium.to_string(dec.slice(2, 2 + dec[1]));
				const lenPadding = dec[0];
				dec = dec.slice(2 + dec[1]);

				if (fileHandle) {
					const writer = await fileHandle.createWritable();

					if (totalChunks > 1) {
						writer.write(dec);
						downloadChunks(slot, 1, totalChunks, lenPadding, writer, progressCallback, endCallback);
					} else {
						writer.write(dec.slice(0, dec.length - lenPadding));
						writer.close();
						endCallback("Done");
					}
				} else {
					const a = document.createElement("a");
					a.href = URL.createObjectURL(new Blob([dec.slice(0, dec.length - lenPadding)]));
					a.download = fileName;
					a.click();

					URL.revokeObjectURL(a.href);
					a.href = "";
					a.download = "";
					endCallback("Done");
				}
			});
		});
	};

	this.downloadIndex = function(callback) {if(typeof(callback)!=="function"){return;}
		_fetchEncrypted(0, 0, null, null, null, null, function(resp) {
			if (typeof(resp) === "number") {callback(resp); return;}

			const binTs = resp.slice(0, 5);
			const totalBlocks = new Uint32Array(resp.slice(5, 9).buffer)[0];
			const fileBaseKey = _getFileBaseKey(0, binTs, totalBlocks);

			_decryptMfk(resp.slice(9), _getMfk(fileBaseKey, 0), function(dec) {
				dec = sodium.crypto_aead_chacha20poly1305_decrypt(null, dec, null, _getNonce(sodium.crypto_aead_chacha20poly1305_NPUBBYTES), _getUfk(fileBaseKey, 0));
				dec = dec.slice(2, dec.length - dec[0]);

				let n = 0;
				for (let i = 0; n < dec.length; i++) {
					if (dec[n] == 0) {n++; continue;}

					const fileTime = new Uint32Array(dec.slice(n, n + 4).buffer)[0];
					const fileBlocks = new Uint32Array(dec.slice(n + 4, n + 8).buffer)[0];
					const fileName = sodium.to_string(dec.slice(n + 9, n + 9 + dec[n + 8]));
					_files[i] = new _pvFile(fileName, fileTime, fileBlocks);
					n += 9 + dec[n + 8];
				}

				callback(0);
			});
		});
	};

	this.deleteFile = function(slot, callback) {if(typeof(slot)!=="number" || typeof(callback)!=="function"){return;}
		_fetchEncrypted(slot, 0, null, "DELETE", null, null, function(resp) {
			if (typeof(resp) === "number") {
				callback(resp);
				return;
			}

			_files[slot] = null;
			callback(0);
		});
	};

	this.setKeys = function(umk_hex, callback) {if(typeof(umk_hex)!=="string" || typeof(callback)!=="function"){return;}
		if (umk_hex.length !== sodium.crypto_kdf_KEYBYTES * 2) {
			callback(false);
			return;
		}

		_own_umk = sodium.from_hex(umk_hex);

		const urk = sodium.crypto_kdf_derive_from_key(36, 1, "PVu-URK0", _own_umk);
		_own_uak = urk.slice(0, 32);
		_own_uid = urk.slice(32);

		callback(true);
	};

	readyCallback(true);
}
