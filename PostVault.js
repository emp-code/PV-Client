"use strict";

function PostVault(readyCallback) {
	const _PV_CHUNKSIZE = 4194304;
	const _PV_MAXFILES = 65535;

	const _PV_CMD_GET = 0;
	const _PV_CMD_VFY = 1;
	const _PV_CMD_DEL = 2;
	const _PV_CMD_ADD = 3;
	const _PV_CMD_UPD = 4;

	const _AEM_UAK_TYPE_URL = 0;
	const _AEM_UAK_POST = 64;

	const _BINTS_BEGIN = 1735689600000n; // 2025-01-01 00:00:00 UTC

	const _PV_APIURL = document.head.querySelector("meta[name='postvault.url']").content;
	const _PV_EXPIRATION = ["Disabled", "5 minutes", "1 hour", "6 hours", "24 hours", "7 days", "1 month", "∞"];

	function _pvFile(path, binTs, kib) {
		this.path = path;
		this.binTs = binTs;
		this.kib = kib;
	};

	let _own_uid;
	let _own_uak;
	let _own_fmk;

	let _files = [new _pvFile("", 0n, 0)];

	let _share_chunk1 = null;
	let _share_blocks = null;
	let _share_filename = null;

	// 42-bit millisecond timestamp, years 2025-2164
	const _getBinTs = function(ts) {
		const t = ts? ts : (BigInt(Date.now()) - _BINTS_BEGIN);

		return new Uint8Array([
			Number(t & 255n),
			Number((t >> 8n) & 255n),
			Number((t >> 16n) & 255n),
			Number((t >> 24n) & 255n),
			Number((t >> 32n) & 255n),
			Number((t >> 40n) & 3n)
		]);
	};

	const _aem_kdf_umk = function(size, n, key) {
		return sodium.crypto_stream_chacha20_ietf_xor_ic(new Uint8Array(size),
			/* Nonce   */ key.slice(32, 44),
			/* Counter */ new Uint32Array([(key[44] << 24) | (n << 8)])[0],
			/* Key     */ key.slice(0, 32));
	}

	// Use the 338-bit UAK to generate a 1-64 byte key
	const _aem_kdf_uak = function(size, binTs, post, type) {
		return sodium.crypto_stream_chacha20_ietf_xor_ic(new Uint8Array(size),
			/* Nonce   */ new Uint8Array([binTs[4], (binTs[5] & 3) | (post? _AEM_UAK_POST : 0) | type | (_own_uak[42] & 12), _own_uak[41], _own_uak[40], _own_uak[39], _own_uak[38], _own_uak[37], _own_uak[36], _own_uak[35], _own_uak[34], _own_uak[33], _own_uak[32]]),
			/* Counter */ new Uint32Array([binTs[0] | (binTs[1] << 8) | (binTs[2] << 16) | (binTs[3] << 24)])[0],
			/* Key     */ _own_uak.slice(0, 32));
	}

	// Use the 342-bit File Master Key to generate a 344-bit File Base Key
	const _getFbk = function(binTs) {
		return sodium.crypto_stream_chacha20_ietf_xor_ic(new Uint8Array(43),
			/* Nonce   */ new Uint8Array([binTs[4], (binTs[5] & 3) | (_own_fmk[42] & 252), _own_fmk[41], _own_fmk[40], _own_fmk[39], _own_fmk[38], _own_fmk[37], _own_fmk[36], _own_fmk[35], _own_fmk[34], _own_fmk[33], _own_fmk[32]]),
			/* Counter */ new Uint32Array([binTs[0] | (binTs[1] << 8) | (binTs[2] << 16) | (binTs[3] << 24)])[0],
			/* Key     */ _own_fmk.slice(0, 32));
	};

	// Use the 344-bit File Base Key to generate a 512-bit User File Key
	const _getUfk = function(fbk, chunk) {
		return sodium.crypto_stream_chacha20_ietf_xor_ic(new Uint8Array(64),
			/* Nonce   */ new Uint8Array([0, fbk[42], fbk[41], fbk[40], fbk[39], fbk[38], fbk[37], fbk[36], fbk[35], fbk[34], fbk[33], fbk[32]]),
			/* Counter */ chunk,
			/* Key     */ fbk.slice(0, 32));
	};

	// Use the 344-bit File Base Key to generate a 320-bit Mutual File Key
	const _getMfk = function(fbk, chunk) {
		return sodium.crypto_stream_chacha20_ietf_xor_ic(new Uint8Array(40),
			/* Nonce   */ new Uint8Array([1, fbk[42], fbk[41], fbk[40], fbk[39], fbk[38], fbk[37], fbk[36], fbk[35], fbk[34], fbk[33], fbk[32]]),
			/* Counter */ chunk,
			/* Key     */ fbk.slice(0, 32));
	};

	const _encryptedFilePost = function(src, chunk, bts) {
		const fbk = _getFbk(bts);
		const ufk = _getUfk(fbk, chunk);

		const post = new Uint8Array(40 + src.length + sodium.crypto_aead_aegis256_ABYTES);
		post.set(_getMfk(fbk, chunk));
		post.set(sodium.crypto_aead_aegis256_encrypt(src, null, null, ufk.slice(0, 32), ufk.slice(32)), 40);
		return post;
	}

	const _decryptUfk = function(src, chunk, fbk) {
		const ufk = _getUfk(fbk, chunk);
		let dec;
		try {dec = sodium.crypto_aead_aegis256_decrypt(null, src, null, ufk.slice(0, 32), ufk.slice(32));}
		catch(e) {console.log(e); return null;}
		return dec;
	}

	const _decryptSse = function(src, key) {
		return sodium.crypto_stream_chacha20_xor(src, key.slice(32), key.slice(0, 32));
	};

	const _pvApi_fetch = async function(urlBase, chunk, postData, callback) {
		let r;
//		try {
			r = await fetch(
					_PV_APIURL + "/" +
					sodium.to_base64(urlBase, sodium.base64_variants.URLSAFE) +
					sodium.to_base64(new Uint8Array([chunk & 255, (chunk >> 8) & 255, ((chunk >> 16) & 3) << 6]), sodium.base64_variants.URLSAFE).slice(0, 3)
				, {
				method: postData? "POST" : "GET",
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
//		} catch(e) {callback(0x02);}
		callback(r? ((r.status === 200) ? new Uint8Array(await r.arrayBuffer()) : r.status) : 0x02);
	};

	const _pvApi_urlBase = function(binTs, slot, cmd, share, post) {
		const urlKey = _aem_kdf_uak(35, binTs, post, _AEM_UAK_TYPE_URL);

		const urlBase = new Uint8Array(24);
		urlBase.set(new Uint8Array([
			binTs[0],
			binTs[1],
			binTs[2],
			binTs[3],
			binTs[4],
			binTs[5] | (((cmd & 7) ^ (urlKey[0] & 7)) << 2) | ((share << 5) ^ (urlKey[0] & 224)),
			(slot & 255) ^ urlKey[1],
			(slot >> 8) ^ urlKey[2]
		]));

		urlBase.set(sodium.crypto_onetimeauth(new Uint8Array([urlBase[5] & 252, urlBase[6], urlBase[7]]), urlKey.slice(3)), 8);
		return urlBase;
	}

	const _pvApi = function(binTs, slot, cmd, chunk, post, callback) {
		_pvApi_fetch(_pvApi_urlBase(binTs, slot, cmd, 0, (post != null)), chunk, post, function(result) {callback(result);});
	};

	const _genIndex = function() {
		let lenIndex = 0;
		for (let i = 0; i < _PV_MAXFILES; i++) {
			lenIndex += (_files[i] && _files[i].sz > 0) ? (9 + sodium.from_string(_files[i].path).length) : 1;
		}

		const pvInfo = new Uint8Array(lenIndex);
		let n = 0;

		for (let i = 1; i < _PV_MAXFILES; i++) {
			if (_files[i]) {
				const path = sodium.from_string(_files[i].path.replaceAll("//", "/"));
				const unitMib = _files[i].kib > 1048576;
				const sz = (_files[i].kib - 1) / (unitMib? 1024 : 1);

				pvInfo[n] = 128 | Number(_files[i].binTs & 127n);
				pvInfo[n + 1] = Number((_files[i].binTs >> 7n) & 255n);
				pvInfo[n + 2] = Number((_files[i].binTs >> 15n) & 255n);
				pvInfo[n + 3] = Number((_files[i].binTs >> 23n) & 255n);
				pvInfo[n + 4] = Number((_files[i].binTs >> 31n) & 255n);
				pvInfo[n + 5] = Number((_files[i].binTs >> 39n) & 7n) | (unitMib? 8 : 0) | ((sz & 15) << 4);
				pvInfo[n + 6] = (sz >> 4) & 255;
				pvInfo[n + 7] = (sz >> 12) & 255;
				pvInfo.set(path, n + 8);

				n += 9 + path.length;
			} else {
				let skipCount = 1;
				for (let j = i; j < _PV_MAXFILES; j++) {
					if (_files[i]) break;
					skipCount++;
					if (skipCount == 128) break;
				}

				pvInfo[n] = skipCount - 1;
				n++;
			}
		}

		return pvInfo;
	};

	const _getFreeSlot = function() {
		for (let i = 1; i < _PV_MAXFILES; i++) {
			if (!_files[i]) return i;
		}

		return -1;
	};

	const _getFileType = function(filename) {
		if (!filename) return null;

		const ext = filename.lastIndexOf(".");
		if (ext < 0) return null;

		switch (filename.substr(ext + 1).toLowerCase()) {
			case "bat":
			case "c":
			case "c++":
			case "cc":
			case "cpp":
			case "css":
			case "csv":
			case "cxx":
			case "eml":
			case "h":
			case "h++":
			case "hh":
			case "hpp":
			case "hxx":
			case "ini":
			case "java":
			case "js":
			case "json":
			case "log":
			case "lua":
			case "md":
			case "php":
			case "py":
			case "rb":
			case "rs":
			case "sh":
			case "txt":
			case "vbs":
			case "xml":
			case "yaml":
			case "yml":
				return "text";

			// For non-text formats, only formats supported by browsers are sensible
			case "apng":
			case "avif":
			case "bmp":
			case "gif":
			case "ico":
			case "jpeg":
			case "jpg":
			case "png":
			case "webp":
				return "image";

			case "aac":
			case "flac":
			case "m4a":
			case "m4b":
			case "mp3":
			case "oga":
			case "ogg":
			case "opus":
			case "wav":
				return "audio";

			case "avi":
			case "m4v":
			case "mkv":
			case "mov":
			case "mp4":
			case "ogv":
			case "ogx":
			case "webm":
				return "video";

			case "pdf":
				return "pdf";

			case "html":
			case "htm":
				return "html";

			case "svg":
				return "svg";
		}

		return null;
	};

	// Download/upload functions
	const _uploadChunks = async function(file, slot, bts, lenPadding, offset, totalChunks, chunk, progressCallback, endCallback) {
		progressCallback("Reading chunk " + (chunk + 1) + " of " + totalChunks, chunk, totalChunks);
		const contents = await file.slice(offset, offset + _PV_CHUNKSIZE - sodium.crypto_aead_aegis256_ABYTES);
		const contentsAb = await contents.arrayBuffer();

		let post_src;
		if (chunk + 1 === totalChunks) {
			post_src = new Uint8Array(contents.size + lenPadding);
			post_src.set(new Uint8Array(contentsAb));
		} else post_src = new Uint8Array(contentsAb);
		offset += _PV_CHUNKSIZE - sodium.crypto_aead_aegis256_ABYTES;

		progressCallback("Uploading chunk " + (chunk + 1) + " of " + totalChunks, chunk, totalChunks);
		_pvApi(_getBinTs(), slot, _PV_CMD_ADD, chunk, _encryptedFilePost(post_src, chunk, bts), function(status) {
			if (status !== 204) {
				endCallback("Error: " + status);
			} else if (chunk + 1 === totalChunks) {
				endCallback("Done");
			} else {
				_uploadChunks(file, slot, bts, lenPadding, offset, totalChunks, chunk + 1, progressCallback, endCallback);
			}
		});
	};

	const _downloadChunks = function(slot, chunk, totalChunks, lenPadding, writer, progressCallback, endCallback) {
		progressCallback("Downloading chunk " + (chunk + 1) + " of " + totalChunks, chunk, totalChunks);

		_pvApi(_getBinTs(), slot, _PV_CMD_GET, chunk, null, function(resp) {
			if (typeof(resp) === "number") {writer.close(); endCallback("Error: " + resp); return;}
			const sfk = resp.slice(0, 40);
			const bts = resp.slice(40, 46);
			resp = resp.slice(46);

			const fbk = _getFbk(bts);
			const mfk = _getMfk(fbk, chunk);
			const sse_key = new Uint8Array([
				mfk[0]  ^ sfk[0],  mfk[1]  ^ sfk[1],  mfk[2]  ^ sfk[2],  mfk[3]  ^ sfk[3],  mfk[4]  ^ sfk[4],  mfk[5]  ^ sfk[5],  mfk[6]  ^ sfk[6],  mfk[7]  ^ sfk[7],  mfk[8]  ^ sfk[8],  mfk[9]  ^ sfk[9],
				mfk[10] ^ sfk[10], mfk[11] ^ sfk[11], mfk[12] ^ sfk[12], mfk[13] ^ sfk[13], mfk[14] ^ sfk[14], mfk[15] ^ sfk[15], mfk[16] ^ sfk[16], mfk[17] ^ sfk[17], mfk[18] ^ sfk[18], mfk[19] ^ sfk[19],
				mfk[20] ^ sfk[20], mfk[21] ^ sfk[21], mfk[22] ^ sfk[22], mfk[23] ^ sfk[23], mfk[24] ^ sfk[24], mfk[25] ^ sfk[25], mfk[26] ^ sfk[26], mfk[27] ^ sfk[27], mfk[28] ^ sfk[28], mfk[29] ^ sfk[29],
				mfk[30] ^ sfk[30], mfk[31] ^ sfk[31], mfk[32] ^ sfk[32], mfk[33] ^ sfk[33], mfk[34] ^ sfk[34], mfk[35] ^ sfk[35], mfk[36] ^ sfk[36], mfk[37] ^ sfk[37], mfk[38] ^ sfk[38], mfk[39] ^ sfk[39],
			]);

			progressCallback("Decrypting (ChaCha20) chunk " + (chunk + 1) + " of " + totalChunks, chunk, totalChunks);
			let dec = _decryptSse(resp, sse_key);

			progressCallback("Decrypting (AEGIS) chunk " + (chunk + 1) + " of " + totalChunks, chunk, totalChunks);
			dec = _decryptUfk(dec, chunk, fbk);
			if (!dec) {endCallback("Failed decrypting chunk " + (chunk + 1)); return;}

			progressCallback("Writing chunk " + (chunk + 1) + " of " + totalChunks, chunk, totalChunks);
			if (chunk + 1 === totalChunks) {
				writer.write(dec.slice(0, dec.length - lenPadding));
				writer.close();
				endCallback("Done");
				return;
			}

			writer.write(dec);

			_downloadChunks(slot, chunk + 1, totalChunks, lenPadding, writer, progressCallback, endCallback);
		});
	};

	// Public functions
	this.getExpirationValues = function() {return _PV_EXPIRATION;};

	this.getFolderContents = function(basePath, wantFiles, wantFolders) {if(typeof(basePath)!=="string") return;
		if (basePath !== "" && !basePath.endsWith("/")) basePath += "/";
		if (basePath.startsWith("/")) basePath = basePath.substr(1);

		let list = [];

		_files.forEach(function(f, i) {
			if (i === 0 || !f) return;

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

		if (!wantFiles && wantFolders) list.sort();
		if (wantFiles && !wantFolders) list.sort((a, b) => (_files[a].path > _files[b].path) ? 1 : -1);

		return list;
	};

	this.getFilePath = function(num) {if(typeof(num)!=="number") return; return _files[num]? _files[num].path : null;};
	this.getFileSize = function(num) {if(typeof(num)!=="number") return; return _files[num]? _files[num].kib : null;};
	this.getFileTime = function(num) {if(typeof(num)!=="number") return; return _files[num]? Number(_files[num].binTs + 1735689600000n) : null;};

	this.getTotalFiles = function() {return _files.length;};
	this.getTotalSize = function() {
//		let b = 0;
//		_files.forEach(function(f) {if (f) {b += f.blocks;}});
//		return b * _PV_BLOCKSIZE;
		return 0;
	};

	this.moveFile = function(num, newPath) {if(typeof(num)!=="number" || typeof(newPath)!=="string" || newPath.length<1 || !_files[num]) return false; _files[num].path = newPath; return true;};

	this.uploadIndex = function(callback) {if(typeof(callback)!=="function"){return;}
		const bts = _getBinTs();

		_pvApi(bts, 0, _PV_CMD_ADD, 0, _encryptedFilePost(_genIndex(), 0, bts), function(resp) {
			callback(resp);
		});
	};

	this.uploadFile = async function(folderPath, file, progressCallback, endCallback) {if(typeof(folderPath)!=="string" || typeof(file)!=="object" || typeof(endCallback)!=="function"){return;}
		if (folderPath && folderPath.startsWith("/")) folderPath = folderPath.substr(1);
		if (folderPath && !folderPath.endsWith("/")) folderPath += "/";
		if (sodium.from_string(folderPath + file.name).length > 255) return;

		const slot = _getFreeSlot();
		if (slot < 0) {endCallback(-1); return;}

		const filename = sodium.from_string(file.name);

		let lenTotal = 2 + filename.length + file.size;
		let lenPadding = (lenTotal % 16 === 0) ? 0 : 16 - (lenTotal & 15);
		lenTotal += lenPadding;

		let totalChunks = Math.ceil(lenTotal / _PV_CHUNKSIZE);
		lenTotal += totalChunks * sodium.crypto_aead_aegis256_ABYTES;

		if (totalChunks < Math.ceil(lenTotal / _PV_CHUNKSIZE) || lenTotal % _PV_CHUNKSIZE == 0) {
			lenTotal += sodium.crypto_aead_aegis256_ABYTES;
			totalChunks++;
		}

		if (totalChunks > 1048575) {endCallback("Error: File too large (1 TiB max)"); return;}

		const contents = await file.slice(0, _PV_CHUNKSIZE - 2 - filename.length - sodium.crypto_aead_aegis256_ABYTES);
		const contentsAb = await contents.arrayBuffer();

		const post_src_len = ((totalChunks > 1) ? _PV_CHUNKSIZE : lenTotal) - sodium.crypto_aead_aegis256_ABYTES;
		const post_src = new Uint8Array(post_src_len);
		post_src.set(new Uint8Array([lenPadding, filename.length]));
		post_src.set(filename, 2);
		post_src.set(new Uint8Array(contentsAb), 2 + filename.length);

		const bts = _getBinTs();
		progressCallback("Uploading chunk 1 of " + totalChunks, 0, totalChunks);
		_pvApi(bts, slot, _PV_CMD_ADD, 0, _encryptedFilePost(post_src, 0, bts), function(status) {
			if (status !== 204) {
				endCallback("Error: " + status);
			} else {
				const bts_bi = BigInt(bts[0]) | (BigInt(bts[1]) << 8n) | (BigInt(bts[2]) << 16n) | (BigInt(bts[3]) << 24n) | (BigInt(bts[4]) << 32n) | (BigInt(bts[5]) << 40n);
				_files[slot] = new _pvFile(folderPath + file.name, bts_bi, Math.max(1, Math.round(lenTotal / 1024)));

				if (totalChunks === 1) {
					endCallback("Done");
				} else {
					_uploadChunks(file, slot, bts, lenPadding, contents.size, totalChunks, 1, progressCallback, endCallback);
				}
			}
		});
	};

	const _verifyChunk = async function(repairs, verifyKey, serverHash, chunk, totalChunks, file, offset, slot, lenPadding, lenTotal, fileBts, progressCallback, endCallback) {
		if (chunk == totalChunks) {
			endCallback(repairs);
			return;
		}

		const fileBlocks = lenTotal / 16;
		const fbk = _getFbk(fileBts);
		progressCallback("Checking chunk " + (chunk + 1) + " of " + totalChunks, chunk + 1, totalChunks);

		let chunk_src;
		if (chunk === 0) { // First chunk
			const filename = sodium.from_string(file.name);

			const chunk_src_len = ((totalChunks > 1) ? _PV_CHUNKSIZE : lenTotal) - 16;
			chunk_src = new Uint8Array(chunk_src_len);
			chunk_src.set(new Uint8Array([lenPadding, filename.length]));
			chunk_src.set(filename, 2);

			const contents = await file.slice(0, _PV_CHUNKSIZE - 18 - filename.length);
			const contentsAb = await contents.arrayBuffer();
			chunk_src.set(new Uint8Array(contentsAb), 2 + filename.length);
			offset += _PV_CHUNKSIZE - 18 - filename.length;
		} else if (chunk + 1 === totalChunks) { // Last chunk
			const contents = await file.slice(offset);
			const contentsAb = await contents.arrayBuffer();

			chunk_src = new Uint8Array(contents.size + lenPadding);
			chunk_src.set(new Uint8Array(contentsAb));
		} else { // Middle chunk
			const contents = await file.slice(offset, offset + _PV_CHUNKSIZE - 16);
			const contentsAb = await contents.arrayBuffer();
			chunk_src = new Uint8Array(contentsAb);
			offset += _PV_CHUNKSIZE - 16;
		}

		const chunk_enc = _encryptUfk(_chunk_src, chunk, _getFbk(bts));
		const chunk_server = sodium.crypto_stream_chacha20_xor(chunk_enc, chunkNonce.slice(0, sodium.crypto_aead_chacha20poly1305_NPUBBYTES), _getMfk(fbk, 0));
		const clientHash = sodium.crypto_generichash(16, chunk_server, verifyKey);

		let hashMatch = true;
		if (serverHash.length >= 16) {
			for (let i = 0; i < 16; i++) {
				if (clientHash[i] !== serverHash[i]) {
					hashMatch = false;
					break;
				}
			}
		} else hashMatch = false;

		if (hashMatch) return _verifyChunk(repairs, verifyKey, serverHash.slice(16), chunk + 1, totalChunks, file, offset, slot, lenPadding, lenTotal, fileBts, progressCallback, endCallback);

		// Chunk corrupt - reupload
		progressCallback("Reuploading chunk " + (chunk + 1) + " of " + totalChunks, chunk + 1, totalChunks);

		const bts = _getBinTs();
		_fetchEncrypted(await _fe_create_inner(bts, slot, _PV_CMD_UPLOAD | _PV_FLAG_KEEPOLD, true), bts, _own_uid, chunk, chunk_enc, _getMfk_enc(fileBaseKey, bts, slot), function(status) {
			if (status !== 0) {
				endCallback(status);
				return;
			}

			_verifyChunk(repairs + 1, verifyKey, serverHash.slice(16), chunk + 1, totalChunks, file, offset, slot, lenPadding, lenTotal, fileBts, progressCallback, endCallback);
		});
	}

	this.verifyFile = async function(slot, file, progressCallback, endCallback) {if(typeof(slot)!=="number" || typeof(file)!=="object" || typeof(endCallback)!=="function"){return;}
/*		if (file.name !== _files[slot].path.slice(_files[slot].path.lastIndexOf("/") + 1)) {
			endCallback("Filename mismatch", 0, 0);
			return;
		}

		progressCallback("Requesting hashes", 0, 1);
		const bts = _getBinTs();
		_fetchEncrypted(await _fe_create_inner(bts, slot, _PV_CMD_VERIFY, false), bts, _own_uid, 0, null, null, async function(resp) {
			if (typeof(resp) === "number") {
				endCallback("Error: " + resp);
				return;
			}

			if (_files[slot].lastMod === 0) _files[slot].lastMod = Math.round(file.lastModified / 1000);

			const filename = sodium.from_string(file.name);
			let lenTotal = 2 + filename.length + file.size;
			let lenPadding = (lenTotal % 16 === 0) ? 0 : 16 - (lenTotal & 15);
			lenTotal += lenPadding;

			let totalChunks = Math.ceil(lenTotal / _PV_CHUNKSIZE);
			lenTotal += totalChunks * sodium.crypto_aead_chacha20poly1305_ABYTES;

			if (totalChunks < Math.ceil(lenTotal / _PV_CHUNKSIZE) || lenTotal % _PV_CHUNKSIZE == 0) {
				lenTotal += sodium.crypto_aead_chacha20poly1305_ABYTES;
				totalChunks++;
			}

			if (totalChunks > 4095) {endCallback("Error: File too large."); return;}

			const vfyKeyNonce = new Uint8Array(8);
			vfyKeyNonce.set(bts);
			vfyKeyNonce[7] = 3;
			const verifyKey = _aem_kdf_uak(32, vfyKeyNonce);

			_verifyChunk(0, verifyKey, resp.slice(5), 0, totalChunks, file, 0, slot, lenPadding, lenTotal, resp.slice(0, 5), progressCallback, function(repairs) {
				if (repairs === 0)
					endCallback("Verified OK.");
				else if (repairs > 0)
					endCallback("Repaired " + repairs + " chunks.");
				else
					endCallback("Error: " + repairs);
			});
		});
*/	};

	this.fixFile = function(slot, folderPath, progressCallback, endCallback) {if(typeof(slot)!=="number" || typeof(folderPath)!=="string" || typeof(endCallback)!=="function"){return;}
		if (folderPath && folderPath.startsWith("/")) folderPath = folderPath.substr(1);
		if (folderPath && !folderPath.endsWith("/")) folderPath += "/";

		progressCallback("Downloading first chunk", 0, 1);
		_pvApi(_getBinTs(), slot, _PV_CMD_GET, 0, null, function(resp) {
			if (typeof(resp) === "number") {endCallback("Error: " + resp); return;}
			const sfk = resp.slice(0, 40);
			const bts = resp.slice(40, 46);
			const fbk = _getFbk(bts);
			resp = resp.slice(46);

			const mfk = _getMfk(fbk, 0);
			const sse_key = new Uint8Array([
				mfk[0]  ^ sfk[0],  mfk[1]  ^ sfk[1],  mfk[2]  ^ sfk[2],  mfk[3]  ^ sfk[3],  mfk[4]  ^ sfk[4],  mfk[5]  ^ sfk[5],  mfk[6]  ^ sfk[6],  mfk[7]  ^ sfk[7],  mfk[8]  ^ sfk[8],  mfk[9]  ^ sfk[9],
				mfk[10] ^ sfk[10], mfk[11] ^ sfk[11], mfk[12] ^ sfk[12], mfk[13] ^ sfk[13], mfk[14] ^ sfk[14], mfk[15] ^ sfk[15], mfk[16] ^ sfk[16], mfk[17] ^ sfk[17], mfk[18] ^ sfk[18], mfk[19] ^ sfk[19],
				mfk[20] ^ sfk[20], mfk[21] ^ sfk[21], mfk[22] ^ sfk[22], mfk[23] ^ sfk[23], mfk[24] ^ sfk[24], mfk[25] ^ sfk[25], mfk[26] ^ sfk[26], mfk[27] ^ sfk[27], mfk[28] ^ sfk[28], mfk[29] ^ sfk[29],
				mfk[30] ^ sfk[30], mfk[31] ^ sfk[31], mfk[32] ^ sfk[32], mfk[33] ^ sfk[33], mfk[34] ^ sfk[34], mfk[35] ^ sfk[35], mfk[36] ^ sfk[36], mfk[37] ^ sfk[37], mfk[38] ^ sfk[38], mfk[39] ^ sfk[39],
			]);

			progressCallback("Decrypting (ChaCha20)", 0.5, 1);
			let dec = _decryptSse(resp, sse_key);

			progressCallback("Decrypting (AEGIS)", 0.75, 1);
			dec = _decryptUfk(dec, 0, fbk);
			if (!dec) {endCallback("Failed decrypting file"); return;}

			const fileName = sodium.to_string(dec.slice(2, 2 + dec[1]));

			_files[slot].binTs = BigInt(bts[0]) 
			| (BigInt(bts[1]) << 8n) 
			| (BigInt(bts[2]) << 16n) 
			| (BigInt(bts[3]) << 24n)
			| (BigInt(bts[4]) << 32n)
			| (BigInt(bts[5] & 3) << 40n);

			_files[slot].path = folderPath + sodium.to_string(dec.slice(2, 2 + dec[1]));
			endCallback("Fixed");
		});
	};

	this.downloadFile = async function(slot, progressCallback, endCallback) {if(typeof(slot)!=="number" || typeof(endCallback)!=="function"){return;}
		let fileHandle = null;
		if (window.showSaveFilePicker) {
			fileHandle = await window.showSaveFilePicker({suggestedName: (_files[slot]) ? _files[slot].path : "Unknown"});
		}

		const totalChunks = Math.ceil((_files[slot].kib * 1024) / _PV_CHUNKSIZE);

		if (totalChunks > 1 && !fileHandle) {
			if (!fileHandle) {
				endCallback("This browser does not support downloading large files");
				return;
			}

			progressCallback("Downloading chunk 1 of " + totalChunks, 0, 1);
		} else {
			progressCallback("Downloading file", 0, 1);
		}

		_pvApi(_getBinTs(), slot, _PV_CMD_GET, 0, null, async function(resp) {
			if (typeof(resp) === "number") {endCallback("Error: " + resp); return;}
			const sfk = resp.slice(0, 40);
			const bts = resp.slice(40, 46);
			const fbk = _getFbk(bts);
			resp = resp.slice(46);

			const mfk = _getMfk(fbk, 0);
			const sse_key = new Uint8Array([
				mfk[0]  ^ sfk[0],  mfk[1]  ^ sfk[1],  mfk[2]  ^ sfk[2],  mfk[3]  ^ sfk[3],  mfk[4]  ^ sfk[4],  mfk[5]  ^ sfk[5],  mfk[6]  ^ sfk[6],  mfk[7]  ^ sfk[7],  mfk[8]  ^ sfk[8],  mfk[9]  ^ sfk[9],
				mfk[10] ^ sfk[10], mfk[11] ^ sfk[11], mfk[12] ^ sfk[12], mfk[13] ^ sfk[13], mfk[14] ^ sfk[14], mfk[15] ^ sfk[15], mfk[16] ^ sfk[16], mfk[17] ^ sfk[17], mfk[18] ^ sfk[18], mfk[19] ^ sfk[19],
				mfk[20] ^ sfk[20], mfk[21] ^ sfk[21], mfk[22] ^ sfk[22], mfk[23] ^ sfk[23], mfk[24] ^ sfk[24], mfk[25] ^ sfk[25], mfk[26] ^ sfk[26], mfk[27] ^ sfk[27], mfk[28] ^ sfk[28], mfk[29] ^ sfk[29],
				mfk[30] ^ sfk[30], mfk[31] ^ sfk[31], mfk[32] ^ sfk[32], mfk[33] ^ sfk[33], mfk[34] ^ sfk[34], mfk[35] ^ sfk[35], mfk[36] ^ sfk[36], mfk[37] ^ sfk[37], mfk[38] ^ sfk[38], mfk[39] ^ sfk[39],
			]);

			progressCallback("Decrypting (ChaCha20) chunk 1 of " + totalChunks, 0, totalChunks);
			let dec = _decryptSse(resp, sse_key);

			progressCallback("Decrypting (AEGIS) chunk 1 of " + totalChunks, 0, totalChunks);
			dec = _decryptUfk(dec, 0, fbk);
			if (!dec) {endCallback("Failed decrypting file"); return;}

			const fileName = sodium.to_string(dec.slice(2, 2 + dec[1]));
			const lenPadding = dec[0];

			if (totalChunks == 1) {
				if (fileHandle) {
					const writer = await fileHandle.createWritable();
					writer.write(dec.slice(2 + dec[1], dec.length - lenPadding));
					writer.close();
					endCallback("Done");
				} else {
					const a = document.createElement("a");
					a.href = URL.createObjectURL(new Blob([dec.slice(2 + dec[1], dec.length - lenPadding)]));
					a.download = fileName;
					a.click();

					URL.revokeObjectURL(a.href);
					a.href = "";
					a.download = "";
					endCallback("Done");
				}
			} else {
				const writer = await fileHandle.createWritable();
				writer.write(dec.slice(2 + dec[1]));
				_downloadChunks(slot, 1, totalChunks, lenPadding, writer, progressCallback, endCallback);
			}
		});
	};

	this.downloadIndex = function(callback) {if(typeof(callback)!=="function"){return;}
		_pvApi(_getBinTs(), 0, _PV_CMD_GET, 0, null, function(resp) {
			if (typeof(resp) === "number") {callback("Error getting index:" + resp); return;}

			const slotData = resp.slice(0, 8192);
			const sfk = resp.slice(8192, 8232);
			const bts = resp.slice(8232, 8238);
			resp = resp.slice(8238);

			for (let i = 0; i < _PV_MAXFILES; i++) {
				if ((slotData[Math.floor((i - (i % 8)) / 8)] & (1 << (i % 8))) != 0) {
					_files[i] = new _pvFile("Unknown [" + i + "]", 0n, 1);
				}
			}

			const fbk = _getFbk(bts);
			const mfk = _getMfk(fbk, 0);
			const sse_key = new Uint8Array([
				mfk[0]  ^ sfk[0],  mfk[1]  ^ sfk[1],  mfk[2]  ^ sfk[2],  mfk[3]  ^ sfk[3],  mfk[4]  ^ sfk[4],  mfk[5]  ^ sfk[5],  mfk[6]  ^ sfk[6],  mfk[7]  ^ sfk[7],  mfk[8]  ^ sfk[8],  mfk[9]  ^ sfk[9],
				mfk[10] ^ sfk[10], mfk[11] ^ sfk[11], mfk[12] ^ sfk[12], mfk[13] ^ sfk[13], mfk[14] ^ sfk[14], mfk[15] ^ sfk[15], mfk[16] ^ sfk[16], mfk[17] ^ sfk[17], mfk[18] ^ sfk[18], mfk[19] ^ sfk[19],
				mfk[20] ^ sfk[20], mfk[21] ^ sfk[21], mfk[22] ^ sfk[22], mfk[23] ^ sfk[23], mfk[24] ^ sfk[24], mfk[25] ^ sfk[25], mfk[26] ^ sfk[26], mfk[27] ^ sfk[27], mfk[28] ^ sfk[28], mfk[29] ^ sfk[29],
				mfk[30] ^ sfk[30], mfk[31] ^ sfk[31], mfk[32] ^ sfk[32], mfk[33] ^ sfk[33], mfk[34] ^ sfk[34], mfk[35] ^ sfk[35], mfk[36] ^ sfk[36], mfk[37] ^ sfk[37], mfk[38] ^ sfk[38], mfk[39] ^ sfk[39],
			]);

			let dec = _decryptSse(resp, sse_key);
			dec = _decryptUfk(dec, 0, fbk);
			if (!dec) {callback("Failed decrypting index"); return;}

			let f = 1;
			let n = 0;

			while (n < dec.length) {
				if ((dec[n] & 128) == 0) {
					// Skip
					f += dec[n] & 127;
					n++;
					continue;
				}

				// Exists
				const bts =
					BigInt(dec[n] & 127)
				|	(BigInt(dec[n + 1]) << 7n)
				|	(BigInt(dec[n + 2]) << 15n)
				|	(BigInt(dec[n + 3]) << 23n)
				|	(BigInt(dec[n + 4]) << 31n)
				|	(BigInt((dec[n + 5]) & 7) << 39n);

				const unitMib = dec[n + 5] & 8 != 0;
				const sz = 1 + (
					((dec[n + 5] & 240) >> 4)
				|	(dec[n + 6] << 4)
				|	(dec[n + 7] << 12));

				let pth = dec.slice(n + 8);
				pth = pth.slice(0, pth.indexOf(0));

				_files[f] = new _pvFile(sodium.to_string(pth), bts, sz * (unitMib? 1024 : 1));

				f++;
				n += 9 + pth.length;
			}
/*
for (let i = 0; i < _PV_MAXFILES; i++) {
	if (_files[i]) {
		const path = sodium.from_string(_files[i].path.replaceAll("//", "/"));

		pvInfo[n] = 128 | (_files[i].binTs & 127);
		pvInfo[n + 1] = (_files[i].binTs >> 7) & 255;
		pvInfo[n + 2] = (_files[i].binTs >> 15) & 255;
		pvInfo[n + 3] = (_files[i].binTs >> 23) & 255;
		pvInfo[n + 4] = (_files[i].binTs >> 31) & 255;
		pvInfo[n + 5] = ((_files[i].binTs >> 39) & 7) | ((_files[i].kib & 31) << 3);
		pvInfo[n + 6] = (_files[i].kib >> 5) & 255;
		pvInfo[n + 7] = (_files[i].kib >> 13) & 255;
		pvInfo[n + 8] = (_files[i].kib >> 21) & 127;
		pvInfo.set(path, n + 9);
		pvInfo[n + 9 + path.length] = 0;

		n += 10 + path.length;
	} else {
		let skipCount = 1;
		for (let j = i; j < _PV_MAXFILES; j++) {
			if (_files[i]) break;
			skipCount++;
			if (skipCount == 128) break;
		}

		pvInfo[n] = skipCount - 1;
		n++;
	}
}

 */
			callback(0);
		});
	};

	this.deleteFile = function(slot, callback) {if(typeof(slot)!=="number" || typeof(callback)!=="function"){return;}
		if (_files[slot].binTs === 0) {
			_files[slot] = null;
			return;
		}

		_pvApi(_getBinTs(), slot, _PV_CMD_DEL, slot, null, function(resp) {
			if (resp === 204) {
				_files[slot] = null;
				callback(0);
			} else {
				callback(resp);
			}
		});
	};

	this.setKeys = function(umk_b64, callback) {if(typeof(umk_b64)!=="string" || typeof(callback)!=="function"){return;}
		if (umk_b64.length !== 60) {
			callback(false);
			return;
		}

		const umk = sodium.from_base64(umk_b64, sodium.base64_variants.ORIGINAL);
		_own_uak = _aem_kdf_umk(43, 1, umk);
		_own_fmk = _aem_kdf_umk(37, 128 | 2, umk);

		const counter = ((_own_uak[36] & 127) << 24) | ((_own_uak[36] & 128) << 16);
		const nonce = new Uint8Array([_own_uak[32], _own_uak[33], _own_uak[34], _own_uak[35], 1, 0, 0, 0, 0, 0, 0, 0]);
		_own_uid = new Uint16Array(sodium.crypto_stream_chacha20_ietf_xor_ic(new Uint8Array(2), nonce, counter, _own_uak.slice(0, 32)).buffer)[0] & 4095;

		callback(true);
	};

	const b66_chars = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-.+";

	this.createShareLink = function(slot, expiration) {
		if (typeof(slot) !== "number" || slot < 1 || slot >= _PV_MAXFILES || typeof(expiration) !== "number" || expiration < 1 || expiration > 7) return;

		const url1 = sodium.to_base64(_pvApi_urlBase(_getBinTs(), slot, _PV_CMD_GET, expiration, false).slice(0, 24), sodium.base64_variants.URLSAFE);
		const u2 = new Uint8Array(45);
		u2.set(_getFbk(_getBinTs(_files[slot].binTs)));
		const url2 = sodium.to_base64(u2, sodium.base64_variants.URLSAFE).slice(0, 58);

		return document.documentURI + "#" + url1 + url2;
//		return _PV_APIURL + "/#" + url1 + url2;
	};

	this.sharedLink_get = function(hsh, infoCallback, progressCallback, endCallback) {if(typeof(hsh)!=="string" || hsh.length!==90){return;}
		hsh = sodium.from_base64(hsh + "AA", sodium.base64_variants.URLSAFE);

		const bts = hsh.slice(0, 6);
		const bts_bi = BigInt(bts[0]) 
		| (BigInt(bts[1]) << 8n) 
		| (BigInt(bts[2]) << 16n) 
		| (BigInt(bts[3]) << 24n)
		| (BigInt(bts[4]) << 32n)
		| (BigInt(bts[5] & 3) << 40n);

		infoCallback(Number(_BINTS_BEGIN + bts_bi));

		progressCallback("Downloading chunk 1 of ?", 0, 1);
		_pvApi_fetch(hsh.slice(0, 24), 0, null, function(resp) {
			if (typeof(resp) === "number") {endCallback(resp); return;}

			const chunk = 0;
			const totalChunks = 0;
			const fbk = hsh.slice(24);

			const sfk = resp.slice(0, 40);
			resp = resp.slice(46);

			const mfk = _getMfk(fbk, 0);
			const sse_key = new Uint8Array([
				mfk[0]  ^ sfk[0],  mfk[1]  ^ sfk[1],  mfk[2]  ^ sfk[2],  mfk[3]  ^ sfk[3],  mfk[4]  ^ sfk[4],  mfk[5]  ^ sfk[5],  mfk[6]  ^ sfk[6],  mfk[7]  ^ sfk[7],  mfk[8]  ^ sfk[8],  mfk[9]  ^ sfk[9],
				mfk[10] ^ sfk[10], mfk[11] ^ sfk[11], mfk[12] ^ sfk[12], mfk[13] ^ sfk[13], mfk[14] ^ sfk[14], mfk[15] ^ sfk[15], mfk[16] ^ sfk[16], mfk[17] ^ sfk[17], mfk[18] ^ sfk[18], mfk[19] ^ sfk[19],
				mfk[20] ^ sfk[20], mfk[21] ^ sfk[21], mfk[22] ^ sfk[22], mfk[23] ^ sfk[23], mfk[24] ^ sfk[24], mfk[25] ^ sfk[25], mfk[26] ^ sfk[26], mfk[27] ^ sfk[27], mfk[28] ^ sfk[28], mfk[29] ^ sfk[29],
				mfk[30] ^ sfk[30], mfk[31] ^ sfk[31], mfk[32] ^ sfk[32], mfk[33] ^ sfk[33], mfk[34] ^ sfk[34], mfk[35] ^ sfk[35], mfk[36] ^ sfk[36], mfk[37] ^ sfk[37], mfk[38] ^ sfk[38], mfk[39] ^ sfk[39],
			]);

			progressCallback("Decrypting (ChaCha20) chunk 1 of " + totalChunks, 3.333, totalChunks * 2);
			let dec = _decryptSse(resp, sse_key);

			progressCallback("Decrypting (AEGIS) chunk 1 of " + totalChunks, 3, totalChunks * 2);
			dec = _decryptUfk(dec, 0, fbk);
			if (!dec) {endCallback("Failed decrypting file"); return;}

			const fileName = sodium.to_string(dec.slice(2, 2 + dec[1]));
			const lenFile = dec.length - dec[0];
			endCallback(fileName, lenFile, _getFileType(fileName), dec.slice(2 + dec[1], lenFile));
		});
	};

	this.sharedLink_save = async function() {
		if (!_share_chunk1) return;

		if (_share_blocks > _PV_CHUNKSIZE / _PV_BLOCKSIZE) {
			// TODO: Large share download
			return;
		}

		if (window.showSaveFilePicker) {
			const fileHandle = await window.showSaveFilePicker({suggestedName: _share_filename});

			if (fileHandle) {
				const writer = await fileHandle.createWritable();
				writer.write(_share_chunk1);
				writer.close();
			}
		} else {
			const a = document.createElement("a");
			a.href = URL.createObjectURL(new Blob([_share_chunk1]));
			a.download = _share_filename;
			a.click();

			URL.revokeObjectURL(a.href);
			a.href = "";
			a.download = "";
		}
	};

	readyCallback(true);
}
