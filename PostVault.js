"use strict";

function PostVault(readyCallback) {
	const _AEM_SECURITY_KEYID_UAK = 0xE0;
	const _AEM_SECURITY_UAK_LEN = 35;

	const _PV_CHUNKSIZE = 16777216;
	const _PV_BLOCKSIZE = 16;

	const _PV_FLAG_SHARED = 1;
	const _PV_FLAG_KEEPOLD = 2;

	const _PV_CMD_DOWNLOAD = 0;
	const _PV_CMD_UPLOAD =  64;
	const _PV_CMD_DELETE = 128;
//	const _PV_CMD_       = 192;

	const _PV_APIURL = document.head.querySelector("meta[name='postvault.url']").content;
	const _PV_EXPIRATION = ["5 minutes", "15 minutes", "1 hour", "4 hours", "12 hours", "24 hours", "3 days", "7 days", "2 weeks", "1 month", "3 months", "6 months", "12 months", "2 years", "5 years", "∞"];

//	if (!_PV_DOMAIN || !new RegExp(/^[0-9a-z.-]{1,63}\.[0-9a-z-]{2,63}$/).test(_PV_DOMAIN))) {
//		readyCallback(false);
//		return;
//	}

	function _pvFile(path, lastMod, binTs, blocks) {
		this.path = path;
		this.lastMod = lastMod;
		this.binTs = binTs;
		this.blocks = blocks;
	};

	let _own_umk;
	let _own_uak;
	let _own_uid;

	let _files = [new _pvFile("", 0, null, 0)];

	let _share_chunk1 = null;
	let _share_blocks = null;
	let _share_filename = null;

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
		try {
			const r = await fetch(_PV_APIURL + "/" + sodium.to_base64(urlBase, sodium.base64_variants.URLSAFE), {
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

			if (r.status === 204) {callback(0); return;}
			callback((r.status === 200) ? new Uint8Array(await r.arrayBuffer()) : -1);
		} catch(e) {callback(-2);}
	};

	const _fe_create_inner = async function(binTs, slot, flags) {
		const secretHash = sodium.crypto_generichash(3 + sodium.crypto_onetimeauth_KEYBYTES, binTs, _own_uak);

		const src = new Uint8Array(3);
		src.set(new Uint8Array(new Uint16Array([slot]).buffer));
		src[2] = flags;

		const enc = new Uint8Array(3 + sodium.crypto_onetimeauth_BYTES);
		enc[0] = src[0] ^ secretHash[0];
		enc[1] = src[1] ^ secretHash[1];
		enc[2] = src[2] ^ secretHash[2];

		enc.set(sodium.crypto_onetimeauth(enc.slice(0, 3), secretHash.slice(3)), 3);
		return enc;
	};

	const _fetchEncrypted = async function(inner_enc, binTs, uid, chunk, content, mfk_enc, callback) {
		await new Promise(resolve => setTimeout(resolve, 1)); // Ensure requests are never made within the same millisecond

		const base = new Uint8Array(8 + inner_enc.length);
		base.set(binTs);
		base.set(new Uint8Array(new Uint32Array([uid | (chunk << 12)]).buffer).slice(0, 3), 5);
		base.set(inner_enc, 8);

		let post = null;
		if (content && (typeof(content) === "object")) {
			post = new Uint8Array(mfk_enc.length + content.length);
			post.set(mfk_enc);
			post.set(content, mfk_enc.length);
		}

		_fetchBinary(base, post, function(result) {
			callback(result);
		});
	};

	const _genIndex = function() {
		let lenIndex = 2;
		for (let i = 0; i < 65535; i++) {
			lenIndex += (_files[i] && _files[i].blocks > 0) ? (14 + sodium.from_string(_files[i].path).length) : 1;
		}

		let lenPadding = (lenIndex % 16 === 0) ? 0 : 16 - (lenIndex % 16);
		lenIndex += lenPadding;

		const pvInfo = new Uint8Array(lenIndex);
		pvInfo[0] = lenPadding;
		pvInfo[1] = 0; // No name

		let n = 2;

		for (let i = 0; i < 65535; i++) {
			if (_files[i] && _files[i].blocks > 0) {
				const path = sodium.from_string(_files[i].path.replace("//", "/"));

				pvInfo[n] = path.length;
				pvInfo.set(_files[i].binTs, n + 1);
				pvInfo.set(new Uint8Array(new Uint32Array([_files[i].lastMod]).buffer), n + 6);
				pvInfo.set(new Uint8Array(new Uint32Array([_files[i].blocks]).buffer), n + 10);
				pvInfo.set(path, n + 14);

				n += 14 + path.length;
			} else {
				pvInfo[n] = 0;
				n++;
			}
		}

		return pvInfo;
	};

	const _getFreeSlot = function() {
		for (let i = 1; i < 65536; i++) {
			if (!_files[i]) return i;
		}

		return -1;
	};

	const _getFileBaseKey = function(slot, blocks, binTs) {
		const bytes = new Uint8Array(11);
		bytes.set(new Uint8Array(new Uint16Array([slot]).buffer));
		bytes.set(new Uint8Array(new Uint32Array([blocks]).buffer), 2);
		bytes.set(binTs, 6);
		return sodium.crypto_generichash(32, bytes, _own_umk);
	}

	const _getUfk = function(fileBaseKey) {
		return sodium.crypto_generichash(sodium.crypto_aead_chacha20poly1305_KEYBYTES, new Uint8Array([0x50]), fileBaseKey);
	};

	const _getMfk = function(fileBaseKey) {
		return sodium.crypto_generichash(32, new Uint8Array([0x51]), fileBaseKey);
	};

	const _getMfk_enc = function(fileBaseKey, binTs, slot) {
		const mfk = _getMfk(fileBaseKey);
		const xmfk_base = new Uint8Array(7);
		xmfk_base.set(binTs);
		xmfk_base.set(new Uint8Array(new Uint16Array([slot]).buffer), 5);

		const xmfk = sodium.crypto_generichash(32, xmfk_base, _own_uak);

		return new Uint8Array([
			mfk[0]  ^ xmfk[0],  mfk[1]  ^ xmfk[1],  mfk[2]  ^ xmfk[2],  mfk[3]  ^ xmfk[3],  mfk[4]  ^ xmfk[4],  mfk[5]  ^ xmfk[5],  mfk[6]  ^ xmfk[6],  mfk[7]  ^ xmfk[7],  mfk[8]  ^ xmfk[8],  mfk[9]  ^ xmfk[9],
			mfk[10] ^ xmfk[10], mfk[11] ^ xmfk[11], mfk[12] ^ xmfk[12], mfk[13] ^ xmfk[13], mfk[14] ^ xmfk[14], mfk[15] ^ xmfk[15], mfk[16] ^ xmfk[16], mfk[17] ^ xmfk[17], mfk[18] ^ xmfk[18], mfk[19] ^ xmfk[19],
			mfk[20] ^ xmfk[20], mfk[21] ^ xmfk[21], mfk[22] ^ xmfk[22], mfk[23] ^ xmfk[23], mfk[24] ^ xmfk[24], mfk[25] ^ xmfk[25], mfk[26] ^ xmfk[26], mfk[27] ^ xmfk[27], mfk[28] ^ xmfk[28], mfk[29] ^ xmfk[29],
			mfk[30] ^ xmfk[30], mfk[31] ^ xmfk[31]]);
	};

	const _getChunkNonce = function(chunk) {
		const n = new Uint8Array(sodium.crypto_aead_chacha20poly1305_NPUBBYTES);
		n.set(new Uint8Array(new Uint16Array([chunk]).buffer));
		return n;
	}

	const _decryptMfk = async function(src, mfk, callback) {
		const mfk_key = await window.crypto.subtle.importKey("raw", mfk, {"name": "AES-CTR"}, false, ["decrypt"]);
		const firstBlock = src.slice(0, 16);
		const dec = new Uint8Array(src.length);
		dec.set(new Uint8Array(await window.crypto.subtle.decrypt({name: "AES-CTR", counter: new Uint8Array(16), length: 32}, mfk_key, firstBlock)).slice(0, 16));
		dec.set(new Uint8Array(await window.crypto.subtle.decrypt({name: "AES-CTR", counter: firstBlock, length: 32}, mfk_key, src.slice(16))), 16);
		callback(dec);
	}

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
		const fileBaseKey = _getFileBaseKey(slot, totalBlocks, binTs);
		const aead_enc = sodium.crypto_aead_chacha20poly1305_encrypt(aead_src, null, null, _getChunkNonce(chunk), _getUfk(fileBaseKey));

		offset += _PV_CHUNKSIZE - sodium.crypto_aead_chacha20poly1305_ABYTES;

		progressCallback("Uploading chunk " + (chunk + 1) + " of " + totalChunks, chunk * 2 + 1, totalChunks * 2);

		const bts = _getBinTs();
		_fetchEncrypted(await _fe_create_inner(bts, slot, _PV_CMD_UPLOAD | _PV_FLAG_KEEPOLD), bts, _own_uid, chunk, aead_enc, _getMfk_enc(fileBaseKey, binTs, slot), function(status) {
			if (status !== 0) {
				endCallback("Error: " + status);
			} else if (chunk + 1 === totalChunks) {
				endCallback("Done");
			} else {
				_uploadChunks(file, slot, binTs, totalBlocks, lenPadding, offset, totalChunks, chunk + 1, progressCallback, endCallback);
			}
		});
	};

	const _downloadChunks = async function(slot, chunk, totalChunks, lenPadding, writer, progressCallback, endCallback) {
		progressCallback("Downloading chunk " + (chunk + 1) + " of " + totalChunks, chunk * 2, totalChunks * 2);

		const binTs = _getBinTs();
		_fetchEncrypted(await _fe_create_inner(binTs, slot, _PV_CMD_DOWNLOAD), binTs, _own_uid, chunk, null, null, function(resp) {
			if (typeof(resp) === "number") {writer.close(); endCallback("Error: " + resp); return;}

			const totalBlocks = new Uint32Array(resp.slice(5, 9).buffer)[0];
			const fileBaseKey = _getFileBaseKey(slot, totalBlocks, resp.slice(0, 5));

			progressCallback("Decrypting (AES) chunk " + (chunk + 1) + " of " + totalChunks, chunk * 2 + 1, totalChunks * 2);
			_decryptMfk(resp.slice(9), _getMfk(fileBaseKey), async function(dec) {
				progressCallback("Decrypting (ChaCha20) chunk " + (chunk + 1) + " of " + totalChunks, chunk * 2 + 1.333, totalChunks * 2);
				dec = sodium.crypto_aead_chacha20poly1305_decrypt(null, dec, null, _getChunkNonce(chunk), _getUfk(fileBaseKey));

				progressCallback("Writing chunk " + (chunk + 1) + " of " + totalChunks, chunk * 2 + 1.667, totalChunks * 2);
				if (chunk + 1 === totalChunks) {
					writer.write(dec.slice(0, dec.length - lenPadding));
					writer.close();
					endCallback("Done");
					return;
				}

				writer.write(dec);

				_downloadChunks(slot, chunk + 1, totalChunks, lenPadding, writer, progressCallback, endCallback);
			});
		});
	};

	const _downloadFile = async function(uid, fbk, slot, inner_enc, binTs, progressCallback, doneCallback) {
		progressCallback("Downloading chunk 1 of " + (slot? Math.ceil((_files[slot].blocks * _PV_BLOCKSIZE) / _PV_CHUNKSIZE) : "?"), 0, 1);

		_fetchEncrypted(inner_enc, binTs, uid, 0, null, null, function(resp) {
			if (typeof(resp) === "number") {doneCallback("Error: " + resp); return;}

			const totalBlocks = new Uint32Array(resp.slice(5, 9).buffer)[0];
			const totalChunks = Math.ceil((totalBlocks * _PV_BLOCKSIZE) / _PV_CHUNKSIZE);
			if (!fbk) fbk = _getFileBaseKey(slot, totalBlocks, resp.slice(0, 5));

			progressCallback("Decrypting (AES) chunk 1 of " + totalChunks, 1, totalChunks * 2);
			_decryptMfk(resp.slice(9), _getMfk(fbk), async function(dec) {
				progressCallback("Decrypting (ChaCha20) chunk 1 of " + totalChunks, 1.333, totalChunks * 2);
				dec = sodium.crypto_aead_chacha20poly1305_decrypt(null, dec, null, new Uint8Array(sodium.crypto_aead_chacha20poly1305_NPUBBYTES), _getUfk(fbk));

				const fileName = sodium.to_string(dec.slice(2, 2 + dec[1]));
				const lenPadding = dec[0];

				doneCallback(dec.slice(2 + dec[1]), fileName, totalBlocks, lenPadding);
			});
		});
	};

	// Public functions
	this.getExpirationValues = function() {return _PV_EXPIRATION;};

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

		if (!wantFiles && wantFolders) list.sort();

		return list;
	};

	this.getFilePath = function(num) {if(typeof(num)!=="number") return; return _files[num]? _files[num].path : null;};
	this.getFileSize = function(num) {if(typeof(num)!=="number") return; return _files[num]? _files[num].blocks * _PV_BLOCKSIZE : null;};
	this.getFileTime = function(num) {if(typeof(num)!=="number") return; return _files[num]? _files[num].lastMod : null;};

	this.getTotalFiles = function() {return _files.length;};
	this.getTotalSize = function() {
		let b = 0;
		_files.forEach(function(f) {b += f.blocks;});
		return b * _PV_BLOCKSIZE;
	};

	this.moveFile = function(num, newPath) {if(typeof(num)!=="number" || typeof(newPath)!=="string" || newPath.length<1 || !_files[num]) return false; _files[num].path = newPath; return true;};

	this.uploadIndex = async function(callback) {if(typeof(callback)!=="function"){return;}
		const index_src = _genIndex();
		const binTs = _getBinTs();
		const totalBlocks = (index_src.length + sodium.crypto_aead_chacha20poly1305_ABYTES) / _PV_BLOCKSIZE;
		const fbk = _getFileBaseKey(0, totalBlocks, binTs);
		const index_enc = sodium.crypto_aead_chacha20poly1305_encrypt(index_src, null, null, new Uint8Array(sodium.crypto_aead_chacha20poly1305_NPUBBYTES), _getUfk(fbk));

		_fetchEncrypted(await _fe_create_inner(binTs, 0, _PV_CMD_UPLOAD), binTs, _own_uid, 0, index_enc, _getMfk_enc(fbk, binTs, 0), function(status) {
			callback(status);
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
		lenTotal += totalChunks * sodium.crypto_aead_chacha20poly1305_ABYTES;

		if (totalChunks < Math.ceil(lenTotal / _PV_CHUNKSIZE) || lenTotal % _PV_CHUNKSIZE == 0) {
			lenTotal += sodium.crypto_aead_chacha20poly1305_ABYTES;
			totalChunks++;
		}

		if (totalChunks > 4095) {endCallback("Error: File too large"); return;}

		const binTs = _getBinTs();
		const totalBlocks = lenTotal / _PV_BLOCKSIZE;
		const fileBaseKey = _getFileBaseKey(slot, totalBlocks, binTs);

		const contents = await file.slice(0, _PV_CHUNKSIZE - 2 - filename.length - sodium.crypto_aead_chacha20poly1305_ABYTES);
		const contentsAb = await contents.arrayBuffer();

		const aead_src_len = ((totalChunks > 1) ? _PV_CHUNKSIZE : lenTotal) - sodium.crypto_aead_chacha20poly1305_ABYTES;
		const aead_src = new Uint8Array(aead_src_len);
		aead_src.set(new Uint8Array([lenPadding, filename.length]));
		aead_src.set(filename, 2);
		aead_src.set(new Uint8Array(contentsAb), 2 + filename.length);

		progressCallback("Encrypting chunk 1 of " + totalChunks, 0, totalChunks * 2);
		const aead_enc = sodium.crypto_aead_chacha20poly1305_encrypt(aead_src, null, null, new Uint8Array(sodium.crypto_aead_chacha20poly1305_NPUBBYTES), _getUfk(fileBaseKey));

		progressCallback("Uploading chunk 1 of " + totalChunks, 0, totalChunks * 2);

		_fetchEncrypted(await _fe_create_inner(binTs, slot, _PV_CMD_UPLOAD), binTs, _own_uid, 0, aead_enc, _getMfk_enc(fileBaseKey, binTs, slot), function(status) {
			if (status !== 0) {
				endCallback("Error: " + status);
			} else {
				_files[slot] = new _pvFile(folderPath + file.name, Math.round(file.lastModified / 1000), binTs, totalBlocks);

				if (totalChunks === 1) {
					endCallback("Done");
				} else {
					_uploadChunks(file, slot, binTs, totalBlocks, lenPadding, contents.size, totalChunks, 1, progressCallback, endCallback);
				}
			}
		});
	};

	this.fixFile = async function(slot, folderPath, progressCallback, endCallback) {if(typeof(slot)!=="number" || typeof(folderPath)!=="string" || typeof(endCallback)!=="function"){return;}
		if (folderPath && folderPath.startsWith("/")) folderPath = folderPath.substr(1);
		if (folderPath && !folderPath.endsWith("/")) folderPath += "/";

		progressCallback("Downloading first chunk", 0, 1);

		const binTs = _getBinTs();
		_fetchEncrypted(await _fe_create_inner(binTs, slot, _PV_CMD_DOWNLOAD), binTs, _own_uid, 0, null, null, function(resp) {
			if (typeof(resp) === "number") {endCallback("Error: " + resp); return;}

			const totalBlocks = new Uint32Array(resp.slice(5, 9).buffer)[0];
			const fileBaseKey = _getFileBaseKey(slot, totalBlocks, resp.slice(0, 5));
			const totalChunks = (totalBlocks * _PV_BLOCKSIZE) / _PV_CHUNKSIZE
			_files[slot].blocks = totalBlocks;

			progressCallback("Decrypting (AES) first chunk", 0.5, 1);
			_decryptMfk(resp.slice(9), _getMfk(fileBaseKey), async function(dec) {
				progressCallback("Decrypting (ChaCha20) first chunk", 0.75, 1);
				dec = sodium.crypto_aead_chacha20poly1305_decrypt(null, dec, null, new Uint8Array(sodium.crypto_aead_chacha20poly1305_NPUBBYTES), _getUfk(fileBaseKey));

				_files[slot].path = folderPath + sodium.to_string(dec.slice(2, 2 + dec[1]));
				endCallback("Fixed");
			});
		});
	};

	this.downloadFile = async function(slot, progressCallback, endCallback) {if(typeof(slot)!=="number" || typeof(endCallback)!=="function"){return;}
		let fileHandle = null;
		if (window.showSaveFilePicker) {
			fileHandle = await window.showSaveFilePicker({suggestedName: (_files[slot]) ? _files[slot].path : "Unknown"});
		}

		const binTs = _getBinTs();
		_downloadFile(_own_uid, null, slot, await _fe_create_inner(binTs, slot, _PV_CMD_DOWNLOAD), binTs, progressCallback, async function(dec, fileName, totalBlocks, lenPadding) {
			const totalChunks = Math.ceil((totalBlocks * _PV_BLOCKSIZE) / _PV_CHUNKSIZE);

			if (totalChunks > 1) {
				if (!fileHandle) {endCallback("This browser does not support downloading large files"); return;}

				const writer = await fileHandle.createWritable();
				writer.write(dec);

				_downloadChunks(slot, 1, totalChunks, lenPadding, writer, progressCallback, endCallback);
			} else {
				if (fileHandle) {
					writer.write(dec.slice(0, dec.length - lenPadding));
					writer.close();
					endCallback("Done");
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
			}
		});
	};

	this.downloadIndex = async function(callback) {if(typeof(callback)!=="function"){return;}
		const binTs = _getBinTs();
		_fetchEncrypted(await _fe_create_inner(binTs, 0, _PV_CMD_DOWNLOAD), binTs, _own_uid, 0, null, null, function(resp) {
			if (typeof(resp) === "number") {callback(resp); return;}

			const totalBlocks = new Uint32Array(resp.slice(5, 9).buffer)[0];
			const fileBaseKey = _getFileBaseKey(0, totalBlocks, resp.slice(0, 5));

			_decryptMfk(resp.slice(9), _getMfk(fileBaseKey), function(dec) {
				try {
					dec = sodium.crypto_aead_chacha20poly1305_decrypt(null, dec, null, new Uint8Array(sodium.crypto_aead_chacha20poly1305_NPUBBYTES), _getUfk(fileBaseKey));
				} catch(e) {callback(-1); return;}
				dec = dec.slice(2, dec.length - dec[0]);

				let n = 0;
				for (let i = 0; n < dec.length; i++) {
					const lenPath = dec[n];
					if (lenPath === 0) {n++; continue;}

					const fileBinTs = dec.slice(n + 1, n + 6);
					const fileTime   = new Uint32Array(dec.slice(n + 6, n + 10).buffer)[0];
					const fileBlocks = new Uint32Array(dec.slice(n + 10, n + 14).buffer)[0];

					let fileName;
					try {fileName = sodium.to_string(dec.slice(n + 14, n + 14 + lenPath));}
					catch(e) {fileName = "Error: " + e;}

					_files[i] = new _pvFile(fileName, fileTime, fileBinTs, fileBlocks);
					n += 14 + lenPath;
				}

				callback(0);
			});
		});
	};

	this.deleteFile = async function(slot, callback) {if(typeof(slot)!=="number" || typeof(callback)!=="function"){return;}
		const binTs = _getBinTs();
		_fetchEncrypted(await _fe_create_inner(binTs, slot, _PV_CMD_DELETE), binTs, _own_uid, 0, null, null, function(status) {
			if (status === 0) {
				_files[slot] = null;
			}

			callback(status);
		});
	};

	this.setKeys = function(umk_b64, callback) {if(typeof(umk_b64)!=="string" || typeof(callback)!=="function"){return;}
		if (umk_b64.length !== 64) {
			callback(false);
			return;
		}

		_own_umk = sodium.from_base64(umk_b64, sodium.base64_variants.ORIGINAL);
		_own_uak = sodium.crypto_generichash(_AEM_SECURITY_UAK_LEN, new Uint8Array([_AEM_SECURITY_KEYID_UAK]), _own_umk);
		_own_uid = new Uint16Array(sodium.crypto_generichash(16, "UserID", _own_uak).slice(0, 2).buffer)[0] & 4095;
		callback(true);
	};

	const b67_chars = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-.+#";

	this.createShareLink = async function(slot, expiration) {
		if (typeof(slot) !== "number" || slot < 1 || slot > 65535 || typeof(expiration) !== "number" || expiration < 0 || expiration > 15) return;

		const binTs = _getBinTs();
		const inner_enc = await _fe_create_inner(binTs, slot, _PV_CMD_DOWNLOAD | _PV_FLAG_SHARED | (expiration << 1));
		const fbk = _getFileBaseKey(slot, _files[slot].blocks, _files[slot].binTs);

		const binLink = new Uint8Array(fbk.length + binTs.length + inner_enc.length + 2);
		binLink.set(fbk);
		binLink.set(binTs, fbk.length);
		binLink.set(inner_enc, fbk.length + binTs.length);
		binLink.set(new Uint8Array(new Uint16Array([_own_uid]).buffer), fbk.length + binTs.length + inner_enc.length);

		let b = 0n;
		for (let i = 0; i < binLink.length; i++) {
			b += BigInt(binLink[i]) * (256n ** BigInt(i));
		}

		let url = document.documentURI + "#";
		for (let i = 0; i < 76; i++) {
			let y = b % 67n;
			url += b67_chars[Number(y)];
			b -= y;
			b /= 67n;
		}

		return url;
	};

	this.sharedLink_get = function(url, infoCallback, progressCallback, endCallback) {if(typeof(url)!=="string" || url.length!=76){return;}
		let b = 0n;
		for (let i = 0; i < 76; i++) {
			b += BigInt(b67_chars.indexOf(url[i])) * (67n ** BigInt(i));
		}

		let bin = new Uint8Array(58);
		for (let i = 0; i < 58; i++) {
			let y = b % 256n;
			bin[i] = Number(y);
			b -= y;
			b /= 256n;
		}

		const shr_fbk = bin.slice(0, 32);
		const shr_binTs = bin.slice(32, 37);
		const shr_inner_enc = bin.slice(37, 40 + sodium.crypto_onetimeauth_BYTES);
		const shr_uid = new Uint16Array(bin.slice(40 + sodium.crypto_onetimeauth_BYTES).buffer)[0];

		const shr_username = String.fromCharCode(97 + (shr_uid & 15)) + String.fromCharCode(97 + ((shr_uid >> 4) & 15)) + String.fromCharCode(97 + ((shr_uid >> 8) & 15));
		const shr_time = Number((BigInt(Date.now()) & ~((1n << 40n) - 1n)) | BigInt(new Uint32Array(shr_binTs.slice(0, 4).buffer)[0]) + BigInt(shr_binTs[4]) * BigInt(Math.pow(2, 32)));
		infoCallback(shr_username, shr_time);

		_downloadFile(shr_uid, shr_fbk, null, shr_inner_enc, shr_binTs, progressCallback, function(dec, fileName, totalBlocks, lenPadding) {
			const totalChunks = Math.ceil((totalBlocks * _PV_BLOCKSIZE) / _PV_CHUNKSIZE);

			_share_chunk1 = (totalChunks === 1) ? dec.slice(0, dec.length - lenPadding) : dec;
			_share_blocks = totalBlocks;
			_share_filename = fileName;

			endCallback(fileName, (totalBlocks * _PV_BLOCKSIZE) - lenPadding, _getFileType(fileName), _share_chunk1);
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
