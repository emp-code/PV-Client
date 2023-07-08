"use strict";

function PostVault(readyCallback) {
	const crypto_aead_aes256gcm_ABYTES = 16;
	const _PV_CHUNKSIZE = 16777216;
	const _PV_BLOCKSIZE = 16;

	const _PV_FLAG_SHARED = 1;
	const _PV_FLAG_KEEPOLD = 2;

	const _PV_CMD_DOWNLOAD = 0;
	const _PV_CMD_UPLOAD =  64;
	const _PV_CMD_DELETE = 128;
//	const _PV_CMD_       = 192;

	const _PV_APIURL = document.head.querySelector("meta[name='postvault.url']").content;
	const _PV_DOCSPK = document.head.querySelector("meta[name='postvault.spk']").content;

//	if (!_PV_DOMAIN || !new RegExp(/^[0-9a-z.-]{1,63}\.[0-9a-z-]{2,63}$/).test(_PV_DOMAIN) || !_PV_DOCSPK || !new RegExp("^[0-9A-f]{" + (sodium.crypto_box_PUBLICKEYBYTES * 2).toString() + "}$").test(_PV_DOCSPK)) {
//		readyCallback(false);
//		return;
//	}

	const _PV_SPK = sodium.from_hex(_PV_DOCSPK);

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

		callback((r.status === 200) ? new Uint8Array(await r.arrayBuffer()) : null);
	};

	const _fe_aes_enc = async function(flags, slot, binTs) {
		const aes_nonce = new Uint8Array(12); // 96 bits
		aes_nonce.set(binTs);

		const aes_src = new Uint8Array(3);
		aes_src.set(new Uint8Array(new Uint16Array([slot]).buffer));
		aes_src[2] = flags;

		return new Uint8Array(await window.crypto.subtle.encrypt({name: "AES-GCM", iv: aes_nonce}, await window.crypto.subtle.importKey("raw", _own_uak, {"name": "AES-GCM"}, false, ["encrypt"]), aes_src));
	};

	const _fetchEncrypted = async function(aes_enc, binTs, uid, chunk, content, mfk, callback) {
		await new Promise(resolve => setTimeout(resolve, 1)); // Ensure requests are never made within the same millisecond

		const box_src = new Uint8Array(8 + aes_enc.length);
		box_src.set(binTs);
		box_src.set(new Uint8Array(new Uint32Array([uid | (chunk << 12)]).buffer).slice(0, 3), 5);
		box_src.set(aes_enc, 8);

		const box_keys = sodium.crypto_box_keypair();
		const box_nonce = new Uint8Array(sodium.crypto_box_NONCEBYTES);
		box_nonce.fill(0x01);
		const box_enc = sodium.crypto_box_easy(box_src, box_nonce, _PV_SPK, box_keys.privateKey);

		const box_wrap = new Uint8Array(box_enc.length + sodium.crypto_box_PUBLICKEYBYTES);
		box_wrap.set(box_enc);
		box_wrap.set(box_keys.publicKey, box_enc.length);

		let postBox;
		if (content && (typeof(content) === "object")) {
			const postBox_src = new Uint8Array(content.length + 32);
			postBox_src.set(mfk);
			postBox_src.set(content, 32);

			box_nonce.fill(0x02);
			postBox = sodium.crypto_box_easy(postBox_src, box_nonce, _PV_SPK, box_keys.privateKey);
		} else postBox = null;

		_fetchBinary(box_wrap, postBox, function(result_box) {
			if (!result_box) {callback(-1); return;}

			box_nonce.fill(0xFF);

			let dec;
			try {dec = sodium.crypto_box_open_easy(result_box, box_nonce, _PV_SPK, box_keys.privateKey);}
			catch(e) {callback(null); return;}

			// TODO: 5 bytes: LastMod

			callback(dec.slice(5));
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
				const path = sodium.from_string(_files[i].path);

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

	const _getFileBaseKey = function(slot, blocks, binTs) {
		const bytes = new Uint8Array(11);
		bytes.set(new Uint8Array(new Uint16Array([slot]).buffer));
		bytes.set(new Uint8Array(new Uint32Array([blocks]).buffer), 2);
		bytes.set(binTs, 6);
		return sodium.crypto_generichash(sodium.crypto_kdf_KEYBYTES, bytes, _own_umk);
	}

	const _getNonce = function(len) {
		return sodium.crypto_generichash(len, _PV_SPK, null);
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

	// Public functions

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
	}

	this.getFilePath = function(num) {if(typeof(num)!=="number") return; return _files[num]? _files[num].path : null;};
	this.getFileSize = function(num) {if(typeof(num)!=="number") return; return _files[num]? _files[num].blocks * _PV_BLOCKSIZE : null;};
	this.getFileTime = function(num) {if(typeof(num)!=="number") return; return _files[num]? _files[num].lastMod : null;};

	this.getTotalFiles = function() {return _files.length;};
	this.getTotalSize = function() {
		let b = 0;
		_files.forEach(function(f) {b += f.blocks;});
		return b * _PV_BLOCKSIZE;
	}

	this.moveFile = function(num, newPath) {if(typeof(num)!=="number" || typeof(newPath)!=="string" || newPath.length<1 || !_files[num]) return false; _files[num].path = newPath; return true;};

	this.uploadIndex = async function(callback) {if(typeof(callback)!=="function"){return;}
		const index_src = _genIndex();
		const binTs = _getBinTs();
		const totalBlocks = (index_src.length + sodium.crypto_aead_chacha20poly1305_ABYTES) / _PV_BLOCKSIZE;
		const fbk = _getFileBaseKey(0, totalBlocks, binTs);
		const index_enc = sodium.crypto_aead_chacha20poly1305_encrypt(index_src, null, null, _getNonce(sodium.crypto_aead_chacha20poly1305_NPUBBYTES), _getUfk(fbk, 0));

		_fetchEncrypted(await _fe_aes_enc(_PV_CMD_UPLOAD, 0, binTs), binTs, _own_uid, 0, index_enc, _getMfk(fbk, 0), function(status) {
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
		const fileBaseKey = _getFileBaseKey(slot, totalBlocks, binTs);
		const aead_enc = sodium.crypto_aead_chacha20poly1305_encrypt(aead_src, null, null, _getNonce(sodium.crypto_aead_chacha20poly1305_NPUBBYTES), _getUfk(fileBaseKey, chunk));

		offset += _PV_CHUNKSIZE - sodium.crypto_aead_chacha20poly1305_ABYTES;

		progressCallback("Uploading chunk " + (chunk + 1) + " of " + totalChunks, chunk * 2 + 1, totalChunks * 2);

		const bts = _getBinTs();
		_fetchEncrypted(await _fe_aes_enc(_PV_CMD_UPLOAD | _PV_FLAG_KEEPOLD, slot, bts), bts, _own_uid, chunk, aead_enc, _getMfk(fileBaseKey, chunk), function(status) {
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
		const aead_enc = sodium.crypto_aead_chacha20poly1305_encrypt(aead_src, null, null, _getNonce(sodium.crypto_aead_chacha20poly1305_NPUBBYTES), _getUfk(fileBaseKey, 0));

		progressCallback("Uploading chunk 1 of " + totalChunks, 0, totalChunks * 2);

		_fetchEncrypted(await _fe_aes_enc(_PV_CMD_UPLOAD, slot, binTs), binTs, _own_uid, 0, aead_enc, _getMfk(fileBaseKey, 0), function(status) {
			if (typeof(status) === "number") {
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
		_fetchEncrypted(await _fe_aes_enc(_PV_CMD_DOWNLOAD, slot, binTs), binTs, _own_uid, 0, null, null, function(resp) {
			if (typeof(resp) === "number") {endCallback("Error: " + resp); return;}

			const totalBlocks = new Uint32Array(resp.slice(5, 9).buffer)[0];
			const fileBaseKey = _getFileBaseKey(slot, totalBlocks, resp.slice(0, 5));
			const totalChunks = (totalBlocks * _PV_BLOCKSIZE) / _PV_CHUNKSIZE
			_files[slot].blocks = totalBlocks;

			progressCallback("Decrypting (AES) first chunk", 0.5, 1);
			_decryptMfk(resp.slice(9), _getMfk(fileBaseKey, 0), async function(dec) {
				progressCallback("Decrypting (ChaCha20) first chunk", 0.75, 1);
				dec = sodium.crypto_aead_chacha20poly1305_decrypt(null, dec, null, _getNonce(sodium.crypto_aead_chacha20poly1305_NPUBBYTES), _getUfk(fileBaseKey, 0));

				_files[slot].path = folderPath + sodium.to_string(dec.slice(2, 2 + dec[1]));
				endCallback("Fixed");
			});
		});
	};

	const _downloadChunks = async function(slot, chunk, totalChunks, lenPadding, writer, progressCallback, endCallback) {
		progressCallback("Downloading chunk " + (chunk + 1) + " of " + totalChunks, chunk * 2, totalChunks * 2);

		const binTs = _getBinTs();
		_fetchEncrypted(await _fe_aes_enc(_PV_CMD_DOWNLOAD, slot, binTs), binTs, _own_uid, chunk, null, null, function(resp) {
			if (typeof(resp) === "number") {writer.close(); endCallback("Fail: " + resp); return;}

			const totalBlocks = new Uint32Array(resp.slice(5, 9).buffer)[0];
			const fileBaseKey = _getFileBaseKey(slot, totalBlocks, resp.slice(0, 5));

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

	const _downloadFile = async function(uid, fbk, slot, aes_enc, binTs, progressCallback, doneCallback) {
		progressCallback("Downloading chunk 1 of " + (slot? Math.ceil((_files[slot].blocks * _PV_BLOCKSIZE) / _PV_CHUNKSIZE) : "?"), 0, 1);

		_fetchEncrypted(aes_enc, binTs, uid, 0, null, null, function(resp) {
			if (typeof(resp) === "number") {endCallback("Error: " + resp); return;}

			const totalBlocks = new Uint32Array(resp.slice(5, 9).buffer)[0];
			const totalChunks = Math.ceil((totalBlocks * _PV_BLOCKSIZE) / _PV_CHUNKSIZE);
			if (!fbk) fbk = _getFileBaseKey(slot, totalBlocks, resp.slice(0, 5));

			progressCallback("Decrypting (AES) chunk 1 of " + totalChunks, 1, totalChunks * 2);
			_decryptMfk(resp.slice(9), _getMfk(fbk, 0), async function(dec) {
				progressCallback("Decrypting (ChaCha20) chunk 1 of " + totalChunks, 1.333, totalChunks * 2);
				dec = sodium.crypto_aead_chacha20poly1305_decrypt(null, dec, null, _getNonce(sodium.crypto_aead_chacha20poly1305_NPUBBYTES), _getUfk(fbk, 0));

				const fileName = sodium.to_string(dec.slice(2, 2 + dec[1]));
				const lenPadding = dec[0];

				doneCallback(dec.slice(2 + dec[1]), fileName, totalBlocks, lenPadding);
			});
		});
	};

	this.downloadFile = async function(slot, progressCallback, endCallback) {if(typeof(slot)!=="number" || typeof(endCallback)!=="function"){return;}
		let fileHandle = null;
		if (window.showSaveFilePicker) {
			fileHandle = await window.showSaveFilePicker({suggestedName: (_files[slot]) ? _files[slot].path : "Unknown"});
		}

		const binTs = _getBinTs();
		_downloadFile(_own_uid, null, slot, await _fe_aes_enc(_PV_CMD_DOWNLOAD, slot, binTs), binTs, progressCallback, async function(dec, fileName, totalBlocks, lenPadding) {
			const totalChunks = Math.ceil((totalBlocks * _PV_BLOCKSIZE) / _PV_CHUNKSIZE);

			if (totalChunks > 1) {
				if (!fileHandle) {endCallback("This browser does not support downloading large files"); return;}

				const writer = await fileHandle.createWritable();
				writer.write(dec);

				downloadChunks(slot, 1, totalChunks, lenPadding, writer, progressCallback, endCallback);
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
		_fetchEncrypted(await _fe_aes_enc(_PV_CMD_DOWNLOAD, 0, binTs), binTs, _own_uid, 0, null, null, function(resp) {
			if (typeof(resp) === "number") {callback(resp); return;}

			const totalBlocks = new Uint32Array(resp.slice(5, 9).buffer)[0];
			const fileBaseKey = _getFileBaseKey(0, totalBlocks, resp.slice(0, 5));

			_decryptMfk(resp.slice(9), _getMfk(fileBaseKey, 0), function(dec) {
				dec = sodium.crypto_aead_chacha20poly1305_decrypt(null, dec, null, _getNonce(sodium.crypto_aead_chacha20poly1305_NPUBBYTES), _getUfk(fileBaseKey, 0));
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
		_fetchEncrypted(await _fe_aes_enc(_PV_CMD_DELETE, slot, binTs), binTs, _own_uid, 0, null, null, function(resp) {
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
		_own_uak = sodium.crypto_kdf_derive_from_key(32, 1, "PVt-Uak0", _own_umk);
		_own_uid = new Uint16Array(sodium.crypto_aead_chacha20poly1305_encrypt("UserID", null, null, new Uint8Array([0,0,0,0,0,0,0,0]), _own_uak).slice(0, 2).buffer)[0] & 4095;

		callback(true);
	};

	const b84_chars = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()_+=-?.,[]{}'";

	this.getShareLink = async function(slot) {
		const binTs = _getBinTs();
		const aes_enc = await _fe_aes_enc(_PV_CMD_DOWNLOAD | _PV_FLAG_SHARED, slot, binTs);
		const fbk = _getFileBaseKey(slot, _files[slot].blocks, _files[slot].binTs);

		const binLink = new Uint8Array(fbk.length + binTs.length + aes_enc.length + 2);
		binLink.set(fbk);
		binLink.set(binTs, fbk.length);
		binLink.set(aes_enc, fbk.length + binTs.length);
		binLink.set(new Uint8Array(new Uint16Array([_own_uid]).buffer), fbk.length + binTs.length + aes_enc.length);

		let b = 0n;
		for (let i = 0; i < 58; i++) {
			b += BigInt(binLink[i]) * (256n ** BigInt(i));
		}

		let url = document.documentURI + "#";
		for (let i = 0; i < 72; i++) {
			let y = b % 84n;
			url += b84_chars[Number(y)];
			b -= y;
			b /= 84n;
		}

		return url;
	};

	this.sharedLink_get = function(url, infoCallback, progressCallback, endCallback) {if(typeof(url)!=="string" || url.length!=72){return;}
		let b = 0n;
		for (let i = 0; i < 72; i++) {
			b += BigInt(b84_chars.indexOf(url[i])) * (84n ** BigInt(i));
		}

		let bin = new Uint8Array(58);
		for (let i = 0; i < 58; i++) {
			let y = b % 256n;
			bin[i] = Number(y);
			b -= y;
			b /= 256n;
		}

		const shr_fbk = bin.slice(0, sodium.crypto_kdf_KEYBYTES);
		const shr_binTs = bin.slice(sodium.crypto_kdf_KEYBYTES, sodium.crypto_kdf_KEYBYTES + 5);
		const shr_aes_enc = bin.slice(sodium.crypto_kdf_KEYBYTES + 5, sodium.crypto_kdf_KEYBYTES + 8 + crypto_aead_aes256gcm_ABYTES);
		const shr_uid = new Uint16Array(bin.slice(sodium.crypto_kdf_KEYBYTES + 8 + crypto_aead_aes256gcm_ABYTES).buffer)[0];

		infoCallback(String.fromCharCode(97 + (shr_uid & 15)) + String.fromCharCode(97 + ((shr_uid >> 4) & 15)) + String.fromCharCode(97 + ((shr_uid >> 8) & 15)), new Uint32Array(shr_binTs.slice(0, 4).buffer)[0] + (shr_binTs[4] * Math.pow(2, 32)));

		_downloadFile(shr_uid, shr_fbk, null, shr_aes_enc, shr_binTs, progressCallback, function(dec, fileName, totalBlocks, lenPadding) {
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
			endCallback("Done");
		}
	};

	readyCallback(true);
}
