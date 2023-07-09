"use strict";

sodium.ready.then(function() {
	const vault = new PostVault(function(ok) {
		if (!ok) {
			return;
		}
	});

	if (document.location.hash) {
		document.getElementById("div_load").hidden = true;
		document.getElementById("div_shared").hidden = false;

		vault.sharedLink_get(document.location.hash.substr(1), function(shr_uid, shr_ts) {
			document.getElementById("share_uid").textContent = shr_uid;
			document.getElementById("share_date").textContent = new Date(shr_ts).toISOString().substr(0, 10);
		}, function(status) {
			document.getElementById("share_status").textContent = status;
		}, function(fileName, fileSize, fileType, fileData) {
			document.getElementById("share_status").textContent = fileName + " (" + fileSize + " bytes)";

			let el;
			switch (fileType) {
				case "image":
					el = document.createElement("img");
					el.src = URL.createObjectURL(new Blob([fileData.buffer]));
				break;

				case "text":
					el = document.createElement("p");
					el.textContent = sodium.to_string(fileData);
				break;

				case "audio":
				case "video":
					el = document.createElement(fileType);
					el.controls = "controls";
					el.src = URL.createObjectURL(new Blob([fileData.buffer]));
				break;

				case "pdf":
					el = document.createElement("embed");
					el.type = "application/pdf";
					el.src = URL.createObjectURL(new Blob([fileData.buffer], {type: "application/pdf"}));
				break;

				default: return;
			}

			const m = document.querySelector("#div_shared main");
			const h = getComputedStyle(m).height;
			m.style.height = h;
			el.style.height = h;
			m.appendChild(el);
		});

		document.getElementById("share_save").onclick = function() {vault.sharedLink_save();};
		return;
	}

	let currentPath = "";

	function getDisplaySize(bytes) {
		if (bytes > 1073741824) {
			return (bytes / 1073741824).toFixed(1) + " GiB";
		} else if (bytes > 1048576) {
			return Math.round(bytes / 1048576) + " MiB";
		} else if (bytes > 1024) {
			return Math.round(bytes / 1024) + " KiB";
		} else {
			return bytes + " B";
		}
	}

	function displayFiles(basePath) {
		if (basePath.startsWith("/")) basePath = basePath.substr(1);
		currentPath = basePath;

		document.getElementsByTagName("ul")[0].replaceChildren();

		if (basePath !== "") {
			const elLi = document.createElement("li");
			elLi.textContent = "📁 ..";
			elLi.onclick = function() {
				displayFiles(currentPath.substr(0, currentPath.lastIndexOf("/")));
			}

			document.getElementsByTagName("ul")[0].append(elLi);
		}

		const folders = vault.getFolderContents(basePath, false, true);
		folders.forEach(function(f) {
			const elLi = document.createElement("li");
			elLi.textContent = "📁 " + f;
			elLi.onclick = function() {
				displayFiles(basePath + "/" + f);
			}

			document.getElementsByTagName("ul")[0].append(elLi);
		});

		const files = vault.getFolderContents(basePath, true, false);
		files.forEach(function(f) {
			const elLi = document.createElement("li");

			const elTime = document.createElement("time");
			elTime.textContent = new Date(vault.getFileTime(f) * 1000).toISOString().slice(0, 19).replace("T", " ") + " ";
			elLi.append(elTime);

			const elSpan = document.createElement("span");

			elSpan.textContent = vault.getFilePath(f).substr(basePath? basePath.length + 1 : 0) + " (" + getDisplaySize(vault.getFileSize(f)) + ") ";
			elSpan.onclick = function() {
				vault.downloadFile(f,
					function(statusText, currentProgress, maxProgress) {
						document.getElementById("progress_text").textContent = statusText;
						document.getElementById("progress_meter").value = currentProgress;
						document.getElementById("progress_meter").max = maxProgress;
					},
					function(statusText) {
						document.getElementById("progress_text").textContent = statusText;
						document.getElementById("progress_meter").value = 1;
						document.getElementById("progress_meter").max = 1;
					}
				);
			};
			elLi.append(elSpan);

			const delBtn = document.createElement("button");
			delBtn.textContent = "Delete";
			delBtn.onclick = function() {
				const btn = this;
				btn.disabled = true;

				vault.deleteFile(f, function(status) {
					if (status === 0) {
						elSpan.onclick = "";
						elLi.style.textDecoration = "line-through";
					} else {
						btn.enabled = true;
					}
				});
			};
			elLi.append(delBtn);

			const mvBtn = document.createElement("button");
			mvBtn.textContent = "Move";
			mvBtn.onclick = function() {
				if (vault.moveFile(f, prompt("New path", vault.getFilePath(f)))) {
					displayFiles(basePath);
				}
			};
			elLi.append(mvBtn);

			const fxBtn = document.createElement("button");
			fxBtn.textContent = "Fix";
			fxBtn.onclick = function() {
				vault.fixFile(f, currentPath,
					function(statusText, currentProgress, maxProgress) {
						document.getElementById("progress_text").textContent = statusText;
						document.getElementById("progress_meter").value = currentProgress;
						document.getElementById("progress_meter").max = maxProgress;
					},
					function(statusText) {
						document.getElementById("progress_text").textContent = statusText;
						document.getElementById("progress_meter").value = 1;
						document.getElementById("progress_meter").max = 1;
						displayFiles(currentPath);
					}
				);
			}
			elLi.append(fxBtn);

			const shBtn = document.createElement("button");
			shBtn.textContent = "Share";

			shBtn.onclick = async function() {
				await navigator.clipboard.writeText(await vault.createShareLink(f, Number(document.getElementById("share_expiration").value)));
				document.getElementById("progress_text").textContent = "Link copied to clipboard"
			};
			elLi.append(shBtn);

			document.getElementsByTagName("ul")[0].append(elLi);
		});

		document.getElementById("totalfiles").textContent = vault.getTotalFiles();
		document.getElementById("totalsize").textContent = getDisplaySize(vault.getTotalSize());
	}

	document.querySelector("input[type=range]").oninput = function() {
		this.parentElement.children[1].textContent = vault.getExpirationValues()[this.value];
	}

	document.getElementById("btn_ind").onclick = function() {
		const btn = this;
		btn.disabled = true;

		vault.uploadIndex(function(status) {
			btn.disabled = false;
		});
	}

	function uploadFile(files, cur) {
		vault.uploadFile(currentPath, files[cur],
			function(statusText, currentProgress, maxProgress) {
				document.getElementById("progress_text").textContent = statusText;
				document.getElementById("progress_meter").value = currentProgress;
				document.getElementById("progress_meter").max = maxProgress;
			},
			function(statusText) {
				displayFiles(currentPath);

				if (cur + 1 < files.length) {
					uploadFile(files, cur + 1);
				} else {
					document.getElementById("progress_text").textContent = statusText;
					document.getElementById("progress_meter").value = 1;
					document.getElementById("progress_meter").max = 1;

					document.getElementById("btn_upl").disabled = false;
				}
			},
		);
	}

	document.getElementById("btn_upl").onclick = function() {
		const btn = this;

		const fileSelector = document.createElement("input");
		fileSelector.type = "file";
		fileSelector.multiple = "multiple";
		fileSelector.click();

		fileSelector.onchange = function() {
			btn.disabled = true;
			uploadFile(fileSelector.files, 0);
		};
	};

	document.querySelector("#div_entry button").onclick = function() {
		const txtKey = document.getElementsByTagName("input")[0];
		if (!txtKey.reportValidity()) return;
		txtKey.disabled = true;

		const btn = this;
		btn.disabled = true;

		vault.setKeys(txtKey.value, function(successSetKeys) {
			if (!successSetKeys) {
				btn.enabled = true;
				return;
			}

			document.getElementById("div_entry").hidden = true;
			document.getElementById("div_files").hidden = false;

			vault.downloadIndex(function(status) {
				if (status === 0) displayFiles("");
			});
		});
	};

	document.getElementById("div_load").hidden = true;
	document.getElementById("div_entry").hidden = false;
});
