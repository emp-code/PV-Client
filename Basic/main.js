"use strict";
sodium.ready.then(function() {

const vault = new PostVault(function(ok) {
	if (!ok) {
		document.getElementsByTagName("button")[0].disabled = true;
		return;
	}
});

function displayFiles() {
	document.getElementsByTagName("div")[0].hidden = true;
	document.getElementsByTagName("div")[1].hidden = true;
	document.getElementsByTagName("div")[2].hidden = false;

	document.getElementsByTagName("ul")[0].replaceChildren();

	for (let i = 0; i < 256; i++) {
		if (!vault.getFileName(i)) continue;

		const elLi = document.createElement("li");
		if (vault.getFileSize(i) > 0) {
			const elTime = document.createElement("time");
			elTime.textContent = new Date(vault.getFileTime(i) * 1000).toISOString().slice(0, 19).replace("T", " ") + " ";
			elLi.append(elTime);

			const elSpan = document.createElement("span");
			elSpan.textContent = vault.getFileName(i) + " (" + Math.round(vault.getFileSize(i) / 1024) + " KiB) ";
			elSpan.onclick = function() {
				vault.downloadFile(i,
					function(statusText, currentProgress, maxProgress) {
						document.getElementById("progress_text").textContent = statusText;
						document.getElementById("progress_meter").value = currentProgress;
						document.getElementById("progress_meter").max = maxProgress;
					},
					function(statusText) {
						document.getElementById("progress_text").textContent = statusText;
						document.getElementById("progress_meter").value = 1;
						document.getElementById("progress_meter").max = 1;
					},
				);
			};
			elLi.append(elSpan);

			const delBtn = document.createElement("button");
			delBtn.textContent = "Delete";
			delBtn.onclick = function() {
				const btn = this;
				btn.disabled = true;

				vault.deleteFile(i, function(status) {
					if (status === 0) {
						elSpan.onclick = "";
						elLi.style.textDecoration = "line-through";
					} else {
						btn.enabled = true;
					}
				});
			};
			elLi.append(delBtn);
		} else {
			elLi.textContent = vault.getFileName(i);
			elLi.style.textDecoration = "line-through";
		}

		document.getElementsByTagName("ul")[0].append(elLi);
	}
}

document.getElementById("btn_ind").onclick = function() {
	const btn = this;
	btn.disabled = true;

	vault.uploadIndex(function(status) {
		btn.disabled = false;
	});
}

document.getElementById("btn_upl").onclick = function() {
	const btn = this;

	const fileSelector = document.createElement("input");
	fileSelector.type = "file";
	fileSelector.click();

	fileSelector.onchange = function() {
		const file = fileSelector.files[0];
		btn.disabled = true;

		vault.uploadFile(file,
			function(statusText, currentProgress, maxProgress) {
				document.getElementById("progress_text").textContent = statusText;
				document.getElementById("progress_meter").value = currentProgress;
				document.getElementById("progress_meter").max = maxProgress;
			},
			function(statusText) {
				document.getElementById("progress_text").textContent = statusText;
				document.getElementById("progress_meter").value = 1;
				document.getElementById("progress_meter").max = 1;

				displayFiles();
				btn.disabled = false;
			},
		);
	};
};

document.getElementsByTagName("button")[0].onclick = function() {
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

		document.getElementsByTagName("div")[0].hidden = true;
		document.getElementsByTagName("div")[1].hidden = false;

		vault.downloadIndex(function() {displayFiles()});
		displayFiles();
	});
};

});
