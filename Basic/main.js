"use strict";
sodium.ready.then(function() {

const vault = new PostVault(function(ok) {
	if (!ok) {
		document.getElementsByTagName("button")[0].disabled = true;
		return;
	}
});

let currentPath = "";

function displayFiles(basePath) {
	currentPath = basePath;

	document.getElementsByTagName("div")[0].hidden = true;
	document.getElementsByTagName("div")[1].hidden = true;
	document.getElementsByTagName("div")[2].hidden = false;

	document.getElementsByTagName("ul")[0].replaceChildren();

	if (basePath !== "") {
		const elLi = document.createElement("li");
		elLi.textContent = "📁 ..";
		elLi.onclick = function() {
			displayFiles("");
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
		elSpan.textContent = vault.getFilePath(f).substr(basePath.length) + " (" + Math.round(vault.getFileSize(f) / 1024) + " KiB) ";
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
				},
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

		document.getElementsByTagName("ul")[0].append(elLi);
	});
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

		vault.uploadFile(currentPath, file,
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

		vault.downloadIndex(function() {displayFiles("")});
	});
};

});
