const dropArea = document.getElementById("dropArea");
const fileInput = document.getElementById("fileInput");
const progressBar = document.getElementById("progress-bar");
const progressContainer = document.getElementById("progress-container");
const mainContainer = document.querySelector(".main_container");

const loggedIn = mainContainer && mainContainer.dataset.loggedIn === "1";

let mode = "public";
if (loggedIn) {
	const saved = sessionStorage.getItem("mode");
	if (saved === "private" || saved === "public") mode = saved;
}

const publicList = document.getElementById("publicList");
const privateList = document.getElementById("privateList");
const modeDot = document.getElementById("modeDot");

progressBar.textContent = "";
progressContainer.dataset.progress = "0%";

function applyMode() {
	const isPublic = mode === "public";
	if (publicList) publicList.hidden = !isPublic;
	if (privateList) privateList.hidden = isPublic;
	if (modeDot) {
		modeDot.classList.toggle("dot-public", isPublic);
		modeDot.classList.toggle("dot-private", !isPublic);
	}
}

const logoToggle = document.getElementById("logoToggle");
if (loggedIn && logoToggle) {
	logoToggle.addEventListener("click", () => {
		mode = mode === "public" ? "private" : "public";
		sessionStorage.setItem("mode", mode);
		applyMode();
	});
}
applyMode();

dropArea.addEventListener("click", () => fileInput.click());

dropArea.addEventListener("dragover", (e) => {
	e.preventDefault();
	dropArea.classList.add("dragover");
});

dropArea.addEventListener("dragleave", () => {
	dropArea.classList.remove("dragover");
});

dropArea.addEventListener("drop", (e) => {
	e.preventDefault();
	dropArea.classList.remove("dragover");
	if (e.dataTransfer.files.length) {
		uploadFile(e.dataTransfer.files[0]);
	}
});

fileInput.addEventListener("change", () => {
	if (fileInput.files.length) {
		uploadFile(fileInput.files[0]);
	}
});

function setProgressText(text) {
	progressContainer.dataset.progress = text;
}

function csrf() {
	const el = document.getElementById("csrfToken");
	return el ? el.value : "";
}

function uploadFile(file) {
	const isPublic = !loggedIn || mode === "public";

	const formData = new FormData();
	formData.append("file", file);
	formData.append("csrf_token", csrf());
	formData.append("is_public", isPublic ? "true" : "false");

	const xhr = new XMLHttpRequest();
	xhr.open("POST", "/upload", true);

	xhr.upload.onprogress = function (e) {
		if (e.lengthComputable) {
			const percent = Math.round((e.loaded / e.total) * 100);
			progressBar.style.width = percent + "%";
			setProgressText(percent + "%");
		}
	};

	xhr.onload = function () {
		if (xhr.status === 200) {
			setProgressText("Done");
			setTimeout(() => location.reload(), 1000);
		} else {
			let msg = "Error";
			try {
				const r = JSON.parse(xhr.responseText);
				if (r && r.message) msg = r.message;
			} catch (e) {}
			setProgressText(msg);
		}
	};

	xhr.onerror = function () {
		setProgressText("Error");
	};

	xhr.send(formData);
}

function copyToClipboard(text) {
	const textArea = document.createElement("textarea");
	textArea.value = text;
	document.body.appendChild(textArea);
	textArea.select();
	document.execCommand("copy");
	document.body.removeChild(textArea);
}

document.addEventListener("click", (e) => {
	const copyBtn = e.target.closest(".copy-btn");
	if (copyBtn) {
		copyToClipboard(
			window.location.origin + copyBtn.getAttribute("data-url"),
		);
		copyBtn.classList.add("copied");
		setTimeout(() => copyBtn.classList.remove("copied"), 1500);
		return;
	}
	const fileBtn = e.target.closest(".file-button");
	if (fileBtn) {
		window.open(fileBtn.dataset.url, "_blank");
	}
});

const COPY_SVG =
	'<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24"' +
	' fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"' +
	' stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="3" ry="3"/>' +
	'<path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>';

function buildPublicRow(file) {
	const row = document.createElement("div");
	row.className = "files_buttons_container";

	const btn = document.createElement("button");
	btn.className = "file-button";
	btn.dataset.url = file.url;
	btn.textContent = file.name; // textContent avoids HTML injection

	const copy = document.createElement("span");
	copy.className = "copy-btn";
	copy.setAttribute("data-url", file.url);
	copy.innerHTML = COPY_SVG;

	row.appendChild(btn);
	row.appendChild(copy);
	return row;
}

(function initInfiniteScroll() {
	const list = publicList;
	const sentinel = document.getElementById("publicSentinel");
	if (!list || !sentinel) return;

	let offset = parseInt(list.dataset.offset || "0", 10);
	let hasMore = list.dataset.hasMore === "1";
	let loading = false;

	async function loadMore() {
		if (loading || !hasMore) return;
		loading = true;
		try {
			const r = await fetch("/api/public?offset=" + offset);
			if (!r.ok) return;
			const data = await r.json();
			const files = data.files || [];
			for (const f of files) {
				list.insertBefore(buildPublicRow(f), sentinel);
			}
			offset += files.length;
			hasMore = !!data.has_more;
		} catch (e) {
		} finally {
			loading = false;
		}
	}

	const observer = new IntersectionObserver(
		(entries) => {
			if (entries.some((e) => e.isIntersecting)) loadMore();
		},
		{ rootMargin: "200px" },
	);
	observer.observe(sentinel);
})();

const loginBtn = document.getElementById("loginBtn");
const loginModal = document.getElementById("loginModal");

if (loginBtn && loginModal) {
	const modalClose = document.getElementById("modalClose");
	const modalTitle = document.getElementById("modalTitle");
	const modalSubmit = document.getElementById("modalSubmit");
	const modalError = document.getElementById("modalError");
	const switchText = document.getElementById("switchText");
	const switchLink = document.getElementById("switchLink");
	const authForm = document.getElementById("authForm");
	const emailEl = document.getElementById("modalEmail");
	const passwordEl = document.getElementById("modalPassword");
	const modalCsrf = document.getElementById("modalCsrf");

	let authMode = "login";

	function showError(msg) {
		modalError.textContent = msg;
		modalError.hidden = !msg;
	}

	function setAuthMode(m) {
		authMode = m;
		const login = m === "login";
		modalTitle.textContent = login ? "Login" : "Register";
		modalSubmit.textContent = login ? "Login" : "Register";
		switchText.textContent = login
			? "No account?"
			: "Already have an account?";
		switchLink.textContent = login ? "Register" : "Login";
		passwordEl.setAttribute(
			"autocomplete",
			login ? "current-password" : "new-password",
		);
		showError("");
	}

	function openModal() {
		loginModal.hidden = false;
		emailEl.focus();
	}

	function closeModal() {
		loginModal.hidden = true;
		showError("");
	}

	loginBtn.addEventListener("click", openModal);
	modalClose.addEventListener("click", closeModal);
	loginModal.addEventListener("click", (e) => {
		if (e.target === loginModal) closeModal();
	});
	document.addEventListener("keydown", (e) => {
		if (e.key === "Escape" && !loginModal.hidden) closeModal();
	});

	switchLink.addEventListener("click", (e) => {
		e.preventDefault();
		setAuthMode(authMode === "login" ? "register" : "login");
	});

	authForm.addEventListener("submit", (e) => {
		e.preventDefault();
		showError("");
		modalSubmit.disabled = true;

		const formData = new FormData();
		formData.append("csrf_token", modalCsrf.value);
		formData.append("email", emailEl.value.trim());
		formData.append("password", passwordEl.value);

		fetch("/" + authMode, { method: "POST", body: formData })
			.then((r) =>
				r
					.json()
					.catch(() => ({}))
					.then((body) => ({ ok: r.ok, body })),
			)
			.then(({ ok, body }) => {
				if (ok && body.success) {
					window.location.href = body.redirect || "/";
					return;
				}
				showError(body.message || "Something went wrong.");
				modalSubmit.disabled = false;
			})
			.catch(() => {
				showError("Network error.");
				modalSubmit.disabled = false;
			});
	});

	setAuthMode("login");
}
