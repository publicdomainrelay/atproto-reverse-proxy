import { BrowserOAuthClient } from '@atproto/oauth-client-browser'
import { Agent } from '@atproto/api'

function buildClientID() {
	const isLocal = ["localhost", "127.0.0.1"].includes(window.location.hostname);
	if (isLocal) {
		// see https://atproto.com/specs/oauth#localhost-client-development
		return `http://localhost?${new URLSearchParams({
			scope: "atproto repo:com.fedproxy.sshPublicKey?action=create",
			redirect_uri: Object.assign(new URL(window.location.origin), { hostname: '127.0.0.1' }).href,
		})}`
	}
	return `https://${window.location.host}/oauth-client-metadata.json`
}
const clientId = buildClientID();

let oac; // undefined | BrowserOAuthClient
let agent; // undefined | Agent   (gets assigned after successful auth)

// Helper function to fetch and render SSH Keys securely
async function fetchAndRenderKeys(handle) {
	const listContainer = document.getElementById("ssh-public-keys-list");
	listContainer.setAttribute("aria-busy", "true");
	listContainer.innerHTML = ""; // Clear existing

	let sshPublicKeysByService = {};
	let cursor = undefined;

	try {
		while (cursor === undefined || cursor != null) {
			const res = await agent.com.atproto.repo.listRecords({
				repo: agent.did,
				collection: 'com.fedproxy.sshPublicKey',
				cursor: cursor,
			});

			if (!res.success) {
				throw new Error(JSON.stringify(res));
			}

			for (let i = 0; i < res.data.records.length; i++) {
				const sshPublicKey = res.data.records[i].value;
				if (!(sshPublicKey.service in sshPublicKeysByService)) {
					sshPublicKeysByService[sshPublicKey.service] = [];
				}
				sshPublicKeysByService[sshPublicKey.service].push(sshPublicKey);
			}

			if (typeof res.data.cursor === "string") {
				cursor = res.data.cursor;
			} else {
				cursor = null;
			}
		}

		listContainer.removeAttribute("aria-busy");

		const services = Object.keys(sshPublicKeysByService);
		if (services.length === 0) {
			listContainer.innerHTML = "<p><em>No SSH keys found. Create one above!</em></p>";
			return;
		}

		// Render lists securely to prevent XSS
		for (const [service, keys] of Object.entries(sshPublicKeysByService)) {
			const article = document.createElement('article');

			const serviceHeader = document.createElement('h3');
			if (service !== "*") {
				const serviceLink = document.createElement('a');
				serviceLink.setAttribute("target", "_blank");
				serviceLink.href = `https://${service}.${handle}.fedproxy.com`;
				serviceLink.textContent  = service;
				serviceHeader.appendChild(serviceLink)
			} else {
				serviceHeader.textContent = "*";
			}

			const exampleSSHCommandTemplate = document.getElementById("example-ssh-command").textContent;
			const exampleSSHCommand = document.createElement('pre');
			exampleSSHCommand.textContent = exampleSSHCommandTemplate ;
			exampleSSHCommand.textContent = exampleSSHCommand.textContent.replace(
				/handle.example.com/g,
				handle,
			);
			if (service !== "*") {
				exampleSSHCommand.textContent = exampleSSHCommand.textContent.replace(
					/my-cool-service/g,
					service,
				);
			}

			const details = document.createElement('details');
			details.open = true;

			const summary = document.createElement('summary');
			summary.textContent = `Toggle show/hide`
			details.appendChild(summary);

			const ul = document.createElement('ul');
			ul.style.listStyleType = 'none';
			ul.style.paddingLeft = '0';

			keys.forEach(k => {
				const li = document.createElement('li');
				li.className = 'key-list-item';

				const nameStrong = document.createElement('strong');
				nameStrong.textContent = k.name;

				const dateSmall = document.createElement('small');
				if (k.createdAt) {
					dateSmall.textContent = ` (Created: ${new Date(k.createdAt).toLocaleDateString()})`;
					dateSmall.style.color = "var(--pico-muted-color)";
				}

				const br = document.createElement('br');

				const keyCode = document.createElement('code');
				keyCode.textContent = k.key;
				keyCode.style.fontSize = "0.85em";
				keyCode.style.display = "block";
				keyCode.style.marginTop = "0.5rem";
				keyCode.style.padding = "0.5rem";
				keyCode.style.backgroundColor = "var(--pico-code-background-color)";

				li.appendChild(nameStrong);
				li.appendChild(dateSmall);
				li.appendChild(br);
				li.appendChild(keyCode);
				ul.appendChild(li);
			});

			details.appendChild(ul);
			article.appendChild(serviceHeader);
			article.appendChild(exampleSSHCommand);
			article.appendChild(details);
			listContainer.appendChild(article);
		}

	} catch (err) {
		listContainer.removeAttribute("aria-busy");
		listContainer.innerHTML = `<p style="color: #E37474;">Error loading keys: ${err.message}</p>`;
	}
}

// If there was an existing OAuth session, we restore it.
// Otherwise, we present the login UI to the user.
async function init() {
	/* Set up form/button handlers */
	document.getElementById("login-form").onsubmit = function(e) {
		e.preventDefault();
		doLogin(e.target.username.value);
	}

	document.getElementById("bsky-button").onclick = function() {
		doLogin("https://bsky.social");
	}

	document.getElementById("ssh-public-key-form").onsubmit = function(e) {
		e.preventDefault();
		doPost(document.getElementById("ssh-public-key-name").value, document.getElementById("ssh-public-key-service").value, document.getElementById("ssh-public-key-key").value);
	}

	document.getElementById("logout-nav").onclick = function() {
		oac.revoke(agent.did);
		window.location.reload();
	}

	/* Set up the OAuth client */
	try {
		oac = await BrowserOAuthClient.load({
			clientId, // Note: This involves fetching the metadata document. See https://github.com/bluesky-social/atproto/tree/main/packages/oauth/oauth-client-browser#client-metadata for how to avoid this extra round-trip.
			handleResolver: 'https://bsky.social',
		});
		const result = await oac.init();

		if (result) {
			const { session, state } = result
			if (state != null) {
				console.log(`${session.sub} was successfully authenticated (state: ${state})`)
			} else {
				console.log(`${session.sub} was restored (last active session)`)
			}

			agent = new Agent(session);

			const res = await agent.com.atproto.server.getSession();
			if (!res.success) {
				console.log("getSession failed", res);
				throw new Error(JSON.stringify(res));
			}

			document.getElementById("welcome-message").innerText = `@${res.data.handle}`;
			document.getElementById("ssh-public-key-container").style.display = "inherit"; // unhide
			document.getElementById("ssh-public-keys-list-container").style.display = "inherit"; // unhide list section
			document.getElementById("logout-nav").style.display = "inherit"; // unhide

			// Fetch and render keys
			await fetchAndRenderKeys(res.data.handle);

		} else { // there is no existing session
			document.getElementById("login-container").style.display = "inherit"; // unhide
		}
	} catch (error) {
		const msg = `An error occured: ${error}`;
		document.getElementById("loading-error").innerText = msg;
		document.getElementById("loading-error").style.display = "inherit"; // unhide
		return;
	}

	document.getElementById("loading-spinner").style.display = "none";
	console.log("init done");
}

async function doLogin(identifier) {
	const loginButton = document.getElementById("login-button");
	loginButton.setAttribute("aria-busy", "true");
	try {
		await oac.signIn(identifier, {
			state: 'some value needed later',
			signal: new AbortController().signal, // Optional, allows to cancel the sign in (and destroy the pending authorization, for better security)
		})
		console.log('Never executed');
	} catch (err) {
		document.getElementById("login-form-error").innerText = `Login error: ${err}`;
	}
	loginButton.removeAttribute("aria-busy");
}

async function doPost(name, service, key) {
	const createSSHPublicKeyButton = document.getElementById("ssh-public-key-button");
	createSSHPublicKeyButton.setAttribute("aria-busy", "true");

	let res;
	try {
		res = await agent.com.atproto.repo.createRecord({
			repo: agent.did,
			collection: 'com.fedproxy.sshPublicKey',
			record: {
				$type: 'com.fedproxy.sshPublicKey',
				key: key.replace(/(\r\n|\n|\r)/g, ''),
				name: name.replace(/(\r\n|\n|\r)/g, ''),
				service: service.replace(/(\r\n|\n|\r)/g, ''),
				createdAt: new Date().toISOString(),
			},
		});

		if (!res.success) {
			throw new Error(JSON.stringify(res));
		}
	} catch (err) {
		document.getElementById("ssh-public-key-form-error").innerText = `${err}`;
		createSSHPublicKeyButton.removeAttribute("aria-busy");
		return;
	}

	const atUri = res.data.uri;

	// show the "success" screen
	createSSHPublicKeyButton.removeAttribute("aria-busy");
	document.getElementById("success-pdsls").href = `https://pdsls.dev/${atUri}`;
	document.getElementById("success-container").style.display = "inherit"; // unhide

	// Refetch the keys so the new one appears in the list directly below
	await fetchAndRenderKeys();

	// Reset the form so they can easily create another one
	document.getElementById("ssh-public-key-form").reset();
	document.getElementById("ssh-public-key-form-error").innerText = "";
}

document.addEventListener('DOMContentLoaded', init);
