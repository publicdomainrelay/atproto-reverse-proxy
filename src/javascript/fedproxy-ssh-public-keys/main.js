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
			document.getElementById("logout-nav").style.display = "inherit"; // unhide
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
	const [uriRepo, uriCollection, uriRkey] = atUri.split('/').slice(2);
	const pdsHost = (await agent.sessionManager.getTokenInfo()).aud;

	// hide the "ssh-public-key" screen
	createSSHPublicKeyButton.removeAttribute("aria-busy");
	document.getElementById("ssh-public-key-container").style.display = "none";

	// show the "success" screen
	document.getElementById("success-pdsls").href = `https://pdsls.dev/${atUri}`;
	document.getElementById("success-container").style.display = "inherit"; // unhide
}

document.addEventListener('DOMContentLoaded', init);
