/*
 * Copyright (c) 2010-2026 Belledonne Communications SARL.
 *
 * This file is part of Linphone
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

import Foundation
import linphonesw

/// Reports this device's APNs tokens to the NYPNK Fax backend.
///
/// The backend needs the tokens to push an incoming call while the app is
/// suspended. Apple validates a notification against the *push type* the token
/// was minted for and answers 400 InvalidPushType on a mismatch, so the two
/// tokens an iOS VoIP app owns are registered apart:
///
/// * the **notification** (remote) token, from
///   `didRegisterForRemoteNotificationsWithDeviceToken` and forwarded to the
///   core as `<hex>:remote` -> registered as `alert`;
/// * the **VoIP** token, from PushKit -> registered as `voip`.
///
/// The backend authenticates with a bearer token. A Linphone account only
/// carries SIP credentials, so those are exchanged at `POST /auth/sip-login`
/// and the minted token is reused; a failed exchange clears the cache so the
/// next report authenticates again.
///
/// Tokens seen before a core exists (the early PushKit delegate runs while the
/// app is still waiting for its config) are parked in UserDefaults and sent
/// once a core with credentials is available.
final class PushTokenReporter {

	static let shared = PushTokenReporter()

	enum PushType: String {
		case alert
		case voip
	}

	/// Fallback API host when neither MDM nor provisioning names one.
	private static let defaultAPIBaseURL = "https://saas.nypnk.com"
	private static let managedConfigKey = "com.apple.configuration.managed"
	private static let pendingKey = "PushTokenReporter.pendingTokens"
	private static let sentKey = "PushTokenReporter.sentTokens"
	private static let bearerKey = "PushTokenReporter.bearerToken"
	private static let voipTokenKey = "PushTokenReporter.voipToken"
	private static let remoteTokenKey = "PushTokenReporter.remoteToken"

	private let session = URLSession(configuration: .ephemeral)
	private let stateQueue = DispatchQueue(label: "com.nypnk.linphone.PushTokenReporter")

	private var pending: [String: String] = [:]
	private var sent = Set<String>()
	private var bearerToken = ""
	private var cachedVoipToken = ""
	private var cachedRemoteToken = ""
	private var provisioningPasswords: [String: String] = [:]
	private var restoredState = false

	private init() {}

	// MARK: - Reporting

	/// The last VoIP token this device received from PushKit, or nil if PushKit
	/// has not answered yet.
	///
	/// An account only advertises `pn-provider=apns` in its REGISTER Contact when
	/// its params carry a VoIP token, and the core's own config is empty until
	/// PushKit replies. Caching the token here lets an account be created (or
	/// refreshed) with the binding as soon as the token is known, whichever of the
	/// two delegates received it.
	static var voipToken: String? {
		let token = UserDefaults.standard.string(forKey: voipTokenKey) ?? ""
		return token.isEmpty ? nil : token
	}

	/// The last notification (remote) token this device received from APNs, or nil
	/// if APNs has not answered yet. Read by `AccountLoginViewModel` and
	/// `CoreContext` to fill `pn-provider`/`pn-prid` for the alert half of the
	/// binding, which the core otherwise only learns through
	/// `didRegisterForRemotePushWithStringifiedToken`.
	static var remoteToken: String? {
		let token = UserDefaults.standard.string(forKey: remoteTokenKey) ?? ""
		return token.isEmpty ? nil : token
	}

	/// Report the VoIP token from a `PKPushCredentials` object, sending it now
	/// when a core is available and parking it otherwise.
	func report(_ credentials: Data, type: PushType, core: Core? = nil) {
		report(token: Self.hexString(from: credentials), type: type, core: core)
	}

	/// Report a stringified APNs token, with or without the `:remote` suffix the
	/// SDK asks the app to append when forwarding it to the core.
	///
	/// `core` is passed in rather than read from `CoreContext.shared` so a
	/// caller can report before the shared core exists; without one the token is
	/// parked until `reportAll(core:)` runs.
	func report(token: String, type: PushType, core: Core? = nil) {
		guard let hex = Self.hexToken(from: token) else {
			Log.warn("[PushTokenReporter] Ignoring \(type.rawValue) token, not 64 hex chars: \(token)")
			return
		}
		guard let topic = Self.apnsTopic(for: type) else {
			Log.warn("[PushTokenReporter] No bundle identifier, \(type.rawValue) token dropped")
			return
		}
		if type == .voip {
			cacheVoipToken(hex)
		} else {
			cacheRemoteToken(hex)
		}

		guard let core, let server = apiBaseURL(for: core), let username = sipUsername(for: core) else {
			park(type, token: hex)
			return
		}

		let key = "\(type.rawValue):\(hex)"
		guard markSent(key) else { return }
		clearPending(type)
		Task { [weak self] in
			guard let self = self else { return }
			let uploaded = await self.upload(token: hex, type: type, apnsTopic: topic, server: server, username: username, core: core)
			if !uploaded {
				self.unmarkSent(key)
			}
		}
	}

	/// Report every token the core knows and flush anything parked earlier.
	/// Call once the core has started.
	func reportAll(core: Core) {
		if let remote = core.pushNotificationConfig?.remoteToken, !remote.isEmpty {
			report(token: remote, type: .alert, core: core)
		}
		if let voip = core.pushNotificationConfig?.voipToken, !voip.isEmpty {
			report(token: voip, type: .voip, core: core)
		}
		for (raw, hex) in parkedTokens() {
			if let type = PushType(rawValue: raw) {
				report(token: hex, type: type, core: core)
			}
		}
	}

	// MARK: - Networking

	private func upload(token: String, type: PushType, apnsTopic: String, server: String,
	                    username: String, core: Core) async -> Bool {
		guard let password = await sipPassword(for: core, server: server, username: username) else { return false }
		guard let bearer = await bearerToken(from: server, credentials: (username, password)) else { return false }

		#if DEBUG
		let environment = "development"
		#else
		let environment = "production"
		#endif

		var request = URLRequest(url: URL(string: "\(server)/api/v1/device/token") ?? URL(string: server)!)
		request.httpMethod = "POST"
		request.setValue("Bearer \(bearer)", forHTTPHeaderField: "Authorization")
		request.setValue("application/json", forHTTPHeaderField: "Content-Type")
		request.httpBody = try? JSONSerialization.data(withJSONObject: [
			"token": token,
			"platform": "ios",
			"environment": environment,
			"apns_push_type": type.rawValue,
			"apns_topic": apnsTopic
		])
		do {
			let (_, response) = try await session.data(for: request)
			let status = (response as? HTTPURLResponse)?.statusCode ?? 0
			guard (200...299).contains(status) else {
				Log.error("[PushTokenReporter] \(type.rawValue) token rejected with HTTP \(status)")
				return false
			}
			Log.info("[PushTokenReporter] \(type.rawValue) token registered with \(server)")
			return true
		} catch let error {
			Log.error("[PushTokenReporter] \(type.rawValue) token upload failed: \(error.localizedDescription)")
			return false
		}
	}

	/// Cached bearer token, minted by exchanging the account's SIP password.
	private func bearerToken(from server: String, credentials: (user: String, password: String)) async -> String? {
		let cached = stateQueue.sync { restoreStateIfNeeded(); return bearerToken }
		if !cached.isEmpty { return cached }

		var request = URLRequest(url: URL(string: "\(server)/api/v1/auth/sip-login")!)
		request.httpMethod = "POST"
		request.setValue("application/json", forHTTPHeaderField: "Content-Type")
		request.httpBody = try? JSONSerialization.data(withJSONObject: [
			"username": credentials.user,
			"password": credentials.password
		])
		do {
			let (data, response) = try await session.data(for: request)
			let status = (response as? HTTPURLResponse)?.statusCode ?? 0
			guard (200...299).contains(status),
			      let token = (try? JSONSerialization.jsonObject(with: data) as? [String: Any])?["token"] as? String else {
				Log.error("[PushTokenReporter] SIP login failed with HTTP \(status)")
				return nil
			}
			stateQueue.sync {
				bearerToken = token
				persist()
			}
			return token
		} catch let error {
			Log.error("[PushTokenReporter] SIP login failed: \(error.localizedDescription)")
			return nil
		}
	}

	// MARK: - Configuration

	/// The API host to report to: the MDM `apiBaseUrl`, else the origin of the
	/// MDM/core provisioning URL, else the product default.
	private func apiBaseURL(for core: Core?) -> String? {
		let managed = UserDefaults.standard.dictionary(forKey: Self.managedConfigKey)
		for candidate in [managed?["apiBaseUrl"] as? String, managed?["configUri"] as? String, core?.provisioningUri] {
			if let origin = Self.origin(from: candidate) { return origin }
		}
		return Self.origin(from: Self.defaultAPIBaseURL)
	}

	/// The SIP username the core holds, which is what the backend matches a
	/// device against.
	private func sipUsername(for core: Core) -> String? {
		if let username = core.accountList.compactMap({ $0.params?.identityAddress?.username }).first(where: { !$0.isEmpty }) {
			return username
		}
		return core.authInfoList.compactMap { $0.username }.first(where: { !$0.isEmpty })
	}

	/// The SIP password for a user, which `POST /auth/sip-login` exchanges for
	/// the bearer token the device upload needs.
	///
	/// On iOS liblinphone moves the secret into the keychain and leaves the
	/// in-memory `AuthInfo` empty, so neither `findAuthInfo()` nor
	/// `authInfoList` can answer the question even though the account registers
	/// correctly. The provisioning `.rc` the core was configured from carries the
	/// secret in cleartext, which `voipsaas/provisioning.py` documents as the
	/// intended source, so it is fetched and parsed when the core holds nothing.
	/// The result is cached per user so repeated reports fetch it once.
	private func sipPassword(for core: Core, server: String, username: String) async -> String? {
		let cached = stateQueue.sync { provisioningPasswords[username] }
		if let cached, !cached.isEmpty { return cached }
		var password = Self.inMemoryPassword(for: core, username: username)
		if password == nil, let url = Self.provisioningURL(from: core.provisioningUri, server: server, username: username) {
			password = await Self.fetchText(from: url, session: session).flatMap { Self.password(inRc: $0, username: username) }
		}
		guard let password, !password.isEmpty else { return nil }
		stateQueue.sync { provisioningPasswords[username] = password }
		return password
	}

	/// The first non-empty password the core still exposes in memory, for the
	/// platforms and configurations that keep it there.
	private static func inMemoryPassword(for core: Core, username: String) -> String? {
		if let account = core.accountList.first(where: { $0.params?.identityAddress?.username == username }),
		   let password = account.findAuthInfo()?.password, !password.isEmpty {
			return password
		}
		return core.authInfoList.first(where: { $0.username == username && !($0.password ?? "").isEmpty })?.password
	}

	/// The URL the `.rc` for a user is served from.
	///
	/// A provisioning URI is either the `.rc` itself (`https://host/provision/1000.rc`)
	/// or the custom `linphone-config://` scheme wrapping that same URL, in which
	/// case the remainder is the real one. When the core has no URI, the API host
	/// stands in for it, which is where the backend serves it too.
	private static func provisioningURL(from uri: String?, server: String, username: String) -> URL? {
		let trimmed = (uri ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
		let prefix = "linphone-config://"
		var candidates: [String] = []
		if trimmed.lowercased().hasPrefix(prefix) {
			candidates.append(String(trimmed.dropFirst(prefix.count)))
		} else if trimmed.isEmpty == false {
			candidates.append(trimmed)
		}
		candidates.append("\(server)/provision/\(username).rc")
		for candidate in candidates {
			guard let url = URL(string: candidate), let scheme = url.scheme?.lowercased(),
			      scheme == "http" || scheme == "https" else { continue }
			if url.pathExtension.lowercased() == "rc" || url.path.hasPrefix("/provision/") { return url }
		}
		return nil
	}

	/// The `password=` line belonging to a user in a Linphone `.rc`.
	///
	/// The file is an INI file with a global `[sip]` section and one
	/// `[auth_info_N]` section per account, so a plain search for `password=`
	/// would return the first account's secret on a multi-account config. The
	/// section naming the user is read instead, falling back to `[sip]`.
	private static func password(inRc contents: String, username: String) -> String? {
		var sections: [String: [String: String]] = [:]
		var current = ""
		for line in contents.components(separatedBy: .newlines) {
			let trimmed = line.trimmingCharacters(in: .whitespaces)
			if trimmed.hasPrefix("[") && trimmed.hasSuffix("]") {
				current = String(trimmed.dropFirst().dropLast())
				continue
			}
			let parts = trimmed.split(separator: "=", maxSplits: 1)
			guard parts.count == 2 else { continue }
			let key = parts[0].trimmingCharacters(in: .whitespaces).lowercased()
			let value = parts[1].trimmingCharacters(in: .whitespaces)
			if !value.isEmpty { sections[current, default: [:]][key] = value }
		}
		if let section = sections.values.first(where: { section in
			["username", "userid", "auth_user"].contains(where: { section[$0] == username })
		}), let password = section["password"] ?? section["passwd"] {
			return password
		}
		return sections["sip"]?["password"] ?? sections["sip"]?["passwd"]
	}

	/// GET a small text file, or nil on any failure.
	private static func fetchText(from url: URL, session: URLSession) async -> String? {
		do {
			let (data, response) = try await session.data(from: url)
			guard let status = (response as? HTTPURLResponse)?.statusCode, (200...299).contains(status) else { return nil }
			return String(data: data, encoding: .utf8)
		} catch {
			Log.warn("[PushTokenReporter] Provisioning fetch failed: \(error.localizedDescription)")
			return nil
		}
	}

	// MARK: - State

	private static func hexString(from data: Data) -> String {
		data.map { String(format: "%02.2hhx", $0) }.joined()
	}

	/// The `apns-topic` Apple expects for a token type: the bundle id, plus the
	/// `.voip` suffix a PushKit token requires. Apple rejects a VoIP push whose
	/// topic lacks the suffix, so it is part of what gets registered rather than
	/// something the backend has to reconstruct at send time.
	private static func apnsTopic(for type: PushType) -> String? {
		guard let bundleID = Bundle.main.bundleIdentifier else { return nil }
		return type == .voip ? "\(bundleID).voip" : bundleID
	}

	/// Strip the `:remote` suffix the SDK appends and validate the hex.
	private static func hexToken(from token: String) -> String? {
		let stripped = token.components(separatedBy: ":").first?.lowercased() ?? ""
		guard stripped.count == 64, stripped.allSatisfy(\.isHexDigit) else { return nil }
		return stripped
	}

	/// `https://host/path` -> `https://host`.
	///
	/// Only `http`/`https` URLs are accepted. A provisioning URL uses the
	/// `linphone-config://` custom scheme, which is not a usable HTTP origin;
	/// returning nil for it lets `apiBaseURL(for:)` fall through to the product
	/// default instead of building an unreachable `linphone-config://.../api/v1`
	/// request that URLSession rejects.
	private static func origin(from value: String?) -> String? {
		let trimmed = (value ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
		guard let url = URL(string: trimmed), let scheme = url.scheme?.lowercased(), let host = url.host else { return nil }
		guard scheme == "http" || scheme == "https" else { return nil }
		return url.port.map { "\(scheme)://\(host):\($0)" } ?? "\(scheme)://\(host)"
	}

	private func park(_ type: PushType, token: String) {
		stateQueue.sync {
			restoreStateIfNeeded()
			guard pending[type.rawValue] != token else { return }
			pending[type.rawValue] = token
			persist()
		}
		Log.info("[PushTokenReporter] \(type.rawValue) token parked, no usable core yet")
	}

	/// Drop the parked entry for a type once its token is in flight or sent.
	private func clearPending(_ type: PushType) {
		stateQueue.sync {
			restoreStateIfNeeded()
			guard pending.removeValue(forKey: type.rawValue) != nil else { return }
			persist()
		}
	}

	private func parkedTokens() -> [String: String] {
		stateQueue.sync {
			restoreStateIfNeeded()
			return pending
		}
	}

	/// True the first time a key is seen; later calls return false.
	private func markSent(_ key: String) -> Bool {
		stateQueue.sync {
			restoreStateIfNeeded()
			return sent.insert(key).inserted
		}
	}

	/// Allow a key to be reported again, e.g. after a failed upload.
	private func unmarkSent(_ key: String) {
		stateQueue.sync {
			restoreStateIfNeeded()
			guard sent.remove(key) != nil else { return }
			if let separator = key.firstIndex(of: ":") {
				pending[String(key[..<separator])] = String(key[key.index(after: separator)...])
			}
			persist()
		}
	}

	private func restoreStateIfNeeded() {
		guard !restoredState else { return }
		restoredState = true
		pending = UserDefaults.standard.dictionary(forKey: Self.pendingKey) as? [String: String] ?? [:]
		sent = Set(UserDefaults.standard.stringArray(forKey: Self.sentKey) ?? [])
		bearerToken = UserDefaults.standard.string(forKey: Self.bearerKey) ?? ""
		cachedVoipToken = UserDefaults.standard.string(forKey: Self.voipTokenKey) ?? ""
		cachedRemoteToken = UserDefaults.standard.string(forKey: Self.remoteTokenKey) ?? ""
	}

	private func persist() {
		UserDefaults.standard.set(Array(sent).sorted(), forKey: Self.sentKey)
		UserDefaults.standard.set(pending, forKey: Self.pendingKey)
		UserDefaults.standard.set(bearerToken, forKey: Self.bearerKey)
		UserDefaults.standard.set(cachedVoipToken, forKey: Self.voipTokenKey)
		UserDefaults.standard.set(cachedRemoteToken, forKey: Self.remoteTokenKey)
	}

	/// Persist the VoIP token outside the instance cache so the static
	/// `voipToken` reader and every other caller agree on one value.
	private func cacheVoipToken(_ hex: String) {
		stateQueue.sync {
			restoreStateIfNeeded()
			guard cachedVoipToken != hex else { return }
			cachedVoipToken = hex
			persist()
		}
	}

	private func cacheRemoteToken(_ hex: String) {
		stateQueue.sync {
			restoreStateIfNeeded()
			guard cachedRemoteToken != hex else { return }
			cachedRemoteToken = hex
			persist()
		}
	}
}
