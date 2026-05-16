<?php
declare(strict_types = 1);

namespace ReportUri\Dbsc;

use ReportUri\Dbsc\Exception\CorruptStateException;

/**
 * The established device-bound session record. Its existence in the {@see StoreInterface},
 * keyed by the host application's session id, is the authoritative "this session is hard-DBSC"
 * mark. It must NOT be stored in a shared, last-writer-wins session blob: two concurrent
 * requests on the same session (the post-login navigation racing the registration POST) will
 * clobber it and silently disable enforcement. Key it by the stable session id in a dedicated
 * store instead — see README, "Storage".
 *
 * `cookieValue` rotates on every refresh; `sessionIdentifier` is stable and is what the browser
 * echoes back in Sec-Secure-Session-Id.
 *
 * `previousCookieValue` / `previousCookieExpiresAt` retain the single immediately-prior cookie
 * value until the instant that value would itself have expired in the browser. The bound cookie
 * rotates on every refresh, but the refresh round-trip is a propagation window: a request that
 * left the browser just before it stored the rotated Set-Cookie still carries the prior value.
 * Accepting it for the remainder of its own natural lifetime (see {@see DbscServer::boundCookieMatches()})
 * stops the enforcement gate from terminating legitimate sessions over that benign window,
 * without weakening DBSC — only the single most-recent value, only until its own expiry, and an
 * attacker still cannot complete a refresh without the device-bound key.
 */
final class Binding
{

	public function __construct(
		public readonly string $userId,
		public readonly string $sessionIdentifier,
		public readonly string $cookieValue,
		public readonly string $publicKeyPem,
		public readonly string $algorithm,
		public readonly string $challenge,
		public readonly int $challengeTime,
		public readonly int $createdAt,
		public readonly int $cookieIssuedAt = 0,
		public readonly string $previousCookieValue = '',
		public readonly int $previousCookieExpiresAt = 0,
	) {
	}


	public function toJson(): string
	{
		return json_encode([
			'userId' => $this->userId,
			'sessionIdentifier' => $this->sessionIdentifier,
			'cookieValue' => $this->cookieValue,
			'publicKeyPem' => $this->publicKeyPem,
			'algorithm' => $this->algorithm,
			'challenge' => $this->challenge,
			'challengeTime' => $this->challengeTime,
			'createdAt' => $this->createdAt,
			'cookieIssuedAt' => $this->cookieIssuedAt,
			'previousCookieValue' => $this->previousCookieValue,
			'previousCookieExpiresAt' => $this->previousCookieExpiresAt,
		], JSON_THROW_ON_ERROR);
	}


	/**
	 * Parse a stored binding. Throws on a present-but-unreadable value rather than returning
	 * null: callers MUST treat that as fail-closed and NOT collapse it to "no binding", which
	 * would degrade a bound session to plain cookie auth — the fail-open DBSC exists to prevent.
	 * Absence is represented by the store returning null without ever calling this method.
	 *
	 * The cookie-rotation-overlap fields (cookieIssuedAt / previousCookieValue /
	 * previousCookieExpiresAt) are OPTIONAL with safe defaults: records written by an older
	 * library version predate them, and a record without them is fully valid — it simply has no
	 * previous-value overlap (strict current-value match only) until its next refresh re-issues
	 * it under the current code. That is a graceful, fail-closed default, never a lockout and
	 * never a fail-open. Every field that was required stays strictly type-checked.
	 *
	 * @throws CorruptStateException
	 */
	public static function fromJson(string $json): self
	{
		$data = json_decode($json, true);
		if (!is_array($data)) {
			throw new CorruptStateException('Binding record is not a JSON object');
		}
		$userId = $data['userId'] ?? null;
		$sessionIdentifier = $data['sessionIdentifier'] ?? null;
		$cookieValue = $data['cookieValue'] ?? null;
		$publicKeyPem = $data['publicKeyPem'] ?? null;
		$algorithm = $data['algorithm'] ?? null;
		$challenge = $data['challenge'] ?? null;
		$challengeTime = $data['challengeTime'] ?? null;
		$createdAt = $data['createdAt'] ?? null;
		if (
			!is_string($userId) ||
			!is_string($sessionIdentifier) ||
			!is_string($cookieValue) ||
			!is_string($publicKeyPem) ||
			!is_string($algorithm) ||
			!is_string($challenge) ||
			!is_int($challengeTime) ||
			!is_int($createdAt)
		) {
			throw new CorruptStateException('Binding record has missing or wrong-typed fields');
		}
		$cookieIssuedAt = $data['cookieIssuedAt'] ?? null;
		$previousCookieValue = $data['previousCookieValue'] ?? null;
		$previousCookieExpiresAt = $data['previousCookieExpiresAt'] ?? null;
		return new self(
			$userId,
			$sessionIdentifier,
			$cookieValue,
			$publicKeyPem,
			$algorithm,
			$challenge,
			$challengeTime,
			$createdAt,
			is_int($cookieIssuedAt) ? $cookieIssuedAt : $createdAt,
			is_string($previousCookieValue) ? $previousCookieValue : '',
			is_int($previousCookieExpiresAt) ? $previousCookieExpiresAt : 0,
		);
	}


	public function withChallenge(string $challenge, int $challengeTime): self
	{
		return new self(
			$this->userId,
			$this->sessionIdentifier,
			$this->cookieValue,
			$this->publicKeyPem,
			$this->algorithm,
			$challenge,
			$challengeTime,
			$this->createdAt,
			$this->cookieIssuedAt,
			$this->previousCookieValue,
			$this->previousCookieExpiresAt,
		);
	}


	/**
	 * Rotate the bound cookie (and challenge). The value being demoted is retained as
	 * `previousCookieValue`, accepted only until `previousCookieExpiresAt` — the instant the
	 * demoted cookie would itself have expired in the browser, i.e. its own issuance time
	 * (`$this->cookieIssuedAt`) plus the configured max-age. Single-depth: a second rotation
	 * discards the value from two rotations ago.
	 */
	public function withRotatedCookieAndChallenge(
		string $cookieValue,
		string $challenge,
		int $challengeTime,
		int $now,
		int $cookieMaxAgeSeconds,
	): self {
		return new self(
			$this->userId,
			$this->sessionIdentifier,
			$cookieValue,
			$this->publicKeyPem,
			$this->algorithm,
			$challenge,
			$challengeTime,
			$this->createdAt,
			$now,
			$this->cookieValue,
			$this->cookieIssuedAt + $cookieMaxAgeSeconds,
		);
	}

}
