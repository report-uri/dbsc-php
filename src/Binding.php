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
		], JSON_THROW_ON_ERROR);
	}


	/**
	 * Parse a stored binding. Throws on a present-but-unreadable value rather than returning
	 * null: callers MUST treat that as fail-closed and NOT collapse it to "no binding", which
	 * would degrade a bound session to plain cookie auth — the fail-open DBSC exists to prevent.
	 * Absence is represented by the store returning null without ever calling this method.
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
		return new self(
			$userId,
			$sessionIdentifier,
			$cookieValue,
			$publicKeyPem,
			$algorithm,
			$challenge,
			$challengeTime,
			$createdAt,
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
		);
	}


	public function withRotatedCookieAndChallenge(string $cookieValue, string $challenge, int $challengeTime): self
	{
		return new self(
			$this->userId,
			$this->sessionIdentifier,
			$cookieValue,
			$this->publicKeyPem,
			$this->algorithm,
			$challenge,
			$challengeTime,
			$this->createdAt,
		);
	}

}
