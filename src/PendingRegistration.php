<?php
declare(strict_types = 1);

namespace ReportUri\Dbsc;

/**
 * The short-lived registration challenge, written when the Secure-Session-Registration header is
 * emitted at login — before the browser has proven DBSC support. Kept in its own store key
 * (separate from {@see Binding}) so that "a binding exists" is true only after a successful
 * registration, never merely because DBSC was offered. Never consulted by the enforcement gate.
 */
final class PendingRegistration
{

	public function __construct(
		public readonly string $userId,
		public readonly string $regChallenge,
		public readonly int $regChallengeTime,
	) {
	}


	public function toJson(): string
	{
		return json_encode([
			'userId' => $this->userId,
			'regChallenge' => $this->regChallenge,
			'regChallengeTime' => $this->regChallengeTime,
		], JSON_THROW_ON_ERROR);
	}


	/**
	 * Returns null if the stored value is malformed — callers treat that as "no pending
	 * registration" so a corrupt record fails closed rather than registering on garbage.
	 */
	public static function fromJson(string $json): ?self
	{
		$data = json_decode($json, true);
		if (!is_array($data)) {
			return null;
		}
		$userId = $data['userId'] ?? null;
		$regChallenge = $data['regChallenge'] ?? null;
		$regChallengeTime = $data['regChallengeTime'] ?? null;
		if (!is_string($userId) || !is_string($regChallenge) || !is_int($regChallengeTime)) {
			return null;
		}
		return new self($userId, $regChallenge, $regChallengeTime);
	}

}
