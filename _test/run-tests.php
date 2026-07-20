<?php
declare(strict_types = 1);

/*
 * Self-contained test harness — no PHPUnit, no framework. Generates a real EC P-256 device key,
 * builds DBSC registration/refresh JWTs exactly as Chrome does (ES256, raw r||s signature, JWK
 * in the registration header), and drives DbscServer end-to-end through the InMemoryStore.
 *
 * Run: php _test/run-tests.php
 */

require __DIR__ . '/../src/Exception/DbscException.php';
require __DIR__ . '/../src/Exception/RetryableRefreshException.php';
require __DIR__ . '/../src/Exception/JwtInvalidException.php';
require __DIR__ . '/../src/Exception/ChallengeExpiredException.php';
require __DIR__ . '/../src/Exception/ChallengeMismatchException.php';
require __DIR__ . '/../src/Exception/MissingChallengeException.php';
require __DIR__ . '/../src/Exception/SessionNotFoundException.php';
require __DIR__ . '/../src/Exception/CorruptStateException.php';
require __DIR__ . '/../src/RegistrationResult.php';
require __DIR__ . '/../src/PendingRegistration.php';
require __DIR__ . '/../src/Binding.php';
require __DIR__ . '/../src/StoreInterface.php';
require __DIR__ . '/../src/InMemoryStore.php';
require __DIR__ . '/../src/JwtVerifier.php';
require __DIR__ . '/../src/Config.php';
require __DIR__ . '/../src/RequestContext.php';
require __DIR__ . '/../src/Cookie.php';
require __DIR__ . '/../src/DbscResponse.php';
require __DIR__ . '/../src/AuditLoggerInterface.php';
require __DIR__ . '/../src/NullAuditLogger.php';
require __DIR__ . '/../src/DbscServer.php';

use ReportUri\Dbsc\AuditLoggerInterface;
use ReportUri\Dbsc\Binding;
use ReportUri\Dbsc\Config;
use ReportUri\Dbsc\DbscServer;
use ReportUri\Dbsc\Exception\ChallengeExpiredException;
use ReportUri\Dbsc\Exception\ChallengeMismatchException;
use ReportUri\Dbsc\Exception\CorruptStateException;
use ReportUri\Dbsc\Exception\JwtInvalidException;
use ReportUri\Dbsc\Exception\RetryableRefreshException;
use ReportUri\Dbsc\Exception\SessionNotFoundException;
use ReportUri\Dbsc\InMemoryStore;
use ReportUri\Dbsc\JwtVerifier;
use ReportUri\Dbsc\PendingRegistration;
use ReportUri\Dbsc\RequestContext;
use ReportUri\Dbsc\StoreInterface;

$tests = 0;
$failed = 0;

function check(string $name, bool $ok): void
{
	global $tests, $failed;
	$tests++;
	if ($ok) {
		echo "  PASS  $name\n";
	} else {
		$failed++;
		echo "  FAIL  $name\n";
	}
}

/** A simulated DBSC device: holds an EC P-256 key, signs JWTs the way Chrome does. */
final class FakeDevice
{

	private \OpenSSLAsymmetricKey $key;

	/** @var array{x: string, y: string} */
	public array $jwk;


	public function __construct()
	{
		$this->key = openssl_pkey_new([
			'private_key_type' => OPENSSL_KEYTYPE_EC,
			'curve_name' => 'prime256v1',
		]);
		$d = openssl_pkey_get_details($this->key);
		// openssl_pkey_get_details() returns the coordinate as a raw bignum with leading zero
		// bytes stripped, so ~1/256 keys yield a <32-byte x or y. RFC 7518 requires EC JWK
		// coordinates be the full fixed curve size (left-padded); a spec-compliant client (and
		// real Chrome) pads them, and the verifier correctly rejects unpadded ones. Pad here so
		// the fake device behaves like a compliant client and the suite is deterministic.
		$this->jwk = [
			'x' => self::b64u(self::fixed32($d['ec']['x'])),
			'y' => self::b64u(self::fixed32($d['ec']['y'])),
		];
	}


	public function registrationJwt(string $challenge): string
	{
		$header = ['alg' => 'ES256', 'typ' => 'dbsc+jwt', 'jwk' => [
			'kty' => 'EC', 'crv' => 'P-256', 'x' => $this->jwk['x'], 'y' => $this->jwk['y'],
		]];
		return $this->sign($header, ['jti' => $challenge, 'iat' => time()]);
	}


	public function refreshJwt(string $challenge): string
	{
		return $this->sign(['alg' => 'ES256', 'typ' => 'dbsc+jwt'], ['jti' => $challenge, 'iat' => time()]);
	}


	private function sign(array $header, array $payload): string
	{
		$signingInput = self::b64u(json_encode($header)) . '.' . self::b64u(json_encode($payload));
		openssl_sign($signingInput, $der, $this->key, OPENSSL_ALGO_SHA256);
		return $signingInput . '.' . self::b64u(self::derToRaw($der));
	}


	private static function derToRaw(string $der): string
	{
		// SEQUENCE { INTEGER r, INTEGER s } -> fixed 32-byte r || 32-byte s.
		$o = 4;
		$rLen = ord($der[3]);
		$r = ltrim(substr($der, $o, $rLen), "\x00");
		$o += $rLen + 1;
		$sLen = ord($der[$o]);
		$s = ltrim(substr($der, $o + 1, $sLen), "\x00");
		return str_pad($r, 32, "\x00", STR_PAD_LEFT) . str_pad($s, 32, "\x00", STR_PAD_LEFT);
	}


	/** Left-pad (or trim) a P-256 coordinate to the fixed 32-byte width an RFC 7518 JWK requires. */
	private static function fixed32(string $coord): string
	{
		return strlen($coord) >= 32
			? substr($coord, -32)
			: str_pad($coord, 32, "\x00", STR_PAD_LEFT);
	}


	public static function b64u(string $in): string
	{
		return rtrim(strtr(base64_encode($in), '+/', '-_'), '=');
	}

}

function ctx(string $sid, array $headers = [], array $cookies = []): RequestContext
{
	return new RequestContext($sid, 'user-1', 'https://example.test', $headers, $cookies);
}

echo "JwtVerifier\n";
$device = new FakeDevice();
$verifier = new JwtVerifier();

$parsed = $verifier->parse($device->registrationJwt('chal-abc'));
$result = $verifier->verifyRegistrationJwt($parsed);
check('registration JWT verifies, jti extracted', $result->challenge === 'chal-abc' && str_contains($result->publicKeyPem, 'PUBLIC KEY'));

$refParsed = $verifier->parse($device->refreshJwt('chal-xyz'));
check('refresh JWT verifies against stored PEM', $verifier->verifyRefreshJwt($refParsed, $result->publicKeyPem) === 'chal-xyz');

$otherPem = $verifier->verifyRegistrationJwt($verifier->parse((new FakeDevice())->registrationJwt('y')))->publicKeyPem;
try {
	$verifier->verifyRefreshJwt($refParsed, $otherPem);
	check('refresh JWT rejected against a different key', false);
} catch (JwtInvalidException) {
	check('refresh JWT rejected against a different key', true);
}

try {
	$verifier->parse('not.a.jwt.really');
	check('malformed JWT rejected', false);
} catch (JwtInvalidException) {
	check('malformed JWT rejected', true);
}

$algNone = FakeDevice::b64u(json_encode(['alg' => 'none'])) . '.' . FakeDevice::b64u(json_encode(['jti' => 'x'])) . '.' . FakeDevice::b64u('sig');
try {
	$verifier->verifyRegistrationJwt($verifier->parse($algNone));
	check('alg=none rejected (algorithm confusion)', false);
} catch (JwtInvalidException) {
	check('alg=none rejected (algorithm confusion)', true);
}

echo "\nDbscServer — full flow\n";
$store = new InMemoryStore();
$server = new DbscServer(new Config(cookieName: '__Host-dbsc'), $store);
$device = new FakeDevice();
$sid = 'session-AAA';

$reg = $server->buildRegistrationHeaderResponse(ctx($sid));
preg_match('/challenge="([^"]+)"/', $reg->headers['Secure-Session-Registration'], $m);
check('login emits Secure-Session-Registration with a challenge', isset($m[1]) && $m[1] !== '');
check('no binding yet (gate would degrade to cookie auth)', $server->getBinding(ctx($sid)) === null);

$regResp = $server->register($device->registrationJwt($m[1]), ctx($sid));
$binding = $server->getBinding(ctx($sid));
check('register creates a binding', $binding instanceof Binding);
check('register 200 + bound cookie + Sec-Secure-Session-Id', $regResp->status === 200 && count($regResp->cookies) === 1 && isset($regResp->headers['Sec-Secure-Session-Id']));
check('register response has NO Secure-Session-Challenge (Chrome rejects it there)', !isset($regResp->headers['Secure-Session-Challenge']));
$cookie1 = $regResp->cookies[0]->value;

$chalResp = $server->issueRefreshChallenge(ctx($sid));
preg_match('/^"([^"]+)"; id="([^"]+)"$/', $chalResp->headers['Secure-Session-Challenge'], $cm);
check('refresh-challenge is 403 with id-parameterised challenge', $chalResp->status === 403 && isset($cm[1], $cm[2]));

$refResp = $server->refresh($device->refreshJwt($cm[1]), ctx($sid, ['Sec-Secure-Session-Id' => $cm[2]]));
$cookie2 = $refResp->cookies[0]->value;
check('refresh 200 rotates the bound cookie value', $refResp->status === 200 && $cookie2 !== $cookie1 && $cookie2 !== '');
check('refresh rotates the challenge too', $refResp->headers['Secure-Session-Challenge'] !== $chalResp->headers['Secure-Session-Challenge']);

echo "\nDbscServer — enforcement & attack cases\n";
$bindingNow = $server->getBinding(ctx($sid));
check('correct rotated cookie matches', $server->boundCookieMatches($bindingNow, ctx($sid, [], ['__Host-dbsc' => $cookie2])));
check('immediately-previous cookie still matches within its lifetime', $server->boundCookieMatches($bindingNow, ctx($sid, [], ['__Host-dbsc' => $cookie1])));
check('missing cookie does not match', !$server->boundCookieMatches($bindingNow, ctx($sid, [], [])));
check('an unrelated value never matches', !$server->boundCookieMatches($bindingNow, ctx($sid, [], ['__Host-dbsc' => 'never-issued'])));

// Cookie-rotation overlap: the immediately-previous value is accepted only until the instant
// it would itself have expired in the browser, and only one level deep.
$prevLive = new Binding('u', 'sid', $cookie2, 'pem', 'ES256', 'chal', time(), time(), time(), $cookie1, time() + 60);
$prevDead = new Binding('u', 'sid', $cookie2, 'pem', 'ES256', 'chal', time(), time(), time(), $cookie1, time() - 1);
check('previous value accepted before previousCookieExpiresAt', $server->boundCookieMatches($prevLive, ctx($sid, [], ['__Host-dbsc' => $cookie1])));
check('previous value rejected once previousCookieExpiresAt has passed', !$server->boundCookieMatches($prevDead, ctx($sid, [], ['__Host-dbsc' => $cookie1])));
check('current value still matches even after previous expired', $server->boundCookieMatches($prevDead, ctx($sid, [], ['__Host-dbsc' => $cookie2])));

$chal2 = $server->issueRefreshChallenge(ctx($sid));
preg_match('/^"([^"]+)"; id="([^"]+)"$/', $chal2->headers['Secure-Session-Challenge'], $cm2);
$ref2 = $server->refresh($device->refreshJwt($cm2[1]), ctx($sid, ['Sec-Secure-Session-Id' => $cm2[2]]));
$cookie3 = $ref2->cookies[0]->value;
$bindingNow2 = $server->getBinding(ctx($sid));
check('after a second refresh the now-previous (2nd) cookie matches', $server->boundCookieMatches($bindingNow2, ctx($sid, [], ['__Host-dbsc' => $cookie2])));
check('single-depth: the cookie from two rotations ago no longer matches', !$server->boundCookieMatches($bindingNow2, ctx($sid, [], ['__Host-dbsc' => $cookie1])));
check('newest rotated cookie matches', $server->boundCookieMatches($bindingNow2, ctx($sid, [], ['__Host-dbsc' => $cookie3])));

$store2 = new InMemoryStore();
$server2 = new DbscServer(new Config(cookieName: '__Host-dbsc'), $store2);
$dev2 = new FakeDevice();
$attacker = new FakeDevice();
$reg2 = $server2->buildRegistrationHeaderResponse(ctx('session-BBB'));
preg_match('/challenge="([^"]+)"/', $reg2->headers['Secure-Session-Registration'], $m2);
$server2->register($dev2->registrationJwt($m2[1]), ctx('session-BBB'));
$c2 = $server2->issueRefreshChallenge(ctx('session-BBB'));
preg_match('/^"([^"]+)"/', $c2->headers['Secure-Session-Challenge'], $cm2);
try {
	$server2->refresh($attacker->refreshJwt($cm2[1]), ctx('session-BBB'));
	check('refresh signed by a DIFFERENT device key is rejected', false);
} catch (JwtInvalidException) {
	check('refresh signed by a DIFFERENT device key is rejected', true);
}

try {
	$server2->refresh($dev2->refreshJwt('wrong-challenge'), ctx('session-BBB'));
	check('refresh with a wrong challenge is rejected as benign (not terminal)', false);
} catch (ChallengeMismatchException) {
	check('refresh with a wrong challenge is rejected as benign (not terminal)', true);
}
check('binding survives a benign wrong-challenge refresh (not revoked)', $server2->getBinding(ctx('session-BBB')) instanceof Binding);

try {
	$server2->refresh($dev2->refreshJwt('x'), ctx('session-UNKNOWN'));
	check('refresh on an unbound session throws SessionNotFound', false);
} catch (SessionNotFoundException) {
	check('refresh on an unbound session throws SessionNotFound', true);
}

// Long store TTL so the record survives; the server's own challenge-TTL timestamp check is
// what must reject it. Config requires challengeTtl > cookieMaxAge, so cookieMaxAge = 0.
$store3 = new InMemoryStore(challengeTtlSeconds: 1000, sessionLifetimeSeconds: 1000);
$server3 = new DbscServer(new Config(cookieName: '__Host-dbsc', cookieMaxAgeSeconds: 0, challengeTtlSeconds: 1), $store3);
$dev3 = new FakeDevice();
$reg3 = $server3->buildRegistrationHeaderResponse(ctx('session-CCC'));
preg_match('/challenge="([^"]+)"/', $reg3->headers['Secure-Session-Registration'], $m3);
sleep(2);
try {
	$server3->register($dev3->registrationJwt($m3[1]), ctx('session-CCC'));
	check('expired registration challenge rejected', false);
} catch (ChallengeExpiredException) {
	check('expired registration challenge rejected', true);
}

$store4 = new InMemoryStore();
$server4 = new DbscServer(new Config(cookieName: '__Host-dbsc'), $store4);
$dev4 = new FakeDevice();
$reg4 = $server4->buildRegistrationHeaderResponse(ctx('session-DDD'));
preg_match('/challenge="([^"]+)"/', $reg4->headers['Secure-Session-Registration'], $m4);
$server4->register($dev4->registrationJwt($m4[1]), ctx('session-DDD'));
check('binding present before revoke', $server4->getBinding(ctx('session-DDD')) instanceof Binding);
$rev = $server4->revoke(ctx('session-DDD'), true);
check('revoke deletes binding and emits cookie deletion', $server4->getBinding(ctx('session-DDD')) === null && $rev->cookies[0]->delete === true);

// --- Corrupt state fails closed -----------------------------------------------------------
// A stored record that is present but unparseable MUST throw CorruptStateException, never
// decode to null — null is reserved for "no record" (degrade to cookie auth). Returning null
// for a corrupt binding would silently downgrade a hard-DBSC session and re-open the
// stolen-cookie hole DBSC exists to close. Not client-triggerable; the write path always emits
// valid JSON. This guards against a serializer/version/truncation event.

$validBinding = new Binding('u', 'sid', 'cookie', 'pem', 'ES256', 'chal', 100, 100, 90, 'prevcookie', 390);
$roundTripped = Binding::fromJson($validBinding->toJson());
check(
	'Binding round-trips through toJson/fromJson (including the rotation-overlap fields)',
	$roundTripped->cookieValue === 'cookie'
	&& $roundTripped->createdAt === 100
	&& $roundTripped->cookieIssuedAt === 90
	&& $roundTripped->previousCookieValue === 'prevcookie'
	&& $roundTripped->previousCookieExpiresAt === 390,
);

$oneStepBinding = new Binding('u', 'sid', 'cookie', 'pem', 'ES256', 'chal', 100, 100, 90, 'pc', 390, true, 'prevchal', 77, true);
$oneStepRt = Binding::fromJson($oneStepBinding->toJson());
check(
	'Binding round-trips the one-step fields (hasRefreshed / challenge-overlap / challengeAdvertised)',
	$oneStepRt->hasRefreshed === true
	&& $oneStepRt->previousChallenge === 'prevchal'
	&& $oneStepRt->previousChallengeTime === 77
	&& $oneStepRt->challengeAdvertised === true,
);

// A record written by an older library version predates the rotation-overlap fields. It must
// decode WITHOUT throwing (it is fully valid) and default to "no previous-value overlap":
// strict current-value match only, cookieIssuedAt falling back to createdAt. Graceful and
// fail-closed — never a lockout, never a fail-open.
$legacyJson = '{"userId":"u","sessionIdentifier":"s","cookieValue":"c","publicKeyPem":"p","algorithm":"a","challenge":"x","challengeTime":1,"createdAt":7}';
$legacy = Binding::fromJson($legacyJson);
check(
	'legacy (pre-overlap) binding JSON decodes with safe defaults',
	$legacy->previousCookieValue === '' && $legacy->previousCookieExpiresAt === 0 && $legacy->cookieIssuedAt === 7,
);
check(
	'legacy binding JSON defaults the one-step fields safely',
	$legacy->hasRefreshed === false
	&& $legacy->previousChallenge === ''
	&& $legacy->previousChallengeTime === 0
	&& $legacy->challengeAdvertised === false,
);

foreach (['not-json', '"a string"', '12', '[]', '{"userId":"u"}', '{"userId":1,"sessionIdentifier":"s","cookieValue":"c","publicKeyPem":"p","algorithm":"a","challenge":"x","challengeTime":1,"createdAt":1}'] as $i => $bad) {
	try {
		Binding::fromJson($bad);
		check("Binding::fromJson rejects corrupt input #$i", false);
	} catch (CorruptStateException) {
		check("Binding::fromJson rejects corrupt input #$i", true);
	}
}

$validPending = new PendingRegistration('u', 'chal', 100);
check('PendingRegistration round-trips', PendingRegistration::fromJson($validPending->toJson())->regChallenge === 'chal');
try {
	PendingRegistration::fromJson('{"userId":"u","regChallenge":"c"}'); // regChallengeTime missing
	check('PendingRegistration::fromJson rejects corrupt input', false);
} catch (CorruptStateException) {
	check('PendingRegistration::fromJson rejects corrupt input', true);
}

/** Store whose binding key is present but unreadable, exercising the fail-closed contract. */
$corruptStore = new class implements StoreInterface {
	public function putPendingRegistration(string $sessionId, PendingRegistration $pending): void {}
	public function getPendingRegistration(string $sessionId): ?PendingRegistration { return null; }
	public function deletePendingRegistration(string $sessionId): void {}
	public function putBinding(string $sessionId, Binding $binding): void {}
	public bool $deleted = false;
	public function getBinding(string $sessionId): ?Binding { return Binding::fromJson('garbage'); }
	public function delete(string $sessionId): void { $this->deleted = true; }
};

$recorder = new class implements AuditLoggerInterface {
	/** @var list<string> */
	public array $events = [];
	public function log(string $event, string $message, ?string $userId): void { $this->events[] = $event; }
};

$server5 = new DbscServer(new Config(cookieName: '__Host-dbsc'), $corruptStore, audit: $recorder);

try {
	$server5->getBinding(ctx('session-EEE'));
	check('gate read of a corrupt binding throws (fails closed, not degrade)', false);
} catch (CorruptStateException) {
	check('gate read of a corrupt binding throws (fails closed, not degrade)', true);
}

$rev5 = $server5->revoke(ctx('session-EEE'), true);
check(
	'revoke tears down + audits despite a corrupt binding',
	$corruptStore->deleted === true
		&& $rev5->cookies[0]->delete === true
		&& $recorder->events === [DbscServer::EVENT_ENFORCEMENT_TERMINATED],
);

echo "\nDbscServer — one-step first-refresh (advertise + challenge-rotation overlap)\n";

// Proactive advertise: hand the browser the seed challenge on an ordinary authenticated
// response so its first /dbsc/refresh is single-step, delivered exactly once.
$storeA = new InMemoryStore();
$serverA = new DbscServer(new Config(cookieName: '__Host-dbsc'), $storeA);
$devA = new FakeDevice();
$sidA = 'session-ADV';
$regA = $serverA->buildRegistrationHeaderResponse(ctx($sidA));
preg_match('/challenge="([^"]+)"/', $regA->headers['Secure-Session-Registration'], $ma);
$serverA->register($devA->registrationJwt($ma[1]), ctx($sidA));
$bindA = $serverA->getBinding(ctx($sidA));
$seedA = $bindA->challenge;

$adv1 = $serverA->advertiseRefreshChallenge($bindA, ctx($sidA));
check(
	'advertise emits the seed challenge with the mandatory id sf-param',
	($adv1->headers['Secure-Session-Challenge'] ?? '') === sprintf('"%s"; id="%s"', $seedA, $bindA->sessionIdentifier),
);
$bindA2 = $serverA->getBinding(ctx($sidA));
check('advertise does not rotate the challenge', $bindA2->challenge === $seedA && $bindA2->challengeTime === $bindA->challengeTime);
check('advertise records the one-way delivered mark', $bindA2->challengeAdvertised === true && $bindA2->hasRefreshed === false);

$adv2 = $serverA->advertiseRefreshChallenge($bindA2, ctx($sidA));
check('advertise is once-only — a second call no-ops', $adv2->headers === [] && $adv2->cookies === []);

$emptyChal = new Binding('u', 'sid', 'c', 'pem', 'ES256', '', time(), time());
check('advertise no-ops on an empty challenge', $serverA->advertiseRefreshChallenge($emptyChal, ctx('s'))->headers === []);
$expiredChal = new Binding('u', 'sid', 'c', 'pem', 'ES256', 'seed', time() - 100000, time());
check('advertise no-ops on an expired challenge', $serverA->advertiseRefreshChallenge($expiredChal, ctx('s'))->headers === []);
$refreshedB = new Binding('u', 'sid', 'c', 'pem', 'ES256', 'seed', time(), time(), time(), '', 0, true);
check('advertise no-ops once the session has refreshed', $serverA->advertiseRefreshChallenge($refreshedB, ctx('s'))->headers === []);

// Challenge-rotation race: advertise handed the browser the seed while a concurrent reactive
// 403 rotated it. The pre-rotation (advertised) value must still refresh — without the overlap
// this is a JwtInvalidException, the TERMINAL revoke-and-logout path, not a benign 403 retry.
$storeR = new InMemoryStore();
$serverR = new DbscServer(new Config(cookieName: '__Host-dbsc'), $storeR);
$devR = new FakeDevice();
$sidR = 'session-RACE';
$regR = $serverR->buildRegistrationHeaderResponse(ctx($sidR));
preg_match('/challenge="([^"]+)"/', $regR->headers['Secure-Session-Registration'], $mr);
$serverR->register($devR->registrationJwt($mr[1]), ctx($sidR));
$seedR = $serverR->getBinding(ctx($sidR))->challenge;
$serverR->issueRefreshChallenge(ctx($sidR));
check('reactive 403 retains the pre-rotation challenge as previous', $serverR->getBinding(ctx($sidR))->previousChallenge === $seedR);
$prevAccepted = false;
try {
	$serverR->refresh($devR->refreshJwt($seedR), ctx($sidR));
	$prevAccepted = true;
} catch (ChallengeMismatchException) {
}
check('refresh accepts the advertised-then-rotated (previous) challenge', $prevAccepted);

// Single-depth: only the immediately-previous challenge, two rotations ago is gone.
$storeS = new InMemoryStore();
$serverS = new DbscServer(new Config(cookieName: '__Host-dbsc'), $storeS);
$devS = new FakeDevice();
$sidS = 'session-DEPTH';
$regS = $serverS->buildRegistrationHeaderResponse(ctx($sidS));
preg_match('/challenge="([^"]+)"/', $regS->headers['Secure-Session-Registration'], $ms);
$serverS->register($devS->registrationJwt($ms[1]), ctx($sidS));
$seedS = $serverS->getBinding(ctx($sidS))->challenge;
$serverS->issueRefreshChallenge(ctx($sidS));
$serverS->issueRefreshChallenge(ctx($sidS));
$r1S = $serverS->getBinding(ctx($sidS))->previousChallenge;
$twoAgoRejected = false;
try {
	$serverS->refresh($devS->refreshJwt($seedS), ctx($sidS));
} catch (ChallengeMismatchException) {
	$twoAgoRejected = true;
}
check('single-depth: the challenge from two rotations ago is rejected', $twoAgoRejected);
$singlePrevOk = false;
try {
	$serverS->refresh($devS->refreshJwt($r1S), ctx($sidS));
	$singlePrevOk = true;
} catch (ChallengeMismatchException) {
}
check('single-depth: the single immediately-previous challenge is accepted', $singlePrevOk);

// The overlap is bounded by the previous challenge's OWN TTL.
$storeT = new InMemoryStore();
$serverT = new DbscServer(new Config(cookieName: '__Host-dbsc'), $storeT);
$devT = new FakeDevice();
$sidT = 'session-TTL';
$regT = $serverT->buildRegistrationHeaderResponse(ctx($sidT));
preg_match('/challenge="([^"]+)"/', $regT->headers['Secure-Session-Registration'], $mt);
$serverT->register($devT->registrationJwt($mt[1]), ctx($sidT));
$seedT = $serverT->getBinding(ctx($sidT))->challenge;
$serverT->issueRefreshChallenge(ctx($sidT));
$bT = $serverT->getBinding(ctx($sidT));
$staleT = new Binding(
	$bT->userId, $bT->sessionIdentifier, $bT->cookieValue, $bT->publicKeyPem, $bT->algorithm,
	$bT->challenge, $bT->challengeTime, $bT->createdAt, $bT->cookieIssuedAt,
	$bT->previousCookieValue, $bT->previousCookieExpiresAt, $bT->hasRefreshed,
	$bT->previousChallenge, time() - 100000, $bT->challengeAdvertised,
);
$storeT->putBinding($sidT, $staleT);
$expiredPrevRejected = false;
try {
	$serverT->refresh($devT->refreshJwt($seedT), ctx($sidT));
} catch (ChallengeMismatchException) {
	$expiredPrevRejected = true;
}
check('previous challenge rejected once past its own TTL', $expiredPrevRejected);
$currentStillOk = false;
try {
	$serverT->refresh($devT->refreshJwt($staleT->challenge), ctx($sidT));
	$currentStillOk = true;
} catch (ChallengeMismatchException) {
}
check('current challenge still accepted after the previous one expired', $currentStillOk);

// A successful refresh deliberately does NOT retain the just-proved challenge (no success-path
// propagation window; keeps the spent challenge from being replayable). Asymmetric vs cookies.
$storeN = new InMemoryStore();
$serverN = new DbscServer(new Config(cookieName: '__Host-dbsc'), $storeN);
$devN = new FakeDevice();
$sidN = 'session-NORETAIN';
$regN = $serverN->buildRegistrationHeaderResponse(ctx($sidN));
preg_match('/challenge="([^"]+)"/', $regN->headers['Secure-Session-Registration'], $mn);
$serverN->register($devN->registrationJwt($mn[1]), ctx($sidN));
$cN = $serverN->issueRefreshChallenge(ctx($sidN));
preg_match('/^"([^"]+)"/', $cN->headers['Secure-Session-Challenge'], $cmn);
$serverN->refresh($devN->refreshJwt($cmn[1]), ctx($sidN));
$bN = $serverN->getBinding(ctx($sidN));
check(
	'successful refresh does not retain the previous challenge',
	$bN->previousChallenge === '' && $bN->previousChallengeTime === 0 && $bN->hasRefreshed === true,
);
$spentRejected = false;
try {
	$serverN->refresh($devN->refreshJwt($cmn[1]), ctx($sidN));
} catch (ChallengeMismatchException) {
	$spentRejected = true;
}
check('the just-spent challenge is not replayable after a successful refresh', $spentRejected);

echo "\nDbscServer — allowed_refresh_initiators\n";

// Default: no Config value, no per-request override -> key absent, byte-identical to prior output.
$storeI1 = new InMemoryStore();
$serverI1 = new DbscServer(new Config(cookieName: '__Host-dbsc'), $storeI1);
$devI1 = new FakeDevice();
$sidI1 = 'session-INIT1';
$regI1Hdr = $serverI1->buildRegistrationHeaderResponse(ctx($sidI1));
preg_match('/challenge="([^"]+)"/', $regI1Hdr->headers['Secure-Session-Registration'], $mi1);
$regI1 = $serverI1->register($devI1->registrationJwt($mi1[1]), ctx($sidI1));
check('default: register body omits allowed_refresh_initiators', !str_contains($regI1->body, 'allowed_refresh_initiators'));
$cI1 = $serverI1->issueRefreshChallenge(ctx($sidI1));
preg_match('/^"([^"]+)"; id="([^"]+)"$/', $cI1->headers['Secure-Session-Challenge'], $cmi1);
$refI1 = $serverI1->refresh($devI1->refreshJwt($cmi1[1]), ctx($sidI1, ['Sec-Secure-Session-Id' => $cmi1[2]]));
check('default: refresh body omits allowed_refresh_initiators', !str_contains($refI1->body, 'allowed_refresh_initiators'));

// Static config: Config-level list appears in register, refresh, and sessionInstructionsJson.
$storeI2 = new InMemoryStore();
$serverI2 = new DbscServer(
	new Config(cookieName: '__Host-dbsc', allowedRefreshInitiators: ['example.com', '*.example.com']),
	$storeI2,
);
$devI2 = new FakeDevice();
$sidI2 = 'session-INIT2';
$regI2Hdr = $serverI2->buildRegistrationHeaderResponse(ctx($sidI2));
preg_match('/challenge="([^"]+)"/', $regI2Hdr->headers['Secure-Session-Registration'], $mi2);
$regI2 = $serverI2->register($devI2->registrationJwt($mi2[1]), ctx($sidI2));
$regI2Decoded = json_decode($regI2->body, true);
check(
	'static config: register body carries the configured initiators, order preserved',
	($regI2Decoded['allowed_refresh_initiators'] ?? null) === ['example.com', '*.example.com'],
);
$cI2 = $serverI2->issueRefreshChallenge(ctx($sidI2));
preg_match('/^"([^"]+)"; id="([^"]+)"$/', $cI2->headers['Secure-Session-Challenge'], $cmi2);
$refI2 = $serverI2->refresh($devI2->refreshJwt($cmi2[1]), ctx($sidI2, ['Sec-Secure-Session-Id' => $cmi2[2]]));
$refI2Decoded = json_decode($refI2->body, true);
check(
	'static config: refresh body carries the configured initiators',
	($refI2Decoded['allowed_refresh_initiators'] ?? null) === ['example.com', '*.example.com'],
);
$sessionJsonI2 = json_decode($serverI2->sessionInstructionsJson(ctx($sidI2)), true);
check(
	'static config: sessionInstructionsJson carries the configured initiators',
	($sessionJsonI2['allowed_refresh_initiators'] ?? null) === ['example.com', '*.example.com'],
);

// Per-request override: RequestContext value wins over a different Config default.
$storeI3 = new InMemoryStore();
$serverI3 = new DbscServer(
	new Config(cookieName: '__Host-dbsc', allowedRefreshInitiators: ['configured.example']),
	$storeI3,
);
$devI3 = new FakeDevice();
$sidI3 = 'session-INIT3';
$ctxI3Override = new RequestContext($sidI3, 'user-1', 'https://example.test', [], [], ['rp.example']);
$regI3Hdr = $serverI3->buildRegistrationHeaderResponse($ctxI3Override);
preg_match('/challenge="([^"]+)"/', $regI3Hdr->headers['Secure-Session-Registration'], $mi3);
$regI3 = $serverI3->register($devI3->registrationJwt($mi3[1]), $ctxI3Override);
$regI3Decoded = json_decode($regI3->body, true);
check(
	'per-request override: RequestContext initiators win over the Config default',
	($regI3Decoded['allowed_refresh_initiators'] ?? null) === ['rp.example'],
);

// Explicit empty override: RequestContext([]) resolves to empty -> key omitted, even though
// Config has a non-empty default.
$ctxI3Empty = new RequestContext($sidI3, 'user-1', 'https://example.test', [], [], []);
$sessionJsonI3Empty = $serverI3->sessionInstructionsJson($ctxI3Empty);
check(
	'explicit empty override: key omitted despite a non-empty Config default',
	!str_contains($sessionJsonI3Empty, 'allowed_refresh_initiators'),
);

// Filtering: empty / whitespace-only entries are dropped.
$storeI4 = new InMemoryStore();
$serverI4 = new DbscServer(new Config(cookieName: '__Host-dbsc'), $storeI4);
$devI4 = new FakeDevice();
$sidI4 = 'session-INIT4';
$ctxI4 = new RequestContext($sidI4, 'user-1', 'https://example.test', [], [], ['rp.example', '', '   ', ' other.example ']);
$regI4Hdr = $serverI4->buildRegistrationHeaderResponse($ctxI4);
preg_match('/challenge="([^"]+)"/', $regI4Hdr->headers['Secure-Session-Registration'], $mi4);
$regI4 = $serverI4->register($devI4->registrationJwt($mi4[1]), $ctxI4);
$regI4Decoded = json_decode($regI4->body, true);
check(
	'filtering: empty / whitespace-only entries dropped, surviving entries trimmed',
	($regI4Decoded['allowed_refresh_initiators'] ?? null) === ['rp.example', 'other.example'],
);

echo "\nDbscServer — benign challenge mismatch does not terminate the session\n";

// Repro: idle session past TTL, two concurrent refreshes holding the same stale challenge.
// Refresh A expires it (benign); refresh B must mismatch benignly too, not revoke.
$storeU = new InMemoryStore(challengeTtlSeconds: 1000, sessionLifetimeSeconds: 1000);
$recorderU = new class implements AuditLoggerInterface {
	/** @var list<string> */
	public array $events = [];
	public function log(string $event, string $message, ?string $userId): void { $this->events[] = $event; }
};
$serverU = new DbscServer(new Config(cookieName: '__Host-dbsc', cookieMaxAgeSeconds: 0, challengeTtlSeconds: 1), $storeU, audit: $recorderU);
$devU = new FakeDevice();
$sidU = 'session-IDLE-RACE';
$regU = $serverU->buildRegistrationHeaderResponse(ctx($sidU));
preg_match('/challenge="([^"]+)"/', $regU->headers['Secure-Session-Registration'], $mu);
$serverU->register($devU->registrationJwt($mu[1]), ctx($sidU));

// Drive one successful refresh so the loop is in steady state.
$chalU1 = $serverU->issueRefreshChallenge(ctx($sidU));
preg_match('/^"([^"]+)"/', $chalU1->headers['Secure-Session-Challenge'], $cmu1);
$serverU->refresh($devU->refreshJwt($cmu1[1]), ctx($sidU));
$staleChallenge = $serverU->getBinding(ctx($sidU))->challenge;

sleep(2); // advance past challengeTtlSeconds (1s)

$refreshAExpired = false;
try {
	$serverU->refresh($devU->refreshJwt($staleChallenge), ctx($sidU));
} catch (ChallengeExpiredException) {
	$refreshAExpired = true;
}
check('refresh A on the idle-past-TTL challenge is benign ChallengeExpiredException', $refreshAExpired);
check('refresh A audits EVENT_REFRESH_RETRYABLE too', end($recorderU->events) === DbscServer::EVENT_REFRESH_RETRYABLE);

$chalU2 = $serverU->issueRefreshChallenge(ctx($sidU));
preg_match('/^"([^"]+)"/', $chalU2->headers['Secure-Session-Challenge'], $cmu2);
check('reissuing after the benign expiry gives a fresh challenge', $cmu2[1] !== $staleChallenge);

// The demoted previous challenge is already past its own TTL here, so this is a genuine mismatch.
$refreshBMismatch = null;
try {
	$serverU->refresh($devU->refreshJwt($staleChallenge), ctx($sidU));
} catch (\Throwable $e) {
	$refreshBMismatch = $e;
}
check(
	'refresh B (same stale challenge, against rotated state) throws ChallengeMismatchException, not JwtInvalidException',
	$refreshBMismatch instanceof ChallengeMismatchException && !($refreshBMismatch instanceof JwtInvalidException),
);
check(
	'refresh B mismatch is benign / RetryableRefreshException',
	$refreshBMismatch instanceof RetryableRefreshException,
);
check(
	'the binding still exists after the benign mismatch (session not revoked)',
	$serverU->getBinding(ctx($sidU)) instanceof Binding,
);
check(
	'a retryable mismatch audits EVENT_REFRESH_RETRYABLE, not EVENT_REFRESH_FAILED',
	end($recorderU->events) === DbscServer::EVENT_REFRESH_RETRYABLE
	&& !in_array(DbscServer::EVENT_REFRESH_FAILED, $recorderU->events, true),
);

// Forged signature is still terminal, unchanged: a refresh JWT signed by a different key throws
// JwtInvalidException, never the benign ChallengeMismatchException.
$storeV = new InMemoryStore();
$serverV = new DbscServer(new Config(cookieName: '__Host-dbsc'), $storeV);
$devV = new FakeDevice();
$forgerV = new FakeDevice();
$sidV = 'session-FORGED';
$regV = $serverV->buildRegistrationHeaderResponse(ctx($sidV));
preg_match('/challenge="([^"]+)"/', $regV->headers['Secure-Session-Registration'], $mv);
$serverV->register($devV->registrationJwt($mv[1]), ctx($sidV));
$chalV = $serverV->issueRefreshChallenge(ctx($sidV));
preg_match('/^"([^"]+)"/', $chalV->headers['Secure-Session-Challenge'], $cmv);
$forgedResult = null;
try {
	$serverV->refresh($forgerV->refreshJwt($cmv[1]), ctx($sidV));
} catch (\Throwable $e) {
	$forgedResult = $e;
}
check(
	'a forged-signature refresh is still terminal JwtInvalidException, not a RetryableRefreshException',
	$forgedResult instanceof JwtInvalidException && !($forgedResult instanceof RetryableRefreshException),
);

// Type/contract: the benign family shares one catchable marker; JwtInvalidException is excluded.
check(
	'ChallengeMismatchException is a DbscException and a RetryableRefreshException',
	new ChallengeMismatchException() instanceof \ReportUri\Dbsc\Exception\DbscException
	&& new ChallengeMismatchException() instanceof RetryableRefreshException,
);
check(
	'JwtInvalidException is NOT a RetryableRefreshException',
	!(new JwtInvalidException() instanceof RetryableRefreshException),
);
check(
	'ChallengeExpiredException and MissingChallengeException are RetryableRefreshException too',
	new ChallengeExpiredException() instanceof RetryableRefreshException
	&& new \ReportUri\Dbsc\Exception\MissingChallengeException() instanceof RetryableRefreshException,
);

echo "\n" . ($failed === 0 ? "OK" : "FAILED") . " — $tests checks, $failed failed\n";
exit($failed === 0 ? 0 : 1);
