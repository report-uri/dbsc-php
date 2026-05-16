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
require __DIR__ . '/../src/Exception/JwtInvalidException.php';
require __DIR__ . '/../src/Exception/ChallengeExpiredException.php';
require __DIR__ . '/../src/Exception/MissingChallengeException.php';
require __DIR__ . '/../src/Exception/SessionNotFoundException.php';
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

use ReportUri\Dbsc\Binding;
use ReportUri\Dbsc\Config;
use ReportUri\Dbsc\DbscServer;
use ReportUri\Dbsc\Exception\ChallengeExpiredException;
use ReportUri\Dbsc\Exception\JwtInvalidException;
use ReportUri\Dbsc\Exception\SessionNotFoundException;
use ReportUri\Dbsc\InMemoryStore;
use ReportUri\Dbsc\JwtVerifier;
use ReportUri\Dbsc\RequestContext;

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
check('stale (pre-refresh) cookie no longer matches', !$server->boundCookieMatches($bindingNow, ctx($sid, [], ['__Host-dbsc' => $cookie1])));
check('missing cookie does not match', !$server->boundCookieMatches($bindingNow, ctx($sid, [], [])));

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
	check('refresh with a wrong challenge is rejected', false);
} catch (JwtInvalidException) {
	check('refresh with a wrong challenge is rejected', true);
}

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

echo "\n" . ($failed === 0 ? "OK" : "FAILED") . " — $tests checks, $failed failed\n";
exit($failed === 0 ? 0 : 1);
