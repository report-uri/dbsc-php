<?php
declare(strict_types = 1);

/*
 * Reference DBSC integration — a minimal single-file front controller.
 *
 * DBSC is driven entirely by the browser (no JS API), so unlike the passkeys demo there is no
 * client.html: you exercise this with a real DBSC-capable browser (Chrome 146+ on Windows at the
 * time of writing) over HTTPS. Routes:
 *
 *   GET  /?route=login     "log in" -> sets a session, emits Secure-Session-Registration
 *   POST /dbsc/register    browser posts the registration JWT (Sec-Session-Response header)
 *   POST /dbsc/refresh     browser's ~5-min refresh (two-phase: 403+challenge, then 200)
 *   GET  /?route=account   protected page — the enforcement gate runs here
 *   GET  /?route=logout    clears the session and revokes DBSC
 *
 * The store is file-backed and keyed by the PHP session id — deliberately a DEDICATED key space,
 * NOT $_SESSION. Putting DBSC state in the read-modify-written session blob is the exact race
 * (post-login navigation vs the register POST) that silently disables enforcement.
 */

require __DIR__ . '/../src/Exception/DbscException.php';
require __DIR__ . '/../src/Exception/RetryableRefreshException.php';
require __DIR__ . '/../src/Exception/JwtInvalidException.php';
require __DIR__ . '/../src/Exception/ChallengeExpiredException.php';
require __DIR__ . '/../src/Exception/ChallengeMismatchException.php';
require __DIR__ . '/../src/Exception/MissingChallengeException.php';
require __DIR__ . '/../src/Exception/SessionNotFoundException.php';
require __DIR__ . '/../src/RegistrationResult.php';
require __DIR__ . '/../src/PendingRegistration.php';
require __DIR__ . '/../src/Binding.php';
require __DIR__ . '/../src/StoreInterface.php';
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
use ReportUri\Dbsc\DbscResponse;
use ReportUri\Dbsc\DbscServer;
use ReportUri\Dbsc\Exception\DbscException;
use ReportUri\Dbsc\Exception\RetryableRefreshException;
use ReportUri\Dbsc\PendingRegistration;
use ReportUri\Dbsc\RequestContext;
use ReportUri\Dbsc\StoreInterface;

/** Dedicated file-backed store, keyed by session id — the correct pattern (NOT the session blob). */
final class FileStore implements StoreInterface
{

	public function __construct(private string $dir, private int $challengeTtl = 900, private int $sessionTtl = 64800)
	{
		@mkdir($dir, 0700, true);
	}

	private function path(string $k): string { return $this->dir . '/' . sha1($k) . '.json'; }
	private function read(string $k): ?string {
		$f = $this->path($k);
		if (!is_file($f)) { return null; }
		$d = json_decode((string)file_get_contents($f), true);
		if (!is_array($d) || $d['exp'] < time()) { @unlink($f); return null; }
		return $d['v'];
	}
	private function write(string $k, string $v, int $ttl): void {
		file_put_contents($this->path($k), json_encode(['v' => $v, 'exp' => time() + $ttl]), LOCK_EX);
	}

	public function putPendingRegistration(string $s, PendingRegistration $p): void { $this->write("reg:$s", $p->toJson(), $this->challengeTtl); }
	public function getPendingRegistration(string $s): ?PendingRegistration { $r = $this->read("reg:$s"); return $r === null ? null : PendingRegistration::fromJson($r); }
	public function deletePendingRegistration(string $s): void { @unlink($this->path("reg:$s")); }
	public function putBinding(string $s, Binding $b): void { $this->write("bind:$s", $b->toJson(), $this->sessionTtl); }
	public function getBinding(string $s): ?Binding { $r = $this->read("bind:$s"); return $r === null ? null : Binding::fromJson($r); }
	public function delete(string $s): void { @unlink($this->path("reg:$s")); @unlink($this->path("bind:$s")); }

}

session_start();

$config = new Config(cookieName: '__Host-demo_dbsc');
$store = new FileStore(sys_get_temp_dir() . '/dbsc-demo-store');
$dbsc = new DbscServer($config, $store);

function emit(DbscResponse $r): void
{
	foreach ($r->headers as $n => $v) {
		header("$n: $v");
	}
	foreach ($r->cookies as $c) {
		setcookie($c->name, $c->delete ? '' : $c->value, [
			'expires' => $c->delete ? 1 : $c->expiresAt,
			'path' => $c->path,
			'secure' => $c->secure,
			'httponly' => $c->httpOnly,
			'samesite' => $c->sameSite,
		]);
	}
	if ($r->contentType !== null) {
		header('Content-Type: ' . $r->contentType);
	}
	if ($r->status !== null) {
		http_response_code($r->status);
	}
	if ($r->body !== null) {
		echo $r->body;
	}
}

function context(): RequestContext
{
	$headers = function_exists('getallheaders') ? getallheaders() : [];
	return new RequestContext(
		session_id(),
		(string)($_SESSION['uid'] ?? ''),
		(isset($_SERVER['HTTPS']) ? 'https' : 'http') . '://' . ($_SERVER['HTTP_HOST'] ?? 'localhost'),
		$headers,
		$_COOKIE,
	);
}

$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
$route = $_GET['route'] ?? null;
$ctx = context();

// --- DBSC endpoints -----------------------------------------------------------------------
if ($path === '/dbsc/register') {
	$jwt = $ctx->header('Sec-Session-Response') ?? $ctx->header('Secure-Session-Response');
	if (!is_string($jwt) || $jwt === '') {
		http_response_code(400);
		exit;
	}
	try {
		emit($dbsc->register(trim($jwt, '"'), $ctx));
	} catch (DbscException $e) {
		http_response_code(401);
		echo json_encode(['ok' => false, 'error' => $e->getMessage()]);
	}
	exit;
}

if ($path === '/dbsc/refresh') {
	$jwt = $ctx->header('Sec-Session-Response') ?? $ctx->header('Secure-Session-Response');
	if (!is_string($jwt) || $jwt === '') {
		emit($dbsc->issueRefreshChallenge($ctx)); // phase 1: 403 + challenge
		exit;
	}
	try {
		emit($dbsc->refresh(trim($jwt, '"'), $ctx)); // phase 2: 200 + rotated cookie
	} catch (RetryableRefreshException) {
		emit($dbsc->issueRefreshChallenge($ctx)); // stale/missing/mismatched challenge — hand out a fresh one
	} catch (DbscException $e) {
		// Terminal proof failure: revoke + log the user out server-side. Do NOT rely on the
		// browser/cookie-expiry to do it — that is the stolen-cookie-stays-alive hole.
		emit($dbsc->revoke($ctx, true));
		unset($_SESSION['uid']);
		http_response_code(401);
		echo json_encode(['ok' => false, 'error' => $e->getMessage()]);
	}
	exit;
}

// --- App routes ---------------------------------------------------------------------------
if ($route === 'login') {
	$_SESSION['uid'] = 'demo-user';
	// After full auth, decorate the login response with the registration offer.
	emit($dbsc->buildRegistrationHeaderResponse(context()));
	echo "Logged in. DBSC registration offered. <a href='?route=account'>Go to account</a>";
	exit;
}

if ($route === 'logout') {
	emit($dbsc->revoke($ctx));
	unset($_SESSION['uid']);
	echo "Logged out. <a href='?route=login'>Log in</a>";
	exit;
}

if ($route === 'account') {
	if (empty($_SESSION['uid'])) {
		header('Location: ?route=login');
		exit;
	}
	// --- Recommended enforcement gate -----------------------------------------------------
	$binding = $dbsc->getBinding($ctx);
	if ($binding === null) {
		// Never registered (unsupported browser / not yet) — degrade to plain cookie auth.
		echo "Account page (cookie auth — browser did not register DBSC).";
		exit;
	}
	$isDoc = $dbsc->isDocumentRequest($ctx);
	$pastGrace = !$dbsc->isWithinRegistrationGrace($binding);
	if (($isDoc || $pastGrace) && !$dbsc->boundCookieMatches($binding, $ctx)) {
		emit($dbsc->revoke($ctx, true));
		unset($_SESSION['uid']);
		header('Location: ?route=login');
		exit;
	}
	echo "Account page (DBSC-bound — device-bound cookie verified).";
	exit;
}

echo "<a href='?route=login'>Log in</a> to start the DBSC demo (use a DBSC-capable browser over HTTPS).";
