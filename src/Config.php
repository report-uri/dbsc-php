<?php
declare(strict_types = 1);

namespace ReportUri\Dbsc;

/**
 * Static DBSC configuration. Defaults match the wire behaviour validated against real Chrome
 * (see README, "Wire-protocol notes"). Two constraints are load-bearing:
 *
 *  - {@see $challengeTtlSeconds} MUST exceed {@see $cookieMaxAgeSeconds}, so the challenge the
 *    browser cached just before cookie expiry is still valid when it presents it.
 *  - {@see $includeSite} is false because the bound cookie uses the `__Host-` prefix and cannot
 *    span subdomains. Only flip it (and drop the `__Host-` prefix) if you deliberately move to a
 *    `__Secure-` cookie for subdomain coverage.
 */
final class Config
{

	public function __construct(
		public readonly string $cookieName = '__Host-dbsc',
		public readonly int $cookieMaxAgeSeconds = 300,
		public readonly string $registerPath = '/dbsc/register',
		public readonly string $refreshPath = '/dbsc/refresh',
		public readonly int $challengeTtlSeconds = 900,
		/**
		 * Seconds after a successful registration during which subresource fetches are exempt
		 * from the enforcement gate. Covers the inherent in-flight race where a page's
		 * XHR/script/image requests are already on the wire (without the bound cookie) when the
		 * registration response lands client-side. Raise only if production termination audits
		 * show legitimate post-registration traffic still tripping the gate.
		 */
		public readonly int $registrationGraceSeconds = 5,
		public readonly string $cookieSameSite = 'Lax',
		/**
		 * Hosts allowed to initiate a cross-site DBSC refresh (allowed_refresh_initiators).
		 * Overridable per request via {@see RequestContext::$allowedRefreshInitiators}.
		 *
		 * @var list<string>
		 */
		public readonly array $allowedRefreshInitiators = [],
	) {
		if ($challengeTtlSeconds <= $cookieMaxAgeSeconds) {
			throw new \InvalidArgumentException(
				'DBSC: challengeTtlSeconds must exceed cookieMaxAgeSeconds, else the browser\'s '
				. 'cached challenge expires before it can use it just before cookie expiry.',
			);
		}
	}

}
