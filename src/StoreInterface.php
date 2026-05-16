<?php
declare(strict_types = 1);

namespace ReportUri\Dbsc;

/**
 * Persistence for DBSC state, keyed by the host application's session id.
 *
 * Implementation requirements:
 *  - The pending-registration and binding records MUST be stored under separate keys. "A binding
 *    exists" is the authoritative hard-DBSC mark; conflating it with the pending challenge would
 *    let a browser that merely *received* the registration offer be treated as bound.
 *  - State MUST NOT live in a read-modify-written shared session blob (last-writer-wins). Use a
 *    dedicated key space — Redis, a table, etc. See README, "Storage".
 *  - Pending registrations should expire on a short TTL (the challenge TTL). Bindings should
 *    expire with the authenticated session lifetime.
 *  - Read failures should fail closed (return null / throw), never silently return a stale or
 *    empty binding that would degrade a bound session to plain cookie auth.
 */
interface StoreInterface
{

	public function putPendingRegistration(string $sessionId, PendingRegistration $pending): void;


	public function getPendingRegistration(string $sessionId): ?PendingRegistration;


	public function deletePendingRegistration(string $sessionId): void;


	public function putBinding(string $sessionId, Binding $binding): void;


	public function getBinding(string $sessionId): ?Binding;


	public function delete(string $sessionId): void;

}
