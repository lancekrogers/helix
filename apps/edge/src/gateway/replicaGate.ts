/**
 * Caps total in-flight LLM calls on this replica. It protects this process's sockets and
 * event loop without a database lock on every call. Per replica by design, like
 * DenialThrottle: the cross-replica limits are the Postgres leases, and the effective total
 * here is max x replicas (up to three).
 */
export class ReplicaGate {
  readonly #max: number;
  #inFlight = 0;
  constructor(max: number) {
    this.#max = max;
  }
  /** False when the replica is at its limit. 0 disables the limit. */
  tryEnter(): boolean {
    if (this.#max > 0 && this.#inFlight >= this.#max) return false;
    this.#inFlight += 1;
    return true;
  }
  leave(): void {
    if (this.#inFlight > 0) this.#inFlight -= 1;
  }
}
