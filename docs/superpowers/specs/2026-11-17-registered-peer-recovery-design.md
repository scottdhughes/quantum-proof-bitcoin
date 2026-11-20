# Registered TEST peer recovery

The experimental public TEST wallet must recover delivery of an already signed,
known mempool transaction when repeated announcements on an existing connection
do not reach the recipient. Recovery must preserve the original 60-second
payment deadline and must not issue another address, signature, or payment.

An exact-L private native experiment retained healthy peer IDs and fresh
ping/pong replies while dropping one transaction INV. Five known-transaction
rebroadcasts left the receiver empty through 60 seconds. A separately timed
control renewed that exact connection and confirmed the same transaction in
about 3.69 seconds. This establishes a recovery target; it does not establish
the cause of the failed public soak. The original reports remain unchanged.

Add a host-controller `renew_peer(endpoint, budget_seconds)` action. It executes
a bounded Python helper against the immutable ID of the currently owned
container, using the existing H `PublicNode`, `PeerPolicy.validate`, and native
RPC. No new H worker opcode, native binary, consensus rule, wallet format,
signature operation, or persistent setting is required.

The helper reads only the public saved peer policy with strict file guards,
refuses an orphan temporary policy, and requires the endpoint to be both saved
and registered in the native node. Saved and native networking must both be on.
It never enables networking, changes policy, or disconnects unrelated peers.
It disconnects only the exact matching peer ID, requests at most one connection
attempt for that endpoint, and observes races without replaying a mutation.
For an existing peer, it preserves the observed v1/v2 transport choice. With no
matching live peer, it uses the native default instead of forcing a downgrade.
Multiple matching live peers are refused.

Successful renewal proves a new target peer ID, completed transaction-relay
handshake, increased ping-sent and pong-received counters, and no pending ping.
The response contains bounded public proof fields and no authentication data.
Policy, live network state, container identity, and remaining budget are checked
again before success. The helper does not construct `PeerPolicy`, whose
constructor can recover files outside the worker's store lock.

The public workload may renew the follower's already registered bridge endpoint
once after ten seconds of receiver absence, then reannounce only the known
transaction. Its original action deadline, recipient mempool observation,
two-node exact block membership, full UTXO agreement, and 60-second settlement
limit remain unchanged. Deliberate network-off stays off.

Acceptance requires focused negative controls, a registered-endpoint native
regression with the same transaction confirmed inside its original deadline,
H-image compatibility, exact-source four-profile native qualification and CI,
a fresh 900-second public preflight, and a separate 86,400-second public soak.
Actual Docker Desktop recovery is repeated if the final change affects that
flow. Historical failures and partial times remain retained with zero credit.
Human review is not claimed; production backend `NONE` and release hold remain.
