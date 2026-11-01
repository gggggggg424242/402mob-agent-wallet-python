# 402Mob agent wallet roadmap

Status: Phases 1–5 are proposals, not shipped functionality. Phase 0 records source
publication and remaining release work. Comparison reviewed 2026-11-02 against
the linked Openfort documentation and our Node 0.1.2 / Python 0.1.1 source.
This is a documentation/source comparison, not a benchmark or audit of Openfort.

## Direction

Build a wallet an agent can instantiate locally, use under an explicit task budget,
and recover after an interrupted exchange. Preserve local key ownership and make
budget decisions part of the signing path. Hosted signer providers can be optional
adapters; an Openfort account should not become a prerequisite for a local EOA.

Our useful distinction is the link between payment intent and the received object:
provider, offer version, recipient, operation, result hash and acknowledgment. Wallet
creation alone does not provide that exchange record or create buyer demand.

## Comparison

| Dimension | Openfort's documented workflow | 402Mob today |
| --- | --- | --- |
| Bootstrap | Backend SDK account creation after project/API key and wallet-secret setup | EOA generated in the agent runtime; signature enrollment needs no provider account, existing wallet, operator token or gas |
| Key handling | Backend wallet/signing service; operations require API credentials plus wallet-secret authorization | Private local files (unencrypted) or caller-supplied vault; Node also accepts a managed signer adapter |
| Authorization | Account/project signing policies and policy evaluation API | Node checks exact Base USDC terms, expected payee and a per-purchase cap; no aggregate budget or general policy engine |
| Policy boundary | Guide explicitly says backend EIP-7702 send is evaluated as `signEvmHash`; transaction restrictions need exact-call preflight | Purchase checks run before the client signs its authorization; another holder of the EOA key can bypass this client |
| Gas | Separate fee sponsorship and EIP-7702 transaction flow; example uses Base Sepolia, chain 84532 | Enrollment is off-chain EIP-191; artifact x402 settlement uses a facilitator. Clients have no general transaction sponsorship; direct-transfer API flows need Base ETH |
| Agent tools | Local stdio CLI MCP server exposes wallet creation, policy preflight and transaction operations | Hosted HTTP MCP exposes enrollment/resources/service actions; it cannot create or sign with a local agent key |
| Payments | Broader transaction infrastructure with a separate x402 recipe | Node implements 402Mob prepared-artifact x402 purchase/replay/receipts; Python has seller creation/enrollment/publication/discovery only |
| Recovery | Transaction IDs, receipt polling and webhooks | Node journals exact payment authorization and operation data; Python retains enrollment identity and rotates a lost credential |
| Delegation | Separate user/server signer workflow describes scoped sessions | Long-lived merchant bearer credential with wallet-proof rotation; no expiring merchant sessions |

Source boundaries matter: an off-chain preflight is not equivalent to on-chain
restriction. The linked Openfort guide also warns that reusing a guardrail policy
for fee sponsorship changes its behavior. Do not assume a paymaster bounds spending,
or that a rule on transaction fields inspects an opaque hash or typed-data message.
Neither 402Mob's per-purchase cap nor its Work Ticket cap limits spending by other
software holding the same wallet key. A signed receipt is not proof of work quality.

## Phase 0 — reproducible independent clients

Public source repositories are now available:

- [Node wallet](https://github.com/gggggggg424242/402mob-agent-wallet): 5 standalone tests and 32 optional service-integration tests verified locally.
- [Python wallet](https://github.com/gggggggg424242/402mob-agent-wallet-python): 14 standalone regression tests verified locally.

Both include licenses and CI. Runtime files match npm 0.1.2 / PyPI 0.1.1; repository
metadata and test harnesses are separate from the immutable registry artifacts.
Cross-language protocol vectors and automated release provenance remain future work.

Priority: first. Publish separate public Node/Python repositories with installable
packages, licenses, tests, CI and clearly documented feature differences. Keep the
published package bytes immutable; distinguish source-only metadata changes from
registry releases. Add cross-language challenge, origin, time and recovery vectors.

Exit criteria: fresh clones run their standalone suites without the service source;
optional service integration is explicit; artifacts match published checksums;
no real keys, journals or merchant credentials enter either repository. Run a fresh
Python production enrollment only when explicitly authorized; never infer one from
read-only checks or the successful Node run.

## Phase 1 — Python buyer parity

Implement exact Base USDC offer inspection, required expected payee, per-purchase
cap, durable pre-signing journal, interrupted-response recovery and signed delivery
acknowledgment. Reuse protocol vectors rather than loosely translating Node methods.
Expose publication/discovery through the Python CLI after library behavior is stable.

Exit criteria: two local agents buy and recover one operation after response loss;
changed payee, price, version or idempotency terms cannot trigger another payment.
Then perform a separately authorized funded production run with a declared cap.

## Phase 2 — task spending envelopes at the signer

Add a versioned policy: task ID, network/asset, allowed recipients, per-payment and
task/window caps in atomic units, validity period and revocation identifier. An
atomic ledger reserves budget before signing, commits confirmed spend, and retains
reservations for unresolved authorizations. Retries reuse the reservation; a timeout
must not release spend that might still settle. Define when an unused authorization
has expired and which chain evidence permits a reservation release.

Put enforcement inside a local signing boundary, not an advisory MCP tool. A policy
rejection must prevent creation of a usable signature. Never offer an unrestricted
hash-signing escape hatch in the same tool set. Identify that local software checks
remain bypassable by a process with the raw EOA key; stronger isolation requires a
vault/signer process or contract enforcement with its own assumptions.

Exit criteria: competing purchases cannot exceed a shared cap; crash/restart and
pending settlements preserve budget; unknown typed-data domains/methods are denied;
revocation blocks new signatures without destroying recovery data. Already-issued
authorizations are not claimed to be revoked merely by changing a local policy.

## Phase 3 — local wallet MCP bridge

Add a local stdio MCP wrapper around the same wallet library. Offer narrow tools:
`wallet_status`, `wallet_bootstrap`, `inspect_offer`, `purchase_artifact`,
`recover_purchase`, `publish_artifact` and `set_discovery`. Publication and payment
remain separate actions. Carry task/policy IDs into purchase tools. Expose neither
private-key export nor unrestricted message/hash/transaction signing.

Document framework configuration with a stable private state directory, explicit
allowed tools and a signer bound to the selected policy. The hosted evidence.contact
MCP remains a service interface; private keys and local credentials do not move to it.

Exit criteria: an MCP-only tool caller with the installed local bridge creates an
identity, enrolls and completes a bounded exchange without shell access or secret
values in tool results. Reconnect/restart preserves identity and payment journals.

## Phase 4 — credential lifecycle, vaults and observability

Add validated encrypted-store adapters and key-safe backup/restore tooling. Design
expiring, revocable merchant sessions scoped to operations and one merchant, while
keeping wallet identity separate from the merchant access credential. Add local
machine-readable events for authorization intent, policy decision, pending/settled
operation, credential recovery and result verification, with secret-free fields.

Exit criteria: session expiry/revocation and restore are covered end to end; a session
cannot manage another provider or elevate its own scope; logs never contain keys,
bearer credentials or replayable signed authorizations. No claim that a public wallet
address proves an agent's operator, identity, competence or reputation.

## Phase 5 — optional sponsored execution and signer providers

Prototype an Openfort-compatible Node signer adapter using the documented signing
interfaces, and test EIP-191 plus the exact EIP-3009 typed-data/domain requirements.
Do not assume an EIP-7702 or contract account is accepted by 402Mob's EOA verifier.
Treat EIP-1271 support as a separate service verification project if needed.

For ordinary on-chain actions, explore sponsored transactions with a distinct gas
policy and hard caps. Validate the exact destination, chain, calldata and amount at
the signing/execution boundary. Never describe preflight-only filtering as an
unbypassable contract allowlist. Keep the existing facilitator-based artifact flow
separate from general wallet gas sponsorship.

Exit criteria: provider compatibility vectors pass; unsupported signature/account
types fail before a charge; sponsor failures become actionable states rather than
indefinite pending; a transaction outside the policy cannot obtain a valid signature
through another exposed tool. Production enablement requires its own review/run.

## First experiment after this publication

Prioritize Python buyer parity, then a task budget and local MCP bridge. Test an
external buyer agent discovering a real prepared resource, inspecting exact terms,
paying once under a cap, recovering after a deliberately interrupted response, and
acknowledging the result. Measure independent completed operations and repeat buyers;
exclude our tests, registry crawls and health probes from adoption claims.

## References

- [Openfort agentic-wallet workflow](https://www.openfort.io/docs/products/server/workflows/agentic-wallets)
- [Openfort policies and backend-send evaluation caveat](https://www.openfort.io/docs/configuration/policies#what-a-backend-send-is-evaluated-as)
- [Openfort backend setup](https://www.openfort.io/docs/products/server/setup)
- [Openfort x402 recipe](https://www.openfort.io/docs/recipes/x402)
- [Openfort user/server signers](https://www.openfort.io/docs/products/server/workflows/user-and-server-signers)
- [402Mob Node wallet guide](https://evidence.contact/agent-wallet.md)
- [402Mob Python wallet guide](https://evidence.contact/python-wallet.md)
- [Runtime recipe and validation scope](https://evidence.contact/agent-wallet.json)
