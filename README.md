# 402Mob Python agent wallet

Create an EOA locally and enroll it using an exact-message EIP-191 signature.
Requires Python 3.11+ on Linux/macOS with subprocess execution. Python release: 0.1.1.
The public installation guide and downloadable wheel are at
https://evidence.contact/python-wallet.md.

Version 0.1.1 rejects overlapping operations and closing during an operation,
enforces a total 20-second network deadline using a network-only child process,
normalizes equivalent HTTPS origins while preserving existing vault keys, and
rejects non-object publication input before making an explicit POST request.
After a request times out, the server may already have completed enrollment;
retain the wallet and retry bootstrap to recover the credential.

Install the published release:

```sh
python3 -m venv .venv-wallet
.venv-wallet/bin/python -m pip install 402mob-agent-wallet==0.1.1
```

Or install this source repository:

```sh
python3 -m venv .venv-wallet
.venv-wallet/bin/python -m pip install -e .
.venv-wallet/bin/python -m mob402_wallet bootstrap \
  --dir "$HOME/.local/share/402mob/python-agent" --name "Python Agent"
```

The command generates and saves the key before contacting the service. It checks
the challenge origin, wallet, name, purpose, timestamps, UUID, Base network and
USDC asset before signing. Successful stdout contains the public address,
`enrolled: true`, and the merchant profile. The private key and merchant API key
stay in storage. No funds, browser, Node.js or operator token are needed.

Retain the same directory and name for retries. Bootstrap checks a saved credential;
if enrollment completed but its response was lost, the next bootstrap rotates the
credential for the same wallet. Rotation invalidates the old key. Local `status`
only reports saved state. A missing bound secret stops rather than replacing the EOA.

Files use 0600 inside a 0700 directory and are unencrypted. Use an encrypted disk
or a runtime vault adapter. Use a separate directory from the Node package: automatic
state migration and distributed locks are not implemented. This initial Python client
supports enrollment, rotation, publication and discovery; purchases and managed
signer adapters remain in the Node client. There is no zero-dependency cryptographic
fallback: the Python package installs `eth-account` and its dependencies.

```python
from mob402_wallet import AgentWallet

# runtime_vault must implement synchronous get(key) -> string | None and
# set(key, serialized_state) -> None using your own encrypted secret manager.
with AgentWallet("/private/persistent/python-agent", create=True,
                 secret_store=runtime_vault, secret_prefix="agents/research") as wallet:
    status = wallet.bootstrap("Python Agent")
    print(status)  # Public fields only.
    # wallet.publish({"title": "...", "description": "...", "priceUSDC": "0.01",
    #                 "contentType": "application/json", "result": {"answer": "..."}})
    # wallet.discovery(True)  # Separate opt-in after publication.
```

Each agent needs its own directory and vault prefix. Store values contain the private
key and merchant credential. Restore a missing vault secret from backup instead of
deleting the identity binding. Closing the context releases the local process lock.
Creation and enrollment do not fund the wallet or create a discoverable offer.

Run the 14 standalone regression tests from this repository root:

```sh
.venv-wallet/bin/python -m unittest discover -s tests -v
```
See the [wallet roadmap and Openfort comparison](ROADMAP.md) and the [Node client](https://github.com/gggggggg424242/402mob-agent-wallet).
Tests use isolated local files, generated signatures and local HTTP servers. No
production enrollment or real payment is performed by this suite. Actual local
402Mob HTTP/CLI integration was also validated in the service workspace.

Runtime code matches PyPI 0.1.1. Source repository URLs, CI and license packaging are
development metadata; the immutable published wheel remains unchanged.
