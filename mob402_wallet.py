"""Agent-owned EOA and 402Mob enrollment. No private material leaves storage."""
import argparse
import fcntl
import json
import os
import re
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from datetime import datetime
from functools import wraps
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener

import certifi

from eth_account import Account
from eth_account.messages import encode_defunct

USDC = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"


class WalletError(Exception):
    pass


class ApiError(WalletError):
    def __init__(self, status, code):
        self.status, self.code = status, code
        super().__init__(f"Service rejected request (HTTP {status}); retain wallet state.")


def require(condition, message):
    if not condition:
        raise WalletError(message)


def origin_of(value):
    u = urlsplit(value)
    require(u.scheme == "https" or (u.scheme == "http" and u.hostname in ("localhost", "127.0.0.1", "::1")), "Use HTTPS or loopback HTTP.")
    require(u.hostname and not u.username and not u.password and not u.query and not u.fragment and u.path in ("", "/"), "Use a service origin without path or credentials.")
    try:
        port = u.port
        host = u.hostname.encode('idna').decode('ascii').lower()
    except (ValueError, UnicodeError):
        raise WalletError("Invalid service hostname or port.") from None
    host = f"[{host}]" if ':' in host else host
    suffix = '' if port is None or port == (443 if u.scheme == 'https' else 80) else f':{port}'
    return f"{u.scheme}://{host}{suffix}"


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise WalletError("Service redirect refused; preserve wallet state.")


def _http_request_json(origin, path, body=None, token=None, method=None):
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = Request(origin + path, data=None if body is None else json.dumps(body).encode(),
                      headers=headers, method=method or ("GET" if body is None else "POST"))
    try:
        response = build_opener(NoRedirect(), HTTPSHandler(context=ssl.create_default_context(cafile=certifi.where()))).open(request, timeout=20)
    except HTTPError as error:
        with error:
            data = error.read(1024 * 1024 + 1)
        try:
            code = json.loads(data).get("error")
        except (ValueError, AttributeError):
            code = None
        raise ApiError(error.code, code) from None
    with response:
        data = response.read(1024 * 1024 + 1)
    require(len(data) <= 1024 * 1024, "Service response exceeds 1 MiB.")
    try:
        return json.loads(data)
    except ValueError:
        raise WalletError("Invalid service response; retry with the same wallet directory.") from None


def _http_worker():
    """Network-only child: bounded output; secrets travel only through private pipes."""
    try:
        args = json.loads(sys.stdin.buffer.read())
        result = {"ok": True, "value": _http_request_json(*args)}
    except ApiError as error:
        result = {"ok": False, "status": error.status,
                  "code": error.code if isinstance(error.code, str) else None}
    except Exception:
        result = {"ok": False}
    sys.stdout.write(json.dumps(result))


def request_json(origin, path, body=None, token=None, method=None, *, timeout=20):
    # A socket timeout alone can be extended indefinitely by trickled bytes.
    # Terminating this network-only child bounds DNS, headers and body together;
    # no child can write wallet state or outlive the timed-out request.
    require(type(timeout) in (int, float) and 0 < timeout <= 300, "Invalid request deadline.")
    try:
        completed = subprocess.run([sys.executable, '-I', str(Path(__file__).resolve()), '--internal-http'],
                                   input=json.dumps([origin, path, body, token, method]).encode(),
                                   capture_output=True, timeout=timeout, check=True)
    except subprocess.TimeoutExpired:
        raise WalletError("Service request deadline exceeded; retain wallet state and retry bootstrap to recover.") from None
    except (OSError, subprocess.CalledProcessError):
        raise WalletError("Service request failed; retain wallet state.") from None
    try:
        result = json.loads(completed.stdout)
    except ValueError:
        raise WalletError("Invalid network worker response; retain wallet state.") from None
    if not result.get('ok'):
        if isinstance(result.get('status'), int):
            raise ApiError(result['status'], result.get('code'))
        raise WalletError("Service request failed; check connectivity and retain wallet state.")
    return result['value']


def exclusive(action):
    @wraps(action)
    def run(self, *args, **kwargs):
        require(self._operation_lock.acquire(blocking=False), "Wallet operation is active; wait before retrying or closing.")
        try:
            require(self._lock is not None, "Wallet is closed.")
            return action(self, *args, **kwargs)
        finally:
            self._operation_lock.release()
    return run


def read_private(path):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return None
    with os.fdopen(fd) as stream:
        s = os.fstat(stream.fileno())
        require(stat.S_ISREG(s.st_mode) and s.st_uid == os.getuid() and not s.st_mode & 0o077 and s.st_size <= 1024 * 1024,
                "Unsafe wallet file permissions, owner, type or size.")
        return json.load(stream)


def write_private(path, value):
    fd, temp = tempfile.mkstemp(prefix=".state-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(value, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def timestamp(value):
    require(isinstance(value, str), "Invalid challenge timestamp.")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        require(parsed.tzinfo is not None, "Challenge needs timezone.")
        return parsed.timestamp()
    except ValueError:
        raise WalletError("Invalid challenge timestamp.") from None


class AgentWallet:
    """Use as a context manager. secret_store implements get(key), set(key, string)."""
    def __init__(self, directory, origin="https://evidence.contact", *, create=False,
                 secret_store=None, secret_prefix="402mob/python-wallet", transport=request_json):
        self.origin = origin_of(origin)
        self.directory = Path(os.path.abspath(directory))
        self._lock = None
        self._operation_lock = threading.Lock()
        self._store = secret_store
        self._transport = transport
        require(re.fullmatch(r"[A-Za-z0-9._/-]{1,100}", secret_prefix), "Invalid secret prefix.")
        self._secret_key = f"{secret_prefix}:{self.origin}"
        if create:
            self.directory.mkdir(parents=True, mode=0o700, exist_ok=True)
        s = self.directory.lstat()
        require(stat.S_ISDIR(s.st_mode) and s.st_uid == os.getuid() and not s.st_mode & 0o077,
                "Wallet directory must be owned by this user with permissions 0700.")
        try:
            fd = os.open(self.directory / ".python.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            self._lock = os.fdopen(fd, "r+")
            ls = os.fstat(fd)
            require(stat.S_ISREG(ls.st_mode) and ls.st_uid == os.getuid() and not ls.st_mode & 0o077, "Unsafe lock file.")
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise WalletError("Wallet is already open in another process.") from None
            require(not (self.directory / "wallet.json").exists() and not (self.directory / "identity.json").exists(),
                    "Use a separate directory for Python; Node wallet migration is not supported.")
            binding = read_private(self.directory / "python-identity.json")
            storage = f"secretStore:{self._secret_key}" if secret_store is not None else "file"
            if binding is not None:
                require(origin_of(binding.get("origin")) == self.origin, "Restore the original origin and storage.")
                # 0.1.0 retained host case/default ports. Reuse its vault key rather
                # than treating normalization as a missing secret or new identity.
                bound_storage = binding.get('storage', '')
                prefix = f'secretStore:{secret_prefix}:'
                if secret_store is not None and bound_storage.startswith(prefix):
                    require(origin_of(bound_storage[len(prefix):]) == self.origin, "Restore the original origin and storage.")
                    self._secret_key = bound_storage[len('secretStore:'):]
                    storage = bound_storage
                require(bound_storage == storage, "Restore the original origin and storage.")
            if secret_store is not None:
                require(not (self.directory / "python-wallet.json").exists(), "File-to-vault migration is not supported.")
                encoded = secret_store.get(self._secret_key)
                self._state = None if encoded is None else json.loads(encoded)
            else:
                self._state = read_private(self.directory / "python-wallet.json")
            if self._state is None:
                require(binding is None and create, "Wallet secret is missing. Restore it; no replacement identity was created.")
                self._state = {"version": 1, "origin": self.origin, "privateKey": "0x" + bytes(Account.create().key).hex()}
                self._save()  # Persist identity before making any network call.
            require(self._state.get("version") == 1 and origin_of(self._state.get("origin")) == self.origin, "Invalid wallet state or service origin.")
            self._state['origin'] = self.origin
            key = self._state.get("privateKey")
            require(isinstance(key, str) and re.fullmatch(r"0x[0-9a-fA-F]{64}", key), "Invalid saved wallet key.")
            self._account = Account.from_key(key)
            if binding is not None:
                require(binding.get("address", "").lower() == self.address.lower(), "Wallet identity changed; restore its original secret.")
            else:
                write_private(self.directory / "python-identity.json", {"origin": self.origin, "storage": storage, "address": self.address})
        except BaseException:
            self.close()
            raise

    @property
    def address(self):
        return self._account.address

    def _save(self):
        if self._store is not None:
            self._store.set(self._secret_key, json.dumps(self._state))
        else:
            write_private(self.directory / "python-wallet.json", self._state)

    def _request(self, path, body=None, *, authenticated=False, method=None):
        require(self._lock is not None, "Wallet is closed.")
        token = self._state.get("apiKey") if authenticated else None
        require(not authenticated or token, "Run bootstrap first.")
        return self._transport(self.origin, path, body, token, method)

    def status(self):
        return {"address": self.address, "network": "eip155:8453", "origin": self.origin,
                "enrolled": bool(self._state.get("apiKey")), "merchant": self._state.get("merchant")}

    def _merchant(self, value):
        require(isinstance(value, dict) and isinstance(value.get("id"), str), "Invalid merchant response.")
        try:
            uuid.UUID(value["id"])
        except ValueError:
            raise WalletError("Invalid merchant UUID.") from None
        require(isinstance(value.get("name"), str) and isinstance(value.get("payoutAddress"), str)
                and value["payoutAddress"].lower() == self.address.lower(), "Merchant payout address does not match wallet.")
        return {k: value[k] for k in ("id", "name", "payoutAddress")}

    def _signature(self, challenge, rotating):
        require(isinstance(challenge, dict), "Invalid challenge.")
        message, cid = challenge.get("message"), challenge.get("challengeId")
        require(isinstance(message, str) and isinstance(cid, str), "Missing challenge message or ID.")
        try:
            uuid.UUID(cid)
        except ValueError:
            raise WalletError("Invalid challenge UUID.") from None
        issued_match = re.search(r"^Issued: (.+)$", message, re.M)
        require(issued_match, "Missing challenge issue time.")
        issued, expires = issued_match[1], challenge.get("expiresAt")
        now = time.time()
        require(now - 300 <= timestamp(issued) <= now + 30 and now < timestamp(expires) <= now + 330
                and 0 < timestamp(expires) - timestamp(issued) <= 300, "Expired or invalid challenge lifetime.")
        proof = challenge.get("transactionProof", {})
        address = proof.get("proofAddress", "")
        require(proof.get("network") == "eip155:8453" and str(proof.get("asset", "")).lower() == USDC
                and re.fullmatch(r"0x[0-9a-fA-F]{40}", address), "Invalid challenge network, asset or proof address.")
        lines = ["402Mob merchant credential rotation" if rotating else "402Mob merchant enrollment",
                 f"Origin: {self.origin}", f"Wallet: {self.address.lower()}"]
        if not rotating:
            lines.append(f"Merchant name: {self._state['name']}")
        expected = "\n".join(lines + [f"Challenge: {cid}", f"Issued: {issued}", f"Expires: {expires}",
                                      f"Transaction proof address: {address}",
                                      "This creates or replaces a merchant API key. It does not authorize a payment."])
        require(message == expected, "Challenge does not match this wallet, origin and purpose.")
        return "0x" + bytes(self._account.sign_message(encode_defunct(text=expected)).signature).hex()

    @exclusive
    def bootstrap(self, name=None):
        require(self._lock is not None, "Wallet is closed.")
        saved = self._state.get("name")
        require(name is None or isinstance(name, str), "Name must be a string.")
        requested = name.strip() if name else None
        require(not saved or not requested or requested == saved, "Wallet already has a different merchant name.")
        name = saved or requested or f"Agent {self.address[2:10]}"
        require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._ -]{0,63}", name), "Use a supported merchant name of 1-64 ASCII characters.")
        self._state["name"] = name
        self._save()
        if self._state.get("apiKey"):
            try:
                result = self._request("/v1/agent/merchant", authenticated=True)
                self._merchant(result.get("merchant"))
                return self.status()
            except ApiError as error:
                if error.status != 401:
                    raise
        rotating = False
        try:
            challenge = self._request("/v1/merchants/enrollment-challenges", {"wallet": self.address, "name": name})
        except ApiError as error:
            if error.status != 409 or error.code != "merchant_wallet_registered":
                raise
            rotating = True
            challenge = self._request("/v1/merchants/credential-challenges", {"wallet": self.address})
        signature = self._signature(challenge, rotating)
        body = {"wallet": self.address, "challengeId": challenge["challengeId"], "signature": signature}
        if not rotating:
            body["name"] = name
        result = self._request("/v1/merchants/credentials/rotate" if rotating else "/v1/merchants/enrollments", body)
        require(isinstance(result, dict), "Invalid enrollment response; retry bootstrap to recover.")
        merchant = self._merchant(result.get("merchant"))
        key = result.get("apiKey")
        require(isinstance(key, str) and re.fullmatch(r"402mob_agent_[A-Za-z0-9_-]{43}", key), "Missing merchant credential; retry bootstrap to recover.")
        self._state.update(apiKey=key, merchant=merchant)
        self._save()
        return self.status()

    @exclusive
    def publish(self, offer):
        require(isinstance(offer, dict), "Offer must be a JSON object.")
        return self._request("/v1/agent/merchant/offers", offer, authenticated=True, method="POST")

    @exclusive
    def discovery(self, enabled):
        require(type(enabled) is bool, "Discovery must be boolean.")
        return self._request("/v1/agent/merchant/discovery", {"discoverable": enabled}, authenticated=True, method="PUT")

    def close(self):
        require(self._operation_lock.acquire(blocking=False), "Wallet operation is active; wait before closing.")
        try:
            if self._lock is not None:
                self._lock.close()  # Advisory lock releases even after a process crash.
                self._lock = None
        finally:
            self._operation_lock.release()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def main():
    parser = argparse.ArgumentParser(description="Create a local EOA and enroll with 402Mob.")
    parser.add_argument("command", choices=("bootstrap", "status"))
    parser.add_argument("--dir", required=True, help="Persistent private directory; separate from the Node wallet")
    parser.add_argument("--origin", default="https://evidence.contact")
    parser.add_argument("--name")
    args = parser.parse_args()
    try:
        require(args.command == "bootstrap" or args.name is None, "--name applies only to bootstrap.")
        with AgentWallet(args.dir, args.origin, create=args.command == "bootstrap") as wallet:
            result = wallet.bootstrap(args.name) if args.command == "bootstrap" else wallet.status()
            print(json.dumps(result))
    except Exception as error:
        # Only expose fixed local messages; never remote payloads, credentials or state.
        message = str(error) if isinstance(error, WalletError) else "Wallet command failed; retain the directory and retry after checking connectivity and storage."
        print(json.dumps({"error": "wallet_error", "message": message}), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    if sys.argv[1:] == ['--internal-http']:
        _http_worker()
    else:
        sys.exit(main())
