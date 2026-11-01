import json
import os
import tempfile
import threading
import time
import unittest
import uuid
from datetime import datetime, timezone
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from eth_account import Account
from eth_account.messages import encode_defunct
from mob402_wallet import AgentWallet, ApiError, WalletError, USDC, origin_of, request_json


def iso(value):
    return datetime.fromtimestamp(value, timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


class Server:
    def __init__(self):
        self.registered = False
        self.token = "402mob_agent_" + "x" * 43
        self.merchant_id = str(uuid.uuid4())
        self.challenges = {}
        self.bad_message = False
        self.lose_completion = False
        self.calls = []

    def __call__(self, origin, path, body, token, method):
        self.calls.append(path)
        if path == "/v1/agent/merchant":
            if token != self.token:
                raise ApiError(401, "invalid_api_key")
            return {"merchant": self.merchant}
        if path.endswith("enrollment-challenges") or path.endswith("credential-challenges"):
            rotating = path.endswith("credential-challenges")
            if self.registered and not rotating:
                raise ApiError(409, "merchant_wallet_registered")
            now = time.time()
            cid, issued, expires = str(uuid.uuid4()), iso(now), iso(now + 300)
            address = "0x" + "12" * 20
            lines = ["402Mob merchant credential rotation" if rotating else "402Mob merchant enrollment",
                     f"Origin: {origin}", f"Wallet: {body['wallet'].lower()}"]
            if not rotating:
                lines.append(f"Merchant name: {body['name']}")
            msg = "\n".join(lines + [f"Challenge: {cid}", f"Issued: {issued}", f"Expires: {expires}",
                                   f"Transaction proof address: {address}",
                                   "This creates or replaces a merchant API key. It does not authorize a payment."])
            self.challenges[cid] = msg
            return {"challengeId": cid, "expiresAt": expires, "message": msg + ("\nextra" if self.bad_message else ""),
                    "transactionProof": {"network": "eip155:8453", "asset": USDC, "proofAddress": address}}
        if path.endswith("enrollments") or path.endswith("credentials/rotate"):
            recovered = Account.recover_message(encode_defunct(text=self.challenges[body['challengeId']]), signature=body['signature'])
            assert recovered.lower() == body['wallet'].lower()
            self.registered = True
            self.merchant = {"id": self.merchant_id, "name": body.get("name", "Python Agent"), "payoutAddress": body['wallet'].lower()}
            if self.lose_completion:
                self.lose_completion = False
                raise TimeoutError()
            return {"merchant": self.merchant, "apiKey": self.token}
        raise AssertionError(path)


class WalletTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name) / "wallet"
        self.server = Server()

    def wallet(self, **kwargs):
        return AgentWallet(self.directory, transport=self.server, **kwargs)

    def test_enroll_reopen_and_secret_privacy(self):
        with self.wallet(create=True) as wallet:
            status = wallet.bootstrap("Python Agent")
            self.assertTrue(status['enrolled'])
            self.assertEqual(status['address'].lower(), status['merchant']['payoutAddress'])
            self.assertNotIn(self.server.token, json.dumps(status))
        with self.wallet() as wallet:
            self.assertEqual(wallet.bootstrap()['address'], status['address'])
        self.assertEqual(self.server.calls.count('/v1/merchants/enrollments'), 1)
        self.assertEqual(self.directory.stat().st_mode & 0o777, 0o700)
        self.assertEqual((self.directory / 'python-wallet.json').stat().st_mode & 0o777, 0o600)

    def test_lost_response_recovers_same_identity(self):
        self.server.lose_completion = True
        with self.wallet(create=True) as wallet:
            address = wallet.address
            with self.assertRaises(TimeoutError):
                wallet.bootstrap('Python Agent')
        with self.wallet() as wallet:
            self.assertEqual(wallet.bootstrap()['address'], address)
        self.assertIn('/v1/merchants/credentials/rotate', self.server.calls)

    def test_changed_challenge_never_submitted(self):
        self.server.bad_message = True
        with self.wallet(create=True) as wallet:
            with self.assertRaises(WalletError):
                wallet.bootstrap('Python Agent')
        self.assertFalse(self.server.registered)

    def test_missing_file_secret_never_replaced(self):
        with self.wallet(create=True):
            pass
        (self.directory / 'python-wallet.json').unlink()
        with self.assertRaises(WalletError):
            self.wallet(create=True)
        self.assertFalse((self.directory / 'python-wallet.json').exists())

    def test_lock_and_closed_wallet(self):
        with self.wallet(create=True) as wallet:
            with self.assertRaises(WalletError):
                self.wallet()
        with self.assertRaises(WalletError):
            wallet.bootstrap()
        with self.wallet():
            pass

    def test_vault_binding_and_missing_secret(self):
        class Vault:
            data = {}
            def get(self, key): return self.data.get(key)
            def set(self, key, value): self.data[key] = value
        vault = Vault()
        with self.wallet(create=True, secret_store=vault) as wallet:
            address = wallet.bootstrap('Python Agent')['address']
        with self.wallet(secret_store=vault) as wallet:
            self.assertEqual(wallet.address, address)
        vault.data.clear()
        with self.assertRaises(WalletError):
            self.wallet(create=True, secret_store=vault)

    def test_node_state_and_unsafe_permissions_refused(self):
        self.directory.mkdir(mode=0o700)
        (self.directory / 'wallet.json').write_text('{}')
        with self.assertRaises(WalletError):
            self.wallet(create=True)
        (self.directory / 'wallet.json').unlink()
        os.chmod(self.directory, 0o755)
        with self.assertRaises(WalletError):
            self.wallet(create=True)

    def test_status_never_creates(self):
        with self.assertRaises(FileNotFoundError):
            self.wallet()
        self.assertFalse(self.directory.exists())

    def test_concurrent_operations_and_close_cannot_release_wallet(self):
        entered, release = threading.Event(), threading.Event()
        errors = []
        def delayed(*args):
            result = self.server(*args)
            if args[1] == '/v1/merchants/enrollments':
                entered.set();release.wait(10)
            return result
        with AgentWallet(self.directory,create=True,transport=delayed) as wallet:
            def enroll():
                try: wallet.bootstrap('Python Agent')
                except Exception as error: errors.append(error)
            thread=threading.Thread(target=enroll)
            thread.start()
            try:
                self.assertTrue(entered.wait(5))
                for action in [lambda:wallet.bootstrap('Python Agent'),wallet.close,
                               lambda:wallet.publish({}),lambda:wallet.discovery(True)]:
                    with self.assertRaises(WalletError): action()
                with self.assertRaises(WalletError): self.wallet()
            finally:
                release.set();thread.join(5)
            self.assertFalse(thread.is_alive());self.assertEqual(errors,[])
            self.assertTrue(wallet.bootstrap()['enrolled'])
        with self.wallet() as reopened:
            self.assertTrue(reopened.bootstrap()['enrolled'])

    def test_equivalent_origins_enroll_and_reopen_same_identity(self):
        with AgentWallet(self.directory,'https://EVIDENCE.CONTACT:443/',create=True,transport=self.server) as wallet:
            first=wallet.bootstrap('Python Agent')
            self.assertEqual(wallet.origin,'https://evidence.contact')
        with self.wallet() as wallet:
            self.assertEqual(wallet.bootstrap(),first)
        self.assertEqual(origin_of('http://LOCALHOST:80/'),'http://localhost')
        self.assertEqual(origin_of('http://[::1]:80'),'http://[::1]')
        self.assertEqual(origin_of('https://example.com:8443'),'https://example.com:8443')
        with self.assertRaises(WalletError): origin_of('https://example.com:bad')

    def test_legacy_origin_in_file_and_vault_preserves_identity(self):
        class Vault:
            def __init__(self): self.data={}
            def get(self,key): return self.data.get(key)
            def set(self,key,value): self.data[key]=value
        for use_vault in [False,True]:
            directory=Path(self.tmp.name)/('legacy-vault' if use_vault else 'legacy-file')
            vault=Vault() if use_vault else None
            with AgentWallet(directory,create=True,secret_store=vault) as wallet:
                address=wallet.address
            legacy_origin='https://EVIDENCE.CONTACT:443'
            marker=directory/'python-identity.json'
            binding=json.loads(marker.read_text());binding['origin']=legacy_origin
            if vault:
                old_key=next(iter(vault.data));encoded=vault.data.pop(old_key)
                legacy_key='402mob/python-wallet:'+legacy_origin
                state=json.loads(encoded);state['origin']=legacy_origin
                vault.data[legacy_key]=json.dumps(state);binding['storage']='secretStore:'+legacy_key
            else:
                state_path=directory/'python-wallet.json'
                state=json.loads(state_path.read_text());state['origin']=legacy_origin
                state_path.write_text(json.dumps(state))
            marker.write_text(json.dumps(binding))
            with AgentWallet(directory,secret_store=vault) as wallet:
                self.assertEqual(wallet.address,address)
                self.assertEqual(wallet.origin,'https://evidence.contact')
                wallet._save()
            if vault:
                self.assertEqual(list(vault.data),[legacy_key])

    def test_publish_rejects_non_object_and_uses_post(self):
        calls=[]
        def record(*args): calls.append(args);return {'id':'fixture'}
        with AgentWallet(self.directory,create=True,transport=record) as wallet:
            wallet._state['apiKey']='fixture-token'
            for value in [None,[],False,'text',1]:
                with self.assertRaises(WalletError): wallet.publish(value)
            self.assertEqual(calls,[])
            wallet.publish({'title':'Example'})
            self.assertEqual(calls[0][4],'POST')

    def test_total_deadline_bounds_headers_success_and_error_trickle(self):
        seen=threading.Event()
        class Handler(BaseHTTPRequestHandler):
            def log_message(self,*args): pass
            def do_GET(self):
                seen.set()
                try:
                    if self.path=='/headers': time.sleep(3)
                    self.send_response(500 if self.path=='/error' else 200)
                    body=b'"'+b'x'*40+b'"'
                    self.send_header('Content-Length',str(len(body)));self.end_headers()
                    for byte in body:
                        self.wfile.write(bytes([byte]));self.wfile.flush();time.sleep(.1)
                except (BrokenPipeError,ConnectionResetError): pass
        server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
        threading.Thread(target=server.serve_forever,daemon=True).start()
        try:
            for route in ['/headers','/body','/error']:
                seen.clear();start=time.monotonic()
                with self.assertRaisesRegex(WalletError,'deadline exceeded'):
                    request_json(f'http://127.0.0.1:{server.server_port}',route,timeout=1.5)
                self.assertTrue(seen.is_set())
                self.assertLess(time.monotonic()-start,2.5)
        finally: server.shutdown();server.server_close()

    def test_altered_signing_fields_rejected(self):
        with self.wallet(create=True) as wallet:
            wallet._state['name'] = 'Python Agent'
            c = self.server(wallet.origin, '/v1/merchants/enrollment-challenges', {'wallet': wallet.address, 'name': 'Python Agent'}, None, None)
            for change in [
                lambda v: v.update(challengeId=str(uuid.uuid4())),
                lambda v: v.update(expiresAt=iso(time.time()-1)),
                lambda v: v.update(message=v['message'].replace(wallet.origin, 'https://wrong.invalid')),
                lambda v: v.update(message=v['message'].replace(wallet.address.lower(), '0x'+'11'*20)),
                lambda v: v.update(message=v['message'].replace('Python Agent', 'Other Agent')),
                lambda v: v['transactionProof'].update(network='eip155:1'),
                lambda v: v['transactionProof'].update(asset='0x'+'11'*20),
            ]:
                altered=json.loads(json.dumps(c));change(altered)
                with self.assertRaises(WalletError):
                    wallet._signature(altered, False)
            with self.assertRaises(WalletError):
                wallet._signature(c, True)


if __name__ == '__main__':
    unittest.main()
