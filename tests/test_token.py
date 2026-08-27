import importlib.util
import os


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_guitoken_prints_plain_token_and_writes_hash(tmp_path, monkeypatch):
    script = load_module('guitoken', '/Users/sab/Documents/project/WebMap/guitoken.py')

    plain_path = tmp_path / 'token.plain'
    hash_path = tmp_path / 'token.sha256'
    monkeypatch.setattr(script, 'TOKEN_FILE', str(plain_path))
    monkeypatch.setattr(script, 'TOKEN_HASH_FILE', str(hash_path))

    token = script.generate_token()
    assert token.isalnum()
    assert len(token) == 12

    script.write_token(token)

    assert plain_path.read_text().strip() == token
    assert hash_path.exists()
    assert script.verify_token(token, hash_path.read_text().strip()) is True
