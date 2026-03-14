import json
import hashlib
from pathlib import Path
from typing import Any, Dict, List


class JSONExporter:
    def __init__(self, accounts: List[Dict[str, Any]], extracted_files: List[Path] = None):
        self.accounts = accounts
        self.extracted_files = extracted_files or []

    def _hash_file(self, file_path: Path) -> str:
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                sha256.update(chunk)
        return sha256.hexdigest()

    def export(self, output_path: Path) -> None:
        report = {
            'accounts': [],
            'extracted_files': [],
            'summary': {
                'total_accounts': len(self.accounts),
                'total_files': len(self.extracted_files)
            }
        }

        for acc in self.accounts:
            account_data = {
                'account_dir': acc.get('account_dir'),
                'user_id': acc.get('user_id'),
                'dc_id': acc.get('dc_id'),
                'has_passcode': acc.get('has_passcode', False),
                'auth_key_ids': {}
            }
            for dc_id, key in acc.get('auth_keys', {}).items():
                sha1_hash = hashlib.sha1(key).digest()
                account_data['auth_key_ids'][str(dc_id)] = sha1_hash[-8:].hex()
            report['accounts'].append(account_data)

        for file_path in self.extracted_files:
            if file_path.exists():
                report['extracted_files'].append({
                    'name': file_path.name,
                    'size': file_path.stat().st_size,
                    'sha256': self._hash_file(file_path)
                })

        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
