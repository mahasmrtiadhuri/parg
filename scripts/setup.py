"""Create local-only demo configuration. Existing files are never overwritten."""
import os
from pathlib import Path
import secrets

path = Path('.env')
content = f'''PARG_WORKER_TOKEN={secrets.token_hex(32)}
PARG_CORE_TOKEN={secrets.token_hex(32)}
POSTGRES_PASSWORD={secrets.token_hex(24)}
PARG_TARGET_ID=33333333-3333-4333-8333-333333333333
PARG_PRINCIPAL_ID=11111111-1111-4111-8111-111111111111
PARG_SOURCE_ID=aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa
PARG_DEST_ID=bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb
'''
try:
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w') as stream:
        stream.write(content)
    print('Created .env with fresh local demo credentials. Do not commit it.')
except FileExistsError:
    print('Existing .env preserved.')
