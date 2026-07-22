# x-IAM
A small role-based access control (IAM) engine, built as a learning project. Users authenticate with a salted, hashed password (PBKDF2), and their role is checked against a hierarchical resource tree to decide whether they can access a given resource. Every access attempt is written to an audit log.

## Features

- **Password security**: PBKDF2-HMAC-SHA256 with a unique random salt per user, constant-time comparison on login.
- **Hierarchical permissions**: resources can be nested (e.g. `Alpha_Mock_DB` under `Local_Sandbox_Testing`); a role granted access to a parent resource inherits access to its children.
- **Persistent storage**: users and resources are (de)serialized to/from JSON.
- **Audit logging**: every access attempt (allowed or denied) is timestamped and written to `audit_log.txt`.
- **CLI**: simple menu-driven interface in `main.py` (login, request resource access, view audit log as Admin).

## Project structure

```
models.py    # User, Resource, StorageManager, AccessEngine
config.py    # SYSTEM_PERMISSIONS — maps roles to the resources they can access
main.py      # CLI entry point
test.py      # test suite
users.json   # generated at runtime, not committed (see below)
audit_log.txt # generated at runtime, not committed (see below)
```

## Requirements

Python 3.9+, standard library only — no dependencies to install.

## Running it

```bash
python main.py
```

You'll get a menu to log in, request access to a resource, or (as an Admin) view the audit log.

## Running the tests

```bash
python test.py
```

or, with pytest installed:

```bash
python -m pytest test.py -v
```

## Notes

- `users.json` and `audit_log.txt` are runtime-generated data, not source code — they're listed in `.gitignore` and shouldn't be committed. You'll need to seed your own `users.json` locally (create `User` objects and save them with `StorageManager.save_objects_to_json`) before `main.py` will have anyone to log in as.
- Roles are defined in `config.py`'s `SYSTEM_PERMISSIONS`; a user's `role` field in `users.json` must match a key there to be granted any access.