## Running the script

```sh
python -m app.main
```

## Security assumptions
- After master key is computed between server and client, the encryption key and mac key are derived using the *derive_keys_from_master* helper security function
- These are stored in the session and used for future message exchange until websocket disconnect