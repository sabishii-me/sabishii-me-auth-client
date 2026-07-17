# @sabishii-me/auth-client

Native Rust/N-API client for Sabishii.me OAuth device authorization.

## Security

- Pass the account origin, such as `https://account.sabishii.me`; do not append `/auth`.
- Plain HTTP is accepted only for loopback development addresses.
- Auth state is stored in the operating-system keyring, isolated by normalized account origin and client ID.
- Device codes, access tokens, and refresh tokens must not be logged.
- Refresh tokens are rotated after use.

## Node.js API

```ts
import { SabishiiAuth } from '@sabishii-me/auth-client'

const auth = new SabishiiAuth(
  'https://account.sabishii.me',
  'sabishii-account-cli',
)

const device = await auth.requestDeviceCode()
// Display device.verificationUriComplete or verificationUri + userCode.
const token = await auth.pollForDeviceToken(device)
```

`pollForDeviceToken` requires the complete server response so its expiry and polling interval are preserved. The code-only `pollForToken` method remains temporarily available for 0.1 compatibility and is deprecated. `logout()` clears the local keyring entry first and returns whether remote refresh-token revocation was confirmed. Remote refresh-token revocation prevents future refreshes; access-session tokens already issued from that lineage remain valid until their own expiry or separate session revocation.

See `index.d.ts` for the complete API.
