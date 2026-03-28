# NAPI Bindings & Endpoint Updates TODO

## Issues Found

### 1. Endpoint Paths Don't Match Current Server

**Current (in this library):**
- `/device/code`
- `/device/token`  
- `/device/refresh`
- `/device/revoke`

**Should be (server actual endpoints):**
- `/auth/device` (POST - start device flow)
- `/auth/device/token` (POST - poll for token)
- `/auth/device/refresh` (POST - refresh token)
- `/auth/device/revoke` (POST - revoke token)

**Note:** The `/auth` prefix is part of better-auth's routing.

### 2. Add NAPI-RS Bindings for Node.js

**Goal:** Allow TypeScript/Node.js projects to use this Rust library natively.

**Steps:**
1. Add dependencies to `Cargo.toml`:
   ```toml
   [dependencies]
   napi = "2"
   napi-derive = "2"
   
   [build-dependencies]
   napi-build = "2"
   ```

2. Add `[lib]` section:
   ```toml
   [lib]
   crate-type = ["cdylib", "rlib"]
   ```

3. Create `src/napi.rs` with Node.js bindings for:
   - `login(baseUrl, clientId, appName)` 
   - `logout(baseUrl, clientId, appName)`
   - `refresh(baseUrl, clientId, appName)`
   - `loadState(appName)`
   - `isTokenExpired(state)`
   - `getUserProfile(baseUrl, appName)`

4. Create `package.json`:
   ```json
   {
     "name": "@sabishii-me/auth-client",
     "version": "0.2.0",
     "main": "index.js",
     "types": "index.d.ts",
     "napi": {
       "name": "sabishii-auth",
       "triples": {
         "defaults": true
       }
     },
     "scripts": {
       "build": "napi build --platform --release",
       "build:debug": "napi build --platform"
     },
     "devDependencies": {
       "@napi-rs/cli": "^2.0.0"
     }
   }
   ```

5. Auto-generate TypeScript types with `#[napi]` macros

### 3. Test Against Current Account Service

**Test endpoints:**
- Dev: `https://account.sabishii.dev`
- Testing: `https://account-testing.sabishii.me`
- Production: `https://account.sabishii.me`

**Test flow:**
```bash
# Build with NAPI bindings
npm run build

# Test login flow
node -e "
  const auth = require('.');
  auth.login('https://account.sabishii.dev/auth', 'test-cli', 'test-app')
    .then(() => console.log('Success!'))
    .catch(console.error);
"
```

## Priority

1. **HIGH:** Fix endpoint paths (breaks existing CLI)
2. **MEDIUM:** Add NAPI bindings (enables TypeScript usage)
3. **LOW:** Add more comprehensive tests

## References

- NAPI-RS docs: https://napi.rs/
- Current account service: `https://github.com/sabishii-me/sabishii-me-account`
- Endpoint spec: Check `apps/backend/src/routers/auth/` in account service repo
