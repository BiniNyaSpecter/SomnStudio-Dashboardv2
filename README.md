# SOMN Studio OS — Dashboard (Vercel version)

This is the same dashboard, restructured to run as a Vercel serverless
function instead of an always-on Node process. The design, pages, and
auth behavior are the same as the standalone version — only the plumbing
underneath changed, because Vercel doesn't run a persistent server.

If you're deploying to Render, Railway, SnapDeploy, or a VPS instead, use
the other build (`server.js` + `npm start`) — this folder is Vercel-only.

## Deploying

1. Push this folder to a GitHub repo (or the repo root, if this is the
   whole repo).
2. In Vercel, **Add New → Project**, import that repo.
3. Framework preset: leave as **Other** — there's nothing to detect,
   which is correct.
4. Before your first deploy, add two **Environment Variables** (Project
   Settings → Environment Variables):

   | Name | Value |
   |---|---|
   | `DASHBOARD_PASSWORD` | your real studio password |
   | `SESSION_SECRET` | a random string — generate one below |

   Generate `SESSION_SECRET` locally:
   ```bash
   node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
   ```
   Paste the output in as the value. Apply both variables to
   Production (and Preview, if you want preview deployments to work too).

   **Want more than one valid password?** There's still no username —
   just a set of passwords anyone can use to get in. Use
   `DASHBOARD_PASSWORDS` (with an S) instead, comma-separated:

   | Name | Value |
   |---|---|
   | `DASHBOARD_PASSWORDS` | `aki-2026,hana-2026,kenji-2026` |
   | `SESSION_SECRET` | a random string — generate one above |

5. Deploy. You'll land on `/`, which redirects to `/login`.

If you skip step 4 and don't set `DASHBOARD_PASSWORD`(S) / `SESSION_SECRET`,
the app still runs — the password falls back to `change-me-now` and the
session secret is derived from whatever password(s) are set. It'll work,
but change the password before sharing the link with anyone.

## Why this needed restructuring (and what's different from the Node version)

Vercel doesn't run a long-lived process — your code only exists for the
duration of a single request, then the container may be frozen or thrown
away entirely. Two consequences worth knowing about:

**No disk to remember things across requests.** The standalone version
auto-generates a session secret and saves it to `data/.session-secret` so
sessions survive restarts. Vercel's filesystem doesn't persist that way,
so this version reads `SESSION_SECRET` from an environment variable
instead. Set it once in Vercel's dashboard and it stays stable across
every deploy and every cold start.

**Rate limiting is per-instance, not global.** Vercel can run several
copies of this function at once under load, each with its own memory.
The login-attempt counter lives in memory, so it's tracked separately per
instance rather than one shared count — still slows down casual
password-guessing, just not as strictly as the single-process versions
(Render, a VPS) where there's only one counter, period. For a small
shared-password studio tool this is a reasonable tradeoff; if you need
stricter guarantees, that requires an external store (e.g. Vercel KV or
Upstash Redis) — happy to add that if it matters to you.

Everything else — the page rendering, the 5 designed screens, the
password check, the session cookie, the "Coming Soon" placeholders, the
Reports chart fix — is identical to the standalone version.

## Local testing

You don't strictly need the Vercel CLI to sanity-check this — any tool
that calls the exported function with a Node request/response pair works,
since `api/index.js` exports a plain `(req, res) => {}` handler. If you do
have the Vercel CLI installed:

```bash
vercel dev
```

## Changing the password(s) later

Update the `DASHBOARD_PASSWORD` (or `DASHBOARD_PASSWORDS`) environment
variable in Vercel's project settings, then redeploy (Vercel → Deployments
→ Redeploy). Because the
session-signing key is derived in part from the password hash, this
automatically signs out everyone using the old password.

## File structure

```
vercel.json          — routes every request to api/index.js
package.json
config.json           — optional local fallback for the password (env vars win)
public/
  app.js               — sidebar logout button (served directly by Vercel)
  login.js              — login form handling (served directly by Vercel)
api/
  index.js               — the entire backend: routing, auth, rendering
  views/
    head.html              — shared <head> — unedited from the original design
    header.html              — shared top bar — unedited
    logo_block.html            — sidebar logo — unedited
    profile_block.html           — sidebar profile card (logout button added)
    login.html                    — login screen
    error.html                     — 404 page
    nav_structure.json               — sidebar sections/links
    pages/
      overview.html                    — unedited
      projects.html                     — unedited
      feedback.html                      — unedited
      workload.html                       — unedited
      reports.html                         — one bug fix (invisible chart bars)
      coming-soon.html                      — placeholder for unbuilt sections
```
