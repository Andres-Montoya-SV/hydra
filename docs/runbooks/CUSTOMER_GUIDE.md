# Getting Started with Hydra

Hydra maps your organization's external attack surface: the domains,
hosts, services and certificates that are reachable from the internet. It
shows what is exposed, explains why with evidence, and keeps watching for
changes.

You can use Hydra with any HTTP client, or with the small command-line
client shown in this guide. The full list of endpoints is in the
[API reference](../API_REFERENCE.md).

## Before you start

- **The API address.** Your Hydra contact gives you the API address. Set
  it once:

  ```sh
  export HYDRA_API_URL=https://api.example.com
  ```

- **The command-line client** needs only Python 3.10 or later:

  ```sh
  python -m hydra_client --help
  ```

  Every command prints the API's JSON response. A plain HTTP client works
  just as well; each step below names the endpoint.
- **You can only scan what you own.** Hydra scans a domain only after you
  prove you control it. Nothing, including a paid plan, lets you scan
  someone else's domain.

## 1. Create your account

```sh
python -m hydra_client signup you@yourcompany.com --save-key ~/.hydra-key
```

- **Endpoint:** `POST /accounts`.
- **Your API key** is shown only once. `--save-key` writes it to a file
  that only you can read.
- **Using the key.** Pass the file with `--key-file ~/.hydra-key`, or set
  `HYDRA_API_KEY`. Don't put the key on the command line.

Then confirm your email. The email contains a token:

```sh
python -m hydra_client --key-file ~/.hydra-key verify-email <token>
```

The endpoint is `POST /accounts/verify-email`. If the token expired, use
`POST /accounts/resend-verification`.

## 2. Explore the demo while you set up

```sh
python -m hydra_client --key-file ~/.hydra-key demo
```

- **What it is.** `POST /demo/organization` gives you an organization
  full of sample data on reserved example domains. You can browse assets,
  exposures, evidence and changes before your own data arrives.
- **Read-only.** You can't change it or scan it, and it doesn't count
  against your plan.
- Delete it when you're done: `DELETE /organizations/{id}`.

```sh
python -m hydra_client --key-file ~/.hydra-key exposures <demo-organization-id>
```

## 3. Verify a domain you own

```sh
python -m hydra_client --key-file ~/.hydra-key domain-add yourcompany.com
```

- **Endpoint:** `POST /domains`.
- **Instructions.** The response says exactly what to publish: a DNS TXT
  record, or a file at `/.well-known/`.
- **Check.** Once it's published:

  ```sh
  python -m hydra_client --key-file ~/.hydra-key domain-verify yourcompany.com
  ```

  The endpoint is `POST /domains/{domain}/verify`, with `--method dns_txt`
  (the default) or `--method well_known_file`.
- **Subdomains.** A verified domain covers its subdomains.
- **Expiry.** A verification expires. Verify again before then, and
  monitoring keeps going.

## 4. Run your first scan

```sh
python -m hydra_client --key-file ~/.hydra-key scan yourcompany.com
python -m hydra_client --key-file ~/.hydra-key scan-wait <scan_id>
```

- **Starting it.** `POST /scans` queues the scan, and `scan-wait` polls
  `GET /scans/{id}` until it finishes.
- **Quota.** Each scan counts against your monthly quota.
- **`--profile passive`** runs passive collection only.

## 5. See what you have and what is exposed

Find your organization with `orgs` (`GET /organizations`), then:

```sh
python -m hydra_client --key-file ~/.hydra-key assets <organization-id>
python -m hydra_client --key-file ~/.hydra-key exposures <organization-id>
```

- **Assets** are what Hydra found and why it believes they're yours.
- **Exposures** are security findings on those assets, with their
  severity and status.
- **Evidence.** Each exposure explains itself. For example:

  ```sh
  python -m hydra_client --key-file ~/.hydra-key call GET \
      /organizations/<organization-id>/exposures/<exposure-id>/evidence
  ```

- **Priority.** `GET .../exposures/{id}/risk` explains an exposure's
  priority: which facts raised or lowered it, and which are unknown.

## 6. Work the findings

- **Resolve** an exposure when it's fixed, with a reason:

  ```sh
  python -m hydra_client --key-file ~/.hydra-key exposure-resolve <org> <exposure> --reason "Moved behind the VPN"
  ```

- **Reopening.** If a later scan sees it again, Hydra reopens it, and the
  history keeps both events.
- **Remediation.** `.../exposures/{id}/remediation` lets you:
  - assign a teammate, set a due date and link a ticket;
  - add comments;
  - move it through triage, in progress, fixed, false positive, or
    accepted risk (with a reason and an end date).

  Accepting a risk never deletes the evidence.
- **Ticketing.** Connect Jira, Linear or ServiceNow, or signed webhooks,
  Slack and Teams, to receive changes where you already work. See the
  integrations section of the [API reference](../API_REFERENCE.md).

## 7. Keep watching

```sh
python -m hydra_client --key-file ~/.hydra-key monitor yourcompany.com
```

- **Daily.** `POST /domains/{domain}/monitoring` turns on daily passive
  monitoring. You get an alert when something significant changes: new or
  removed hosts, new exposures, certificate or technology changes.
- **Weekly active scans** (`--speed2`) are part of the higher plans.

## When something doesn't work

- **Errors.** Every error has a stable `code`, a readable `message`, a
  `request_id`, and `retryable`. The client prints all of them. The codes
  are listed in the
  [error-code table](../productization/13a_errors_and_diagnostics.md#codes).
- **Retrying.** Retry only when `retryable` is true, after the
  `Retry-After` seconds when given. Don't blindly repeat `POST /scans`:
  each call creates and counts a scan. After a timeout, check your recent
  scans first.
- **Diagnostics.** Run `python -m hydra_client --key-file ~/.hydra-key
  diagnostics` (`GET /account/diagnostics`). It lists plain-language
  hints, for example "Email not verified" or "This month's scans are used
  up", plus your last scans and their errors. It's safe to share with
  support: it never contains your key.
- **Contacting support.** Quote the `request_id` of the failing request.
- **Feedback.** Tell us what's missing or confusing:

  ```sh
  python -m hydra_client --key-file ~/.hydra-key feedback idea "Your message"
  ```

  The endpoint is `POST /feedback`. Categories: `bug`, `idea`,
  `question`, `other`.

## Your data

- **Exporting.** `GET /account/export` returns what Hydra holds about
  your account. `GET /organizations/{id}/export` returns an
  organization's data as one archive.
- **Deleting.** `DELETE /account` or `DELETE /organizations/{id}`
  schedules deletion after a 30-day grace period. You can cancel it until
  then.
- **Your plan.** `GET /account/subscription` shows your plan, its limits
  and what you've used. If you go over a limit, the error says which plan
  raises it.
