# Cybersec Hub

Talks on cryptography and cybersecurity by [zevaryx](https://github.com/zevaryx), built as websites. Each talk is a slide deck and a set of live demos in one page: every cipher, hash and key exchange on the slides runs in your browser as you click through.

**Live hub: <https://zevaryx.github.io/cybersec-hub/>** · You're welcome to present these talks yourself; see the license below.

## Talks

Start with **Crypto 101**: every track builds on it. Then pick the track that fits you and take its talks in order.

- **General**: for everyone; protecting yourself, your accounts and your data
- **Developer**: for people who write and ship code
- **Security**: for IT and security professionals

| Order | Talk | Level | Length | Link |
| --- | --- | --- | --- | --- |
| Start here | **Crypto 101: Intro to Cryptography** | Beginner | about 2 hours | [Slides](https://zevaryx.github.io/cybersec-hub/talks/crypto-101/) |
| General 1 | **Passwords and Accounts, done properly** | Beginner | about 70 minutes | [Slides](https://zevaryx.github.io/cybersec-hub/talks/passwords-and-accounts/) |
| General 2 | **How HTTPS Really Works** | Beginner | about 90 minutes | [Slides](https://zevaryx.github.io/cybersec-hub/talks/how-https-works/) |
| General 3 | **Phishing and Scams in the Age of AI** | Beginner | about 60 minutes | [Slides](https://zevaryx.github.io/cybersec-hub/talks/phishing-and-scams/) |
| Developer 1 | **Security Habits for New Developers** | Beginner | about 70 minutes | [Slides](https://zevaryx.github.io/cybersec-hub/talks/security-habits/) |
| Security 1 | **Identity and Access Management** | Intermediate | about 80 minutes | [Slides](https://zevaryx.github.io/cybersec-hub/talks/identity-and-access/) |
| Developer 2 | **Git and GitHub Security** | Beginner to intermediate | about 70 minutes | [Slides](https://zevaryx.github.io/cybersec-hub/talks/git-github-security/) |
| Developer 3 | **Using Crypto Correctly in Code** | Intermediate | about 110 minutes | [Slides](https://zevaryx.github.io/cybersec-hub/talks/crypto-in-code/) |
| Security 2 | **Cloud Security Fundamentals** | Intermediate | about 90 minutes | [Slides](https://zevaryx.github.io/cybersec-hub/talks/cloud-security/) |
| Security 3 | **Public Key Infrastructure in Depth** | Intermediate | about 90 minutes | [Slides](https://zevaryx.github.io/cybersec-hub/talks/pki-in-depth/) |
| General 4 | **Your Phone, Safely** | Beginner | about 55 minutes | [Slides](https://zevaryx.github.io/cybersec-hub/talks/mobile-safety/) |
| Developer 4 | **Web Application Security Essentials** | Intermediate | about 2 hours | [Slides](https://zevaryx.github.io/cybersec-hub/talks/web-app-security/) |
| Security 4 | **Vulnerability and Patch Management** | Intermediate | about 90 minutes | [Slides](https://zevaryx.github.io/cybersec-hub/talks/vulnerability-management/) |
| General 5 | **Securing Your Home Network** | Beginner | about 70 minutes | [Slides](https://zevaryx.github.io/cybersec-hub/talks/home-network/) |
| General 6 | **Backups and Ransomware** | Beginner | about 55 minutes | [Slides](https://zevaryx.github.io/cybersec-hub/talks/backups-and-ransomware/) |
| General 7 | **Privacy Tools Explained** | Beginner | about 80 minutes | [Slides](https://zevaryx.github.io/cybersec-hub/talks/privacy-tools/) |
| General 8 | **Modern Messaging Protocols** | Intermediate | about 90 minutes | [Slides](https://zevaryx.github.io/cybersec-hub/talks/modern-messaging/) |
| General 9 | **Zero-Knowledge Proofs** | Advanced | about 95 minutes | [Slides](https://zevaryx.github.io/cybersec-hub/talks/zero-knowledge-proofs/) |


**Cyber in the News** is a monthly roundup for every track, outside the sequence: the month's security stories, the idea behind each, and what to do. Every story slide lists its sources. All episodes are listed at <https://zevaryx.github.io/cybersec-hub/news/>, sortable by latest or oldest; the front page shows the latest one.

| Episode | Length | Link |
| --- | --- | --- |
| **October 2026: Black October** | about 75 minutes | [Slides](https://zevaryx.github.io/cybersec-hub/news/2026-10-black-october/) |

### Cyber in the News · Black October (October 2026)

Four parts, with a checkpoint after part 2:

1. **Keys and trust** (17 min): the $6.3 billion Binance heist and a live demo of why a signature proves the key said yes, not that anyone meant it; eMudhra's CA keys "generated with insufficient randomness", with a randomness-to-guesses slider
2. **Patch season** (24 min): PHP2Shell and why scans miss things; GitLab and Ruby's regex bugs (a regex is code); Brotli, one bug with three names in every runtime
3. **Stolen secrets** (18 min): LiteLLM's forgotten key and poisoned release (spot the lookalike, pin the hash); a malicious Claude Code extension version in Cursor's marketplace; the Railway and Zeabur breaches
4. **Wrap-up** (12 min): the myth of the month, what to do for each track, the 12 days of cybermas, and every source

The facts were checked against official sources on 30 October 2026. The Binance story was a day old then, so its numbers may have moved.

### Identity and Access Management

Four parts, with checkpoints after parts 1 and 3:

1. **One identity, many apps** (25 min): single sign-on (offboard someone with and without it), a real ES256 ID token to decode and tamper with, OAuth vs OpenID Connect, sessions and token theft
2. **Strong authentication** (22 min): the MFA ladder and what NIST calls phishing-resistant, push fatigue (with and without number matching), rolling out passkeys, conditional access (pick a sign-in, see the decision)
3. **Least privilege over time** (25 min): roles and groups, separate and just-in-time admin, break-glass accounts, joiners/movers/leavers (watch access drift), access reviews people finish, non-human identities, help-desk resets as a way in
4. **Wrap-up** (8 min): a 90-day plan that remembers your ticks

Authentication guidance follows NIST SP 800-63B revision 4, checked 30 October 2026.

### Zero-Knowledge Proofs

Four parts, with checkpoints after parts 1, 2 and 3:

1. **Intuition** (25 min): a cave you can play as verifier or bluffer, Where's Waldo with a piece of cardboard, the three properties (a quiz on which one is broken), and why repeating a round collapses a cheater's odds, including what goes wrong if the calls are predictable
2. **A real protocol** (30 min): Schnorr's proof of knowledge on a toy curve and on P-256 step by step, two answers to one commitment revealing the secret, a transcript simulator you can't tell from the real thing, and Fiat-Shamir with two real bugs (forgetting the commitment, forgetting the public key) that let you forge signatures
3. **Real-world ZK** (25 min): sealed envelopes (salted SHA-256 commitments), a graph 3-colouring proof, a Merkle membership proof with nullifiers, an over-18 check at three levels (the whole ID, salted digests with a real ECDSA signature, a zero-knowledge illustration), SNARKs, STARKs and Bulletproofs side by side, and where zero-knowledge is and isn't used
4. **Wrap-up** (10 min): what a valid proof does not guarantee, and eight questions to ask when someone says "zero-knowledge", saved in your browser

The demos use real elliptic-curve arithmetic (P-256 and a tiny curve), SHA-256 and an ECDSA signature in teaching code, never for real secrets. The zero-knowledge proofs on the membership and age slides are stand-ins and say so. Sources (the original papers, Trail of Bits' Frozen Heart disclosure, BIP340, RFC 8032, RFC 9901, Zcash's own disclosures, Google's Longfellow ZK, the European Commission's age-verification page) were checked on 9 November 2026; the unconfirmed items are listed in the slides' speaker notes.

### Modern Messaging Protocols

Four parts, with checkpoints after parts 1, 2 and 3:

1. **Starting a conversation** (25 min): a step-through X25519 key exchange, starting a chat when Bob is offline (prekeys and X3DH, with a dishonest-server toggle), the post-quantum extra secret against "harvest now, decrypt later", and safety numbers (including a swapped-key and a new-phone case)
2. **Ratchets** (30 min): forward secrecy with a hash chain, healing with a fresh Diffie-Hellman step, a live Double Ratchet where you can copy Alice's keys and watch the thief get locked out, three designs compared on the same twelve messages, and out-of-order delivery with a skip limit
3. **Groups, devices, metadata** (20 min): pairwise copies, sender keys and the MLS key tree (with a clickable tree), one ciphertext per device, and what sealed sender hides and doesn't
4. **Wrap-up** (10 min): what end-to-end encryption doesn't protect, a timeline of what has shipped versus what is beta or announced, and a ten-box checklist that remembers your ticks

The demos use real X25519 (checked against the RFC 7748 test vectors), HMAC, HKDF and AES-GCM in teaching code, never for real messages; the post-quantum secret is a stand-in. Signal's X3DH, PQXDH and Double Ratchet specifications, Sesame, Apple's PQ3 and Contact Key Verification posts, RFC 9420 and the sources on each slide were checked on 9 November 2026; the unconfirmed items (such as whether Signal's post-quantum ratchet is now enforced for everyone) are listed in the slides' speaker notes.

### Privacy Tools Explained

Four parts, with checkpoints after parts 2 and 3:

1. **A way to think about privacy** (15 min): threat models in plain words, and one question for every tool: hidden from whom, and who do I trust instead? A tool explorer for nine tools
2. **Hiding where you go** (25 min): who sees what on the way (HTTP or HTTPS, direct, VPN or Tor), a VPN advert claim checker, Tor's three layers with real AES-GCM you can peel, private DNS and Encrypted ClientHello, and what private windows and tracker blocking really do
3. **Hiding what you say and store** (25 min): "encrypted" versus end-to-end (a who-holds-the-key lab with real AES-GCM), messaging apps and the metadata envelope, the cloud backup gap, and disk encryption and where the recovery key lives
4. **Wrap-up** (10 min): a "hide X from Y" tool chooser and a 12-box privacy checklist that remembers your ticks

Every demo is a simulation in your browser: no real network traffic, and nothing you type is sent anywhere. Tools are named as examples, not recommendations. Claims about Tor, VPNs, private browsing, ECH, messaging apps, backups and disk encryption were checked against the vendors' and projects' own pages on 9 November 2026; the unconfirmed items are listed in the slides' speaker notes.

### Backups and Ransomware

Three parts, with checkpoints after parts 1 and 2:

1. **How ransomware works** (16 min): how it gets in, what it does next (locking, stealing, deleting backups), why you can't crack the key (a key-size calculator with the age of the universe for scale), and why paying is a gamble and a hard call
2. **Backups that survive** (22 min): sync is not backup (delete a file or lock the laptop and watch where it spreads), 3-2-1 plus a copy you can't reach, a plan builder that tests your copies against fire, theft, late deletes and ransomware and remembers your plan, how far back real services let you go, encrypting backups and where the key lives, a restore test that remembers your ticks, and how long a restore takes
3. **The bad day** (13 min): a ransomware morning, simulated; the first hour; practice for small teams, with a drawn tabletop scenario; six habits

Ransomware statistics (Coveware, Chainalysis, FBI IC3, Verizon), official guidance (CISA, NCSC, FBI, FTC, OFAC), the 3-2-1 rule's sources and consumer cloud retention windows were checked against primary sources on 9 November 2026; the unconfirmed items are listed in the slides' speaker notes. Nothing real is encrypted, locked or deleted: files are only marked "locked" on screen.

### Securing Your Home Network

Three parts, with checkpoints after parts 1 and 2:

1. **The router** (25 min): why it's the front door, the four settings that matter most (admin login, firmware, remote management, WPS), WPA3 versus WPA2 with a passphrase checker and random-passphrase maker, UPnP, and a mock router admin page to fix
2. **Everything else on the network** (25 min): smart devices and the accounts behind them, a network map showing what each device can reach on one network versus separate guest and smart networks, a sorter, updates and end of support, and what your provider can see with plain versus encrypted DNS
3. **Your checklist** (15 min): a 30-minute evening checklist that remembers your ticks, a myth-or-real quiz, and six habits

Router, Wi-Fi and smart-device guidance (FTC, CISA, FBI, Apple, the Wi-Fi Alliance), end-of-support examples and the UK, EU and US labelling and law dates were checked against primary sources on 9 November 2026; the unconfirmed items are listed in the slides' speaker notes. The random-word passphrases use the EFF short wordlist (CC BY 3.0 US).

### Vulnerability and Patch Management

Four parts, with checkpoints after parts 1, 2 and 3:

1. **Knowing what you run** (25 min): inventories and SBOMs, a "do we run it?" search over sample SBOMs with real version-range matching, an annotated advisory reader
2. **Deciding what first** (30 min): why CVSS is severity not risk (a CVSS 4.0 context explorer), KEV and EPSS, CISA's BOD 26-04 timelines as a priority model, a priority sorter, Log4Shell from report to "fully patched"
3. **Patching without fear** (20 min): a staged-rollout simulator, verifying the fix (a checklist that remembers your ticks), mitigations when you can't patch, end of life
4. **Wrap-up** (10 min): metrics that matter, with a mean-versus-median demo

CVSS 4.0, the KEV catalogue, EPSS data, BOD 26-04, the EU Cyber Resilience Act dates and the Log4Shell timeline were checked against primary sources on 8 November 2026; the unconfirmed items are listed in the slides' speaker notes.

### Web Application Security Essentials

Four parts, with checkpoints after parts 1, 2 and 3:

1. **Data vs code** (34 min): a toy SQL parser (concatenation versus parameters), raw versus escaped output in sandboxed frames, Content Security Policy against six injections
2. **Who's allowed to do what** (36 min): a mock API for broken access control, a cookie builder, a CSRF and SameSite explorer, an SSRF checker
3. **Making it routine** (30 min): version ranges and lock files, a header grader, a bundle secret scanner, which pipeline tool catches which bug
4. **Wrap-up** (14 min): the OWASP Top 10:2025 as a clickable map, a review checklist that remembers your ticks

Every demo is simulated in the page: no vulnerable server, and nothing you type runs. OWASP Top 10:2025, browser SameSite defaults and CSP Level 3 were checked on 9 November 2026.

### Your Phone, Safely

Three parts, with checkpoints after parts 1 and 2:

1. **The lock and what's behind it** (16 min): what a passcode and face unlock each protect, a guessability checker with real lockout limits, why a restarted phone is safest, lock-screen leaks
2. **Apps** (20 min): a torch-app permission audit, app stores versus sideloading and fake apps, how long phones get updates, public Wi-Fi and charging myths
3. **When it goes wrong** (16 min): a lost-phone checklist that remembers your ticks, Find My and Find Hub, theft protection, SIM-swap locks, and where to get help safely with stalkerware and unwanted trackers

Phone features (iOS Stolen Device Protection, Android Theft Protection, lockout limits and update lifespans) were checked against Apple's and Google's own documentation on 8 November 2026.

### Public Key Infrastructure in Depth

Four parts, with checkpoints after parts 1, 2 and 3:

1. **The trust model** (25 min): trust stores and cross-signing, a chain builder with real ECDSA signatures (normal, forged with a stolen intermediate key, edited after signing, name-constrained)
2. **When CAs get it wrong** (25 min): DigiNotar and the 2026 eMudhra distrust, a mini Certificate Transparency log with real RFC 6962 hashing and inclusion proofs, a distrust-by-date timeline
3. **Revocation and lifetimes** (20 min): why OCSP faded and what replaced it, attacker-window bars, the move to 47-day certificates, a lifetime calculator, an ACME walk-through (HTTP-01 and DNS-01)
4. **Running your own** (15 min): an internal-CA checklist that remembers your ticks, an expiry radar

Dates and standards (Baseline Requirements v2.3.1 and ballot SC-081v3, Let's Encrypt's OCSP and lifetime changes, RFCs 6962, 9162, 8555 and 9773) were checked against primary sources on 8 November 2026; the unconfirmed items are listed in the slides' speaker notes.

### Using Crypto Correctly in Code

Four parts, with checkpoints after parts 1, 2 and 3:

1. **Choosing tools** (20 min): a want-X-use-Y picker, the layers of a crypto library, a use-or-avoid sorter of invented packages
2. **Encryption without footguns** (35 min): authenticated encryption (stream mode versus an AES-GCM tag), a birthday simulation of nonce collisions, nonce reuse, associated data, HKDF labels, KEK/DEK envelopes, versioned formats
3. **Everything else that goes wrong** (32 min): password hash parameters, constant-time comparison, randomness, JWT verification, TLS settings across four tools, logs and errors
4. **Review practice** (18 min): a five-snippet bug hunt with 15 bugs, a twelve-box review checklist that remembers your ticks

The demos use real AES-GCM, HKDF and HMAC from the shared crypto code: teaching code, never for real data. Parameters follow NIST SP 800-38D and the OWASP cheat sheets, checked 8 November 2026.

### Phishing and Scams in the Age of AI

Three parts, with checkpoints after parts 1 and 2:

1. **How scams work on people** (15 min): the five pressure tricks (urgency, authority, fear, secrecy, reward) and the "ask", a pressure-trick highlighter, and the channels scams arrive by
2. **Spotting the fake** (25 min): a link reader that picks out the real site, a real-or-fake quiz, sender names versus addresses, a mock password manager and passkey that refuse a look-alike site, AI-written messages, voice clones and deepfake calls, the call-back rule with a family code phrase, and a scenario drill
3. **If it happens** (15 min): a first-hour checklist that remembers your ticks, where to report, no shame, and six habits to take home

Real examples: US FTC fraud figures for 2024, the Arup deepfake video call (2024) and FTC warnings on voice-clone family emergency calls. Reporting sites checked 8 November 2026.

### Cloud Security Fundamentals

Four parts, with checkpoints after parts 1, 2 and 3:

1. **Who secures what** (20 min): shared responsibility as a stack (click through on-premises, IaaS, PaaS and SaaS), accounts, subscriptions and projects as walls
2. **Identity is the perimeter** (30 min): users, roles and policies, a policy simulator where explicit deny wins, roles instead of long-lived keys, a blast-radius comparison of a leaked key and a leaked role session, MFA for root and owner accounts
3. **Common misconfigurations** (25 min): public storage (block it account-wide), open ports, encryption and who holds the key, the metadata service and SSRF (a link previewer with and without IMDSv2), a misconfiguration hunt in Terraform with a policy check
4. **Guardrails** (15 min): audit logs and findings services across AWS, Azure and Google Cloud, a billing alert as an intrusion detector, everyday habits, a first-week checklist that remembers your ticks

Real examples: Snowflake customers (2024), Capital One (2019), Code Spaces (2014) and the Storm-0558 review. Provider defaults (S3 public access and encryption, IMDSv2, root and Azure MFA, Google's secure-by-default organizations) were checked against the providers' documentation on 30 October 2026.

### Git and GitHub Security

Three parts, with checkpoints after parts 1 and 2:

1. **Who wrote this commit?** (28 min): author names are just text (commit as anyone), signed commits with real ECDSA (sign, forge, tamper), what "Verified" proves, SSH signing setup, commit messages worth reading (a live checker), undoing mistakes without fear (pick the situation, get the command), securing your account
2. **Protecting the repository** (29 min): rulesets, pull requests people want to review, secret scanning and push protection (a simulated push), fine-grained tokens, GitHub Actions (fix a risky workflow: token permissions, locking or pinning actions, fork triggers, script injection), a settings checklist that remembers your ticks
3. **When a secret leaks** (15 min): the response drill (put the steps in order), why rewriting history isn't enough, four things to do this week

Real examples: the tj-actions/changed-files compromise (March 2025) and LiteLLM (October 2026). GitHub facts were checked against GitHub Docs on 30 October 2026; the Actions lockfile is the generally available `gh actions-lock` extension.

### Security Habits for New Developers

Three parts, with checkpoints after parts 1 and 2:

1. **Thinking like a defender** (20 min): everything is input, trust boundaries (pick a flow and see what to check), treating data as code (a SQL query glued together vs parameterised), trusting the client (a shop that believes the price in a hidden field)
2. **Ten habits** (38 min): validate and encode (an HTML comment shown raw vs encoded), permissions on every request (change the invoice number), secrets in Git history (delete vs rotate), well-known libraries, few and current dependencies, failing safely (dev vs production errors), least privilege (watch the blast radius grow), review and blameless learning; plus everyday habits that make them easy (readable code, tools, environments, docs) and an edge-case generator for testing the unhappy path
3. **Wrap-up** (10 min): a ten-habit checklist that remembers your ticks, where to learn next

Real examples come from October 2026 (see Cyber in the News). Every "server" in the demos is JavaScript in your browser; nothing is sent anywhere.

### How HTTPS Really Works

Four parts, with checkpoints after parts 1, 2 and 3:

1. **Before any encryption** (20 min): the journey of a request, DNS lookups and who sees them, the café Wi-Fi view of plain HTTP vs HTTPS
2. **The handshake** (30 min): a live TLS 1.3 handshake with real P-256 key exchange, the real TLS 1.3 key schedule (HKDF), a certificate chain and signatures; hybrid post-quantum key exchange; breaking certificates on purpose; why TLS 1.3 is faster
3. **After the handshake** (25 min): encrypted records and tamper detection, what the network still learns (with encrypted DNS, ECH and VPNs), certificate warnings, HSTS, Certificate Transparency
4. **Wrap-up** (15 min): inspect this page's own connection, the whole journey in one picture

### Passwords and Accounts

Four parts, with checkpoints after parts 1 and 3:

1. **How accounts get broken into** (18 min): the attacker's shopping list, a password-reuse demo, what websites should store, checking for leaks without sending your password
2. **Strong passwords without suffering** (16 min): length beats complexity, a random-password generator, password managers, how a vault is locked (live)
3. **Two-factor and passkeys** (22 min): a live authenticator code the audience can scan with their own phone, how the 6 digits are made, which method stops which attack, the look-alike site test
4. **Don't lock yourself out** (11 min): recovery codes, and a checklist for tonight that remembers your ticks

The authenticator demo uses a public demo secret (`Cybersec Hub: Demo`); delete it from your app afterwards.

### Crypto 101

Five parts, with a five-minute discussion checkpoint after each:

1. **Foundations** (25 min): the four goals of cryptography, Caesar and Vigenère ciphers, the one-time pad, the Enigma machine, bits, bytes, hex and Base64, hashing vs encryption vs encoding
2. **Hashing** (20 min): the avalanche effect, SHA-256 round by round, why MD5 and SHA-1 broke, salt and pepper, slow password hashing
3. **Symmetric encryption** (35 min): XOR, AES step by step, modes from ECB to GCM, the ECB padlock picture, tampering and nonce reuse, why keys need good randomness
4. **Asymmetric** (25 min): RSA with small numbers, elliptic curves, key exchange (with paint, then on P-256), digital signatures, passkeys (simulated, plus an optional real one)
5. **The future and wrap-up** (15 min): post-quantum cryptography and lattices, a secure website from start to finish, inspecting a real certificate, end-to-end encryption, takeaways

Three slides are marked skippable for when you're running long. The passkeys slide can create a real passkey through your browser (fingerprint, face or PIN); it's saved as "Crypto 101 demo" in your password manager.

Crypto 101 used to live at `zevaryx.github.io/crypto-101`; that address now redirects here, slide links included.

## Presenting

Open a talk on a laptop or projector and it shows one slide at a time. On a phone it switches to a scrolling page. Add `?view=scroll` or `?view=slides` to a talk's address to choose.

| Key | Action |
| --- | --- |
| `→` `Space` `PageDown` | Next slide |
| `←` `PageUp` | Previous slide |
| `Home` / `End` | First / last slide |
| `N` | Show or hide the speaker notes |
| `P` | Open the presenter window (notes, next slide, timers, timing plan). It follows the main window. |
| `O` | Overview of all slides |
| `F` | Full screen |
| `Esc` | Close the notes or overview |

Checkpoint slides have a 5-minute discussion timer that starts by itself when the slide appears and resets when you leave; click it (or its copy in the presenter window) to pause or resume. Speaker notes are short cues (Say, Show, Ask, Tip, Next) with a time estimate per slide.

The control bar in the bottom-right corner has the same actions, plus **Scroll view**, **PDF** (print, or save as a PDF with one slide per page) and **All talks**. Every slide has its own link, for example `talks/crypto-101/#padlock`.

The decks need no internet connection once loaded: fonts and libraries are bundled.

## Running it locally

There is no build step. Serve the `docs/` folder with any static web server:

```sh
python3 -m http.server --directory docs 8000
```

Then open <http://localhost:8000>. The real-passkey demo only works on the live site or `localhost`.

Or use the included script, which opens your browser and needs nothing but Python 3:

```sh
python3 serve.py              # http://localhost:8000
python3 serve.py --port 9000  # another port
python3 serve.py --lan        # let phones on your network connect too
```

## Publishing on GitHub Pages

In the repository's **Settings → Pages**, choose **Deploy from a branch**, then the `main` branch and the `/docs` folder. Turn on **Discussions** (Settings → General → Features) so the questions links on the slides work.

## Adding a talk

```sh
./new-talk.sh how-https-works "How HTTPS Really Works" "HTTPS"
```

This copies `template/` to `docs/talks/how-https-works/` with the title filled in: a title slide, a content slide, a checkpoint with its timer, and a questions slide. Then:

1. Write the slides in its `index.html` (each has its speaker notes in a `.notes` block) and its demos in `app.js`.
2. Set the parts and their minutes in the page's `deck-config` block; the presenter window builds its timing plan from them.
3. Add a card for it to its track in `docs/index.html`, in the order to take the talks (before the "More coming soon" tile), and a row to the table above. Also swap it into the "Newest talk" featured card at the top. The track's tab count and progress bar update themselves.
   For a **Cyber in the News** episode, create it the same way, then move the folder to `docs/news/YYYY-MM-slug/` (same depth, so its links to `shared/` still work; point links into other talks at `../../talks/`). Add a card to `docs/news/index.html` with `data-date="YYYY-MM"` (the page sorts itself), and replace the Cyber in the News featured card on `docs/index.html`.
4. Add a `qr.svg` QR code of the talk's address (the title and Questions slides show it; `qr-discussions.svg` is copied in for you), and optionally a 1200×630 `og-image.png` for link previews.
5. Hide a few easter eggs in the demos (jokes for special inputs, a console hint, a reward for finishing something) and list them in the title slide's speaker notes. Every talk has some.

## Project layout

```
docs/
  index.html          the hub's front page: featured cards (Crypto 101, latest news, newest talk), then one tab per track
  hub.js              the track tabs, reading progress (saved in the visitor's browser only), and a few easter eggs
  hub.css             front-page styles (also used by news/). The pages link it, hub.js and news.js with ?v=DATE:
                      change that date when you edit them, so returning visitors don't get a stale copy
  news/               the Cyber in the News page: every episode, sortable (news.js)
    YYYY-MM-slug/     one folder per episode, laid out like a talk folder
  shared/
    deck.css          the cyberpunk theme, slide layout, scroll view, print layout, timers
    deck.js           slide navigation, notes, overview, presenter window, checkpoint timers, and marking a talk read for the hub
    crypto.js         the maths: classical ciphers, SHA-256, SHA-1, HMAC, HKDF (incl. TLS 1.3 labels), HOTP/TOTP, Base32,
                      AES (ECB/CBC/CTR/GCM), RSA, elliptic curves, passkey signature checks, toy lattice encryption
    fonts/            bundled fonts (Chakra Petch, JetBrains Mono)
    vendor/           hash-wasm, used to time bcrypt, scrypt and Argon2id
  talks/
    crypto-101/, passwords-and-accounts/, how-https-works/, security-habits/, git-github-security/, identity-and-access/, cloud-security/, phishing-and-scams/, crypto-in-code/, pki-in-depth/, mobile-safety/, web-app-security/, vulnerability-management/, home-network/, backups-and-ransomware/, privacy-tools/, modern-messaging/, zero-knowledge-proofs/
      index.html      the slides, with their speaker notes and deck-config
      app.js          the talk's live demos
      talk.css        styles for the talk's own demos
      qr*.svg, og-image.png
template/             starting point for a new talk (used by new-talk.sh)
new-talk.sh
serve.py              run the hub locally
```

`shared/crypto.js` also works in Node (`require("./docs/shared/crypto.js")`), so the maths can be tested outside the browser. The AES and GCM code matches the official FIPS-197 and NIST test vectors.

## Educational use only

The ciphers here are written from scratch so each step can be shown. They are not hardened, constant-time or audited. Never use this code to protect real data; use the Web Crypto API or a vetted library instead.

## Licenses

- The code and talks in this repository are released under the [MIT License](LICENSE).
- [hash-wasm](https://github.com/Daninet/hash-wasm) (`docs/shared/vendor/`) is MIT-licensed by Dani Biró.
- [Chakra Petch](https://github.com/m4rc1e/Chakra-Petch) and [JetBrains Mono](https://github.com/JetBrains/JetBrainsMono) (`docs/shared/fonts/`) are under the SIL Open Font License 1.1; see `docs/shared/fonts/OFL-*.txt`.
