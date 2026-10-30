# Cybersec Hub

Talks on cryptography and cybersecurity by [zevaryx](https://github.com/zevaryx), built as websites. Each talk is a slide deck and a set of live demos in one page: every cipher, hash and key exchange on the slides runs in your browser as you click through.

**Live hub: <https://zevaryx.github.io/cybersec-hub/>** · You're welcome to present these talks yourself; see the license below.

## Talks

| Talk | Level | Length | Link |
| --- | --- | --- | --- |
| **How HTTPS Really Works** | Beginner | about 90 minutes | [Slides](https://zevaryx.github.io/cybersec-hub/talks/how-https-works/) |
| **Passwords and Accounts, done properly** | Beginner | about 70 minutes | [Slides](https://zevaryx.github.io/cybersec-hub/talks/passwords-and-accounts/) |
| **Crypto 101: Intro to Cryptography** | Beginner | about 2 hours | [Slides](https://zevaryx.github.io/cybersec-hub/talks/crypto-101/) |

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
3. Add a card for it to `docs/index.html` and a row to the table above.
4. Optionally add a 1200×630 `og-image.png` for link previews.
5. Hide a few easter eggs in the demos (jokes for special inputs, a console hint, a reward for finishing something) and list them in the title slide's speaker notes. Every talk has some.

## Project layout

```
docs/
  index.html          the hub's front page (one card per talk)
  hub.css             front-page styles
  shared/
    deck.css          the cyberpunk theme, slide layout, scroll view, print layout, timers
    deck.js           slide navigation, notes, overview, presenter window, checkpoint timers
    crypto.js         the maths: classical ciphers, SHA-256, SHA-1, HMAC, HKDF (incl. TLS 1.3 labels), HOTP/TOTP, Base32,
                      AES (ECB/CBC/CTR/GCM), RSA, elliptic curves, passkey signature checks, toy lattice encryption
    fonts/            bundled fonts (Chakra Petch, JetBrains Mono)
    vendor/           hash-wasm, used to time bcrypt, scrypt and Argon2id
  talks/
    crypto-101/, passwords-and-accounts/, how-https-works/
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
