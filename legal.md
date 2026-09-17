# Legal Considerations (US) — Windows Keylogger Project

*Educational summary, not legal advice. For anything with real exposure, consult a lawyer.*

## The one-sentence version

Every part of this stack — the code, the compiled exe, the USB board, the Vercel website — is legal to write, own, publish, and sell in the United States; **the only thing that can be illegal is using it on a computer without the authorization of the person being monitored.**

## Which parts of the stack are illegal?

None. There is no illegal component, only illegal *use*:

| Component | Legal status |
|---|---|
| Keylogger source code, compiled exe | Legal to write, compile, own, publish, sell. Commercial keyloggers are sold openly in the US (mSpy, Refog, Veriato, etc.), marketed for parental control and employee monitoring. |
| Pro Micro / HID injection board | Legal hardware, sold openly (Hak5 Rubber Ducky, Flipper Zero, Digispark). |
| Vercel weather-app receiver | A real weather site plus an API endpoint. Entirely legal at hobby scale. |
| GitHub repo with the code | Legal to publish (see "Publishing on GitHub" below). |
| **Deploying it on a machine without authorization** | **The only potentially illegal act.** See below. |

## Federal law

### Wiretap Act / ECPA — 18 U.S.C. §§ 2510–2522

- Prohibits intentionally intercepting wire, oral, or electronic communications. Capturing someone's keystrokes (which often include emails, messages, and passwords as they're typed) has been treated by federal courts as "interception" of electronic communications — there are real federal convictions resting on keylogger-captured evidence.
- **Consent is the escape hatch:** interception is lawful if the person being monitored (or the person doing the monitoring, when it's their own device/communications) consents. 18 U.S.C. § 2511(2)(d) is the one-party-consent exception.

### Computer Fraud and Abuse Act (CFAA) — 18 U.S.C. § 1030

- Prohibits accessing a computer without authorization or exceeding authorized access. Installing a keylogger on a machine you're not authorized to administer can independently violate the CFAA — it doesn't matter that the computer was physically accessible.

## State law

- Most states have their own wiretap/electronic-surveillance statutes; some (e.g., California, Pennsylvania, and other all-party-consent states) are stricter than the federal one-party rule.
- State computer-crime statutes can also apply to unauthorized software installation.
- Practical rule: **assume the strictest applicable state law** when the target and the monitorer are in different states.

## When use is legal vs. illegal

**Generally legal (US):**

- **Your own computers** — you own the device and the communications; monitoring your own machine is not intercepting "another person's" communications.
- **Your minor children** — parents are broadly authorized to monitor children's devices; parental-control products depend on this.
- **Employees, on company-owned equipment, with notice** — employer monitoring with a written policy or consent is the standard, lawful pattern. Written notice/acknowledgment (onboarding policy, login banner) is what makes it defensible.
- **Any adult who consents** — one-party consent satisfies the federal Wiretap Act.

**Illegal (US), even on a device you bought:

- **Monitoring another adult without their knowledge or consent** — e.g., a spouse, partner, roommate, or anyone else using the machine — can violate the federal Wiretap Act and/or CFAA, plus state analogs. People have been criminally convicted and civilly sued for exactly this (keylogging a partner/ex-partner is a recurring fact pattern in the case law).
- Ownership of the *hardware* does not clearly authorize monitoring of *someone else's communications and accounts* — the person being monitored's consent or legal authority (parent, employer with notice) is what matters.

## Practical checklist before deploying on any machine

1. Do I own or administer this machine? (Necessary, not always sufficient.)
2. Am I the only user, or does every user know they may be monitored?
3. If it's an employee's machine, is there written notice/policy?
4. If it's a child's machine, is the child a minor under my care?
5. Will the captured keystrokes include a non-consenting adult's accounts or communications?

If any answer is unfavorable, the deployment is legally risky even if the machine is yours.

## Publishing on GitHub

Safe to publish, with hygiene. Thousands of keylogger repos already exist on GitHub; a clean hobby repo is well within the norm.

- **Repo takedown:** GitHub removes repos mainly for DMCA violations or actively malicious content (stolen credentials, live-malware campaigns). A documented educational keylogger with no secrets is not that.
- **Account takedown:** requires repeated AUP/DMCA strikes; a single clean repo won't get there.
- **Legal action for publishing:** authorities pursue people who *deploy* keyloggers maliciously, not people who *write* them.
- **Hygiene rules (do these):**
  1. Keep secrets out of the repo — `config.json` (real domain + PSK), `src/gen_strings.h`, `out/`, and `receiver/public/payload.exe` are gitignored; only `config.example.json` is committed.
  2. State the intended use in the README ("personal/educational; deploy only on machines you own or are authorized to monitor").
  3. Optionally skip committing the compiled exe so the repo is source-only.

## Ops notes

- Vercel AUP: a hobby-scale personal project is fine; a weather-app facade isn't misleading anyone about anything material.
- If this is ever used for authorized monitoring in a workplace context, keep the notice/policy document — it's your defense.
- If used only on your own machines, none of the above federal/state provisions are implicated.
