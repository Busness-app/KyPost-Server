# Code of Conduct

KyPost handles other people's mail, mail credentials, and private keys. Getting
that right takes people who disagree with each other in public and keep showing
up anyway. This document exists so that disagreement stays about the work.

## Our Commitment

Everyone who contributes to KyPost — code, documentation, bug reports, security
findings, translations, or a question in an issue — is welcome here regardless
of age, body size, visible or invisible disability, ethnicity, sex
characteristics, gender identity and expression, level of experience,
education, socio-economic status, nationality, personal appearance, race,
religion, caste, colour, or sexual identity and orientation.

We are building software for people who want control over their own mail. A
project about self-determination that treats its contributors as
interchangeable would be lying about what it is.

## What We Expect

- **Assume the other person is trying.** Read the strongest version of what
  they wrote before you answer it.
- **Be specific.** "This is wrong" helps nobody. "This drops the lock before
  the write, so two pollers can interleave here" helps everybody.
- **Ask, don't assume, about people.** Use the name and pronouns a person uses
  for themselves. If you don't know someone's pronouns, use they/them. A
  correction is not an attack; take it, apply it, move on.
- **Let inexperience be visible.** Someone asking a basic question in public is
  doing the project a favour — that question is the documentation gap made
  legible. Answer it or point at the doc; don't perform surprise that it was
  asked.
- **Accept review gracefully, including when you're right.** Explain your
  reasoning, link the evidence, and let the maintainers decide.
- **Credit work.** Say whose idea it was. This includes crediting a bug report
  that led to a fix, and disclosing AI assistance as
  [CONTRIBUTING](CONTRIBUTING.md#ai-attribution-is-mandatory) requires.

## What We Won't Accept

- Sexualised language or imagery, or unwanted sexual attention of any kind.
- Slurs, demeaning jokes, or "just asking questions" about whether a group of
  people belongs here.
- Personal attacks, insults, or derogatory comments — including the kind
  dressed up as technical rigour.
- Deliberate misgendering or persistent use of a name a person has asked you
  not to use.
- Publishing someone's private information (physical or email address, private
  messages, employer, legal name) without their explicit permission.
- Harassment in public or in private, including following someone across
  threads, repos, or platforms to continue an argument they have left.
- Retaliation against anyone who reports a Code of Conduct problem or a
  security vulnerability.

## Hostile Reviews Are About Code, Never People

KyPost deliberately runs adversarial review: human reviewers, and AI reviewers
running skills that are *instructed* to be unimpressed with your work. Every PR
gets torn at on purpose, because the alternative is finding out from a user
whose mailbox credentials leaked. See
[CONTRIBUTING](CONTRIBUTING.md#adversarial-review-skills).

That practice has an exact boundary, and the boundary is this:

- **In scope:** "This design cannot work." "You have not shown this is safe."
  "This adds a silent fallback and the project doesn't allow those." "This
  looks like a rewrite, not a patch." Blunt, unsoftened, repeated if it wasn't
  heard the first time.
- **Out of scope:** anything about the author. Their competence, their
  motives, their care, their seniority, whether they "should know better,"
  whether they used AI, or how many times they've been wrong before.

Hostility toward a design is a service. Hostility toward a person is a Code of
Conduct violation, and calling it "just being direct," "the hostile review
persona," or "what the skill told me to say" does not change that. An AI
reviewer that crosses this line is the fault of the human who ran it and pasted
the output.

If you are the author on the receiving end: a severity-ranked list of things
that are wrong with your patch is not a verdict on you. Read it, take what's
real, push back on what isn't. Nobody here got a clean first review.

## Scope

This applies in every project space — issues, pull requests, discussions,
commit messages, code comments, the wiki, and any chat or event where you are
representing KyPost. It also applies to behaviour outside these spaces when
that behaviour is directed at a member of this community because of their
participation here.

## Reporting

Report a problem privately to the maintainer,
[@Yoshiofthewire](https://github.com/Yoshiofthewire), through GitHub. Do not
open a public issue about a Code of Conduct concern; that exposes the reporter
first.

Include what happened, where, when, and links if you have them. You do not need
to prove your case or have a remedy in mind to report something.

Reports are handled privately. The reporter's identity is not disclosed to the
person reported without the reporter's consent. You may report on behalf of
someone else, and you may report an incident you witnessed but were not the
target of.

**Security vulnerabilities are not a Code of Conduct matter.** Report those
through [GitHub Security Advisories](https://github.com/Yoshiofthewire/kypost-server/security/advisories),
as described in [SECURITY.md](SECURITY.md).

## Enforcement

The maintainer will review every report and respond. Depending on severity and
history, the response may be:

1. **A private word.** A note explaining what was wrong and what to do instead.
2. **A warning.** Formal, with defined consequences for continuing — usually a
   period of no interaction with the people involved.
3. **A temporary ban.** No participation in project spaces for a stated period.
4. **A permanent ban.** For sustained harassment, aggression toward a group of
   people, or a pattern that has already been warned about.

Maintainers who do not enforce this document in good faith are subject to it
themselves.

## Attribution

Adapted from the [Contributor Covenant](https://www.contributor-covenant.org),
version 2.1, with sections specific to this project's adversarial review
practice.
