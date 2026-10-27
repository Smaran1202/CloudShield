# Third-party tools and formats

## Prowler

CloudShield can import the output of [Prowler](https://github.com/prowler-cloud/prowler), an
open source cloud security tool. Prowler is licensed under the Apache License 2.0.

CloudShield does not bundle Prowler. You install it yourself, as a separate program, and
CloudShield can use it in two ways:

- You run Prowler yourself and give CloudShield the JSON-OCSF file it writes
  (`python -m cloudshield.imports prowler <file>`). CloudShield only reads that file.
- The dashboard's "Run full scan" starts the Prowler you installed, as a separate process, for
  this computer's account only, and reads the file it writes. See `docs/extended-checks.md`.

In both cases CloudShield only starts the program and reads its output file. Prowler is not
imported as a library and nothing from it is copied into this repository.

No Prowler code, check metadata or knowledge files are copied into this repository. The test
fixtures are written by hand and only follow the shape of the output.

## OCSF

The imported file uses the [Open Cybersecurity Schema Framework](https://ocsf.io) (OCSF)
Detection Finding class, version 1.5.0. CloudShield reads a small set of its fields and ignores
the rest.

## What is vendored

Nothing. No third-party code is vendored in this repository.
