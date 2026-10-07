# Third-party tools and formats

## Prowler

CloudShield can import the output of [Prowler](https://github.com/prowler-cloud/prowler), an
open source cloud security tool. Prowler is licensed under the Apache License 2.0.

CloudShield does not run Prowler. You run it yourself and give CloudShield the JSON-OCSF output
file it writes (`python -m cloudshield.imports prowler <file>`). CloudShield only reads that file.

No Prowler code, check metadata or knowledge files are copied into this repository. The test
fixtures are written by hand and only follow the shape of the output.

## OCSF

The imported file uses the [Open Cybersecurity Schema Framework](https://ocsf.io) (OCSF)
Detection Finding class, version 1.5.0. CloudShield reads a small set of its fields and ignores
the rest.

## What is vendored

Nothing. No third-party code is vendored in this repository.
