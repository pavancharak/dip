# 1. Overview

Status: draft. Normative keywords (MUST, MUST NOT, SHOULD, MAY) follow RFC 2119. This document describes the protocol as implemented in `main`, and marks anything not yet built.

## 1.1 Purpose

DIP makes business authority explicit, decides whether a requested action is authorized, controls execution of authorized actions, and records evidence that an independent party can verify.

Lifecycle: DECLARED → AUTHORIZED → EXECUTED → PROVEN.

## 1.2 Principles

1. Authority MUST be declared explicitly, in a signed, machine-readable form.
2. Authorization MUST be deterministic for the same inputs and clock.
3. Execution MUST be restricted to actions with a valid ALLOW decision for the exact request.
4. Evidence MUST let a third party establish what was authorized and what was executed, without trusting the service that produced it.

AI systems may propose actions. They MUST NOT determine their own authority.

## 1.3 Scope

This specification covers the protocol: data formats, cryptography, state transitions, verification and conformance. It does not cover the deployment of any particular server, which is described in `docs/deployment/`.

## 1.4 Status of this specification

Sections 1 to 21 exist as drafts. The implementation is ahead of some sections and behind others. Each section states its status. Where text and code disagree, the code is authoritative until the text is corrected, and the disagreement is recorded in `docs/IMPLEMENTATION_MATRIX.md`.
