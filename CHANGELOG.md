# Changelog

## 0.4.3 (spec-0.4.3)

Conforms to the Datumesh specification revision `spec-0.4.3` (spec commit `99123b2`): all 1236 vectors, 651 run and 585 skipped (the formula evaluator kinds `formula`, `formula-eval`, `excel`, `decimal` and `call`). Additions only: every 0.4.2 call behaves as before on every input 0.4.2 accepted.

Compatibility (spec-0.4.3 release notes):

- A mesh that serves `declarations` is unverifiable by clients on core < 0.3.7 or datumesh < 0.4.3; publishers should wait for their consumers to upgrade before declaring. The same holds for @datumesh/verify < 0.4.3.
- Envelopes carrying `E_FOREIGN_UNAVAILABLE` (or its `detail` member) are rejected (`E_ENVELOPE`) by libraries that check the closed code and member lists of `spec-0.4.2`: core < 0.3.7, datumesh < 0.4.3 and @datumesh/verify < 0.4.3.

Added:

- Key documents (SPEC 9.2, 4.5): the optional `declarations` member, checked whole (a name that is not a full function name under the document's own host, a subdomain included; a bad licence or instant; `valid_to` not after `valid_from`; a missing or extra entry member; `{}` or `[]`; more than 64 names or 16 entries: `E_KEY_DOC`). Exposed as `KeysResult.declarations` (function name to `Declaration` entries) and `KeysResult.declarations_json()`. Receipts verify exactly as with a document without them.
- `E_FOREIGN_UNAVAILABLE` (SPEC 5.5, 10.2): the last of `ERROR_CODES`; outcome `error` with HTTP 502 exactly and the envelope member `detail`, one of `FOREIGN_DETAILS` (`offline`, `network`, `dns`, `tls`, `timeout`, `refused`), required with this code and rejected in every other envelope. Exposed as `EnvelopeResult.error_detail`. Never a verification result.
- Licence inheritance (SPEC 8.5): `inherit_licence(licences, declarations, fn, issued, mesh_licence) -> LicenceResult` (`licence`, None for a refusal; `reason`), and `licence_tier`, `PUBLIC_DOMAIN`, `ATTRIBUTION`, `SHARE_ALIKE`.
- The entitlement check (SPEC 10.3): `check_entitlement(receipt, licences, keys) -> EntitlementResult` (`entitled`, `reason`, `licence`), `REASONS`, `ENTITLED_REASONS`; a key document of another host than `cell.ns`'s is a `ValueError`. `input_licences(receipt, receipts, manifests=None, keys=None)` follows a receipt's `inputs` through the receipts and manifests supplied, slice members included.
- Unrooted namespaces (SPEC 2.5): `is_unrooted(namespace_or_host)`.
- Conformance runner: the kinds `licence` and `entitlement`, and the `keys` output `declarations`.

Earlier versions: see the git history and `DEFECTS.md`.
