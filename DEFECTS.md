# SPEC.md defects found while implementing datumesh-verify-py

Five sections: `spec-0.1.1` (step 0.2, DEF-01 to DEF-22), then `spec-0.4.0` (what that revision
resolves, and DEF-42 to DEF-47), then `spec-0.3.0` (what that revision resolves, and DEF-40 to
DEF-41), then `spec-0.2.1` (status of every entry at that revision, and DEF-39), then `spec-0.2.0`
(DEF-23 to DEF-38). The `spec-0.1.1` entries are kept as written; where `spec-0.2.0` left one open, the
`spec-0.2.0` section says so.

# spec-0.1.1

Spec revision: `spec-0.1.1` (commit 59bd732). This library was written from SPEC.md, the
schemas and the vectors only. `tools/canon.py` was used as a black box (its `check`, `jcs`,
`uri` and `verify` commands on inputs I wrote), never read. One disclosure: during the first
probes, uncaught exceptions in canon.py printed Python tracebacks that quoted a few of its
source lines (the call sites that raise `E_PARSE_JSON` for out-of-range numbers and lone
surrogates, `E_PARSE_DUPLICATE_KEY`, and `E_ARG_MISSING` in `parse_uri`). After that I kept only
the last line of its output.

Every vector in `spec/vectors/` can be reproduced from SPEC.md plus the vectors and schemas;
none needed canon.py. The entries below are places where the prose was silent, ambiguous or
contradicted a vector, and I had to infer the rule from a vector or a schema, ask the oracle, or
choose. Each entry gives the section, the problem, what this library does, and replacement
wording. "Reference" means canon.py's observed behaviour. `tools/oracle_fuzz.py` runs the
differential check that found most of these (45,000 mutated vectors over nine runs, three of them
with this library on Python 3.10; every remaining disagreement was DEF-01, before the DEF-02
change for userinfo and ports, which adds a second known class).

Deliberate divergences from the reference tool: DEF-01, DEF-02 (userinfo and ports), DEF-04,
DEF-17 (null or text descriptor), DEF-16 (invalid host). All five are on inputs no vector covers.

---

## DEF-01. 5.4 / 10.2: the outer grammar is not checked first by the reference

**Problem.** 5.4 says `parse` checks "1. the outer grammar; 2. the namespace and function names;
...". 10.2 puts "empty query, or a parameter without `=`" under `E_PARSE_URI`, i.e. in the outer
grammar. The reference checks the scheme and the fragment first, then the namespace and function
names, and only then the empty query and parameters without `=`:
`cell://X.example/f?c` is `E_CANON_NAME` in the reference, `E_PARSE_URI` by the prose.

**Resolution.** Follows the prose (`E_PARSE_URI`). Apart from DEF-02 (userinfo and ports), this is the only class of disagreement left
in differential fuzzing.

**Proposed wording (5.4, step 1).** "1. the outer grammar: the URI starts with `cell://`, contains
no `#`, and, if it contains `?`, the text after the first `?` is non-empty and each of its
`&`-separated parameters contains `=` (`E_PARSE_URI`);" (or, if the reference's order is the
intended one, move the empty-query and missing-`=` checks to after step 2 and say so).

## DEF-02. 5.1 / 5.4: where the "outer grammar" ends; userinfo and ports

**Problem.** 5.1 gives one ABNF for the whole URI, then says "A cell URI has no fragment, no
userinfo, no port and no empty query. Failures of this outer grammar are `E_PARSE_URI`. Invalid
names inside it are `E_CANON_NAME`". It does not say which parts of the ABNF are "outer". The
vectors show that characters a value may not contain (`+`, raw `ü`, space) are `E_CANON_PERCENT`,
not `E_PARSE_URI`, although the ABNF excludes them. The reference treats everything between
`cell://` and `?` as a namespace/function path, so userinfo and ports
(`cell://user@rates.example.org/fx_rate`, `cell://rates.example.org:443/fx_rate`) are
`E_CANON_NAME` there, contrary to the explicit sentence in 5.1. A missing function
(`cell://math.example`), an empty path and a trailing `/` are `E_CANON_NAME` in the reference too.

**Resolution (divergence for userinfo and ports; prose wins).** Where the prose is explicit it is
followed over the reference, as in DEF-01: in the outer-grammar step, before names are checked, an
`@` (userinfo) or a `:` (port, including an empty `host:` or a non-numeric one) anywhere in the
authority, i.e. between `cell://` and the first `/` (or the `?` or the end if there is no `/`), is
`E_PARSE_URI`. This matches the independently written JS library; a cross-language check over
1,000 mutated URIs had found 237 such cases where this library, then following the reference, said
`E_CANON_NAME`. `:` and `@` after the authority are not userinfo or ports (a `:` in a function name
is `E_CANON_NAME`; in a value `:` is a literal and `@` is `E_CANON_PERCENT`). Everything else is as
the reference: the path is split at its last `/` (no `/` at all: `E_CANON_NAME`), and every other
character problem is a name (`E_CANON_NAME`) or value (`E_CANON_PERCENT`) error. A value is
everything after the first `=` of a parameter, so `a=b=c` is `E_CANON_PERCENT`.

**Action for the spec.** canon.py reports `E_CANON_NAME` for userinfo and ports and should be fixed
to report `E_PARSE_URI`; the next spec revision should add vectors for userinfo, a port, an empty
port (`cell://host:/fn`) and a non-numeric port.

**Proposed wording (5.1).** "The outer grammar is `"cell://" authority-and-path [ "?" query ]`.
The authority is the text between `cell://` and the first `/` (or `?`, or the end); it contains no
`@` (userinfo) and no `:` (port). The path is any characters other than `?` and `#`; `query` is one
or more `&`-separated parameters, and each parameter is a name, `=`, and a value (the value runs to
the next `&` and may contain further `=`). Failures of the outer grammar are `E_PARSE_URI`. The path
is split at its last `/` into a namespace and a function name, which are checked as names
(`E_CANON_NAME`; empty segments fail here). Values are checked as in 5.2 (`E_CANON_PERCENT` for any
character that is neither a `literal` nor part of a `pct-encoded` triple)."

## DEF-03. 5.2 / 5.4 step 3: duplicates versus order, and `asof`

**Problem.** "Out of order: `E_CANON_ARG_ORDER`. Repeated: `E_CANON_ARG_DUPLICATE`" and "parameter
names left to right (grammar, reserved names, duplicates, order)" leave open (a) whether the four
checks run per parameter or as four passes, (b) which code a repeated but non-adjacent name gets
(it is also out of order), and (c) how `asof` is recognised: the vectors `uri-asof-twice`
(`DUPLICATE`) and `uri-asof-not-last` (`ORDER`) are consistent with several algorithms.

**Resolution.** Per the reference, confirmed by probes: a final parameter named `asof` is taken as
the asof parameter first. Then for each remaining parameter, left to right: name grammar
(`E_CANON_ARG_NAME`), name length (`E_CANON_LIMIT`), then if the name is `asof`:
`E_CANON_ARG_DUPLICATE` when a final `asof` exists, else `E_CANON_ARG_ORDER`; a `dm_` name is
`E_CANON_ARG_NAME`; a name equal to the previous one is `E_CANON_ARG_DUPLICATE`; a name below the
previous one is `E_CANON_ARG_ORDER`. So `b&a&a` and `a&b&a` are `E_CANON_ARG_ORDER`, `a&a&dm_x` is
`E_CANON_ARG_DUPLICATE`, `asof&asof&a=1` is `E_CANON_ARG_ORDER`, `asof&a=1&asof` is
`E_CANON_ARG_DUPLICATE`.

**Proposed wording (5.4 step 3).** "3. parameter names. If the last parameter is named `asof`, it
is the asof parameter. Each other parameter, left to right, is checked completely before the next:
its name is a name (2.2; `E_CANON_ARG_NAME`, or `E_CANON_LIMIT` when longer than 64); if it is
`asof`, that is `E_CANON_ARG_DUPLICATE` when there is an asof parameter and `E_CANON_ARG_ORDER`
otherwise; a `dm_` name is `E_CANON_ARG_NAME`; a name equal to the preceding parameter's is
`E_CANON_ARG_DUPLICATE`, and a name that sorts before it is `E_CANON_ARG_ORDER` (so a repetition
that is not adjacent is reported as an ordering error)."

## DEF-04. 5.4: is the signature validated?

**Problem.** `parse(uri, signature)` takes the descriptor's signature, but 5.4 does not say
whether it is checked. The reference uses it as given: a `valid: true` number argument, extra
members, or an argument named `asof` are accepted (with an `asof` argument, every URI then fails
with `E_ARG_MISSING`).

**Resolution (divergence).** The signature is validated first, exactly as inside a descriptor
(section 7): `E_SCHEMA`, `E_CANON_ARG_NAME`, `E_CANON_TYPE`, `E_CANON_LIMIT`, with paths under
`signature`.

**Proposed wording (5.4).** "The signature must be canonical (section 7); a non-canonical signature
is reported with the codes of section 7 before the URI is examined."

## DEF-05. 5.1 / 5.4 step 7: how the `asof` value is checked

**Problem.** The grammar says `asof-param = "asof=" instant`, with no percent-encoding, which would
make `asof=*` and `asof=2024-01-01T00%3A00...` outer-grammar failures (`E_PARSE_URI`) or instant
failures. The reference applies the value percent-encoding rule first: both are `E_CANON_PERCENT`;
an empty `asof=` is `E_CANON_INSTANT`.

**Resolution.** As the reference.

**Proposed wording (5.4 step 7).** "7. `asof`: its value is checked like an argument value
(percent-encoding, `E_CANON_PERCENT`; a bare `*` is not a slice here and is `E_CANON_PERCENT`), then
as an instant (`E_CANON_INSTANT`)."

## DEF-06. 4.5 / 10.1 step 3: when the 32-argument limit is checked

**Problem.** In a URI the argument count is step 4, after every name (5.4). For JSON argument maps
nothing is said. The reference checks the count when it reaches the map, before any member: 33
arguments one of which has an invalid name is `E_CANON_LIMIT`, in `cell.args`, `valid` and
`signature.args` alike. That the limit also applies to `valid` is not stated either.

**Resolution.** As the reference.

**Proposed wording (10.1 step 3).** "An argument map (`cell.args`, `valid`, `signature.args`) with
more than 32 members is `E_CANON_LIMIT`, checked before its members."

## DEF-07. 10.1 step 3: order of checks within `inputs`

**Problem.** For receipt `inputs` and descriptor `inputs`, three rules apply (entry form, strictly
ascending, at most 4096 entries) with no stated order.

**Resolution.** As the reference: every entry first (`E_CANON_HEX` for receipts, name codes for
descriptors), then the order (`E_CANON_SET`), then the count (`E_CANON_LIMIT`). So 4097 unsorted
valid hashes are `E_CANON_SET`.

**Proposed wording.** "`inputs` is checked entry by entry, then for strictly ascending order
(`E_CANON_SET`), then against the 4096 limit (`E_CANON_LIMIT`)."

## DEF-08. 2.2, 3.1, 4.5, 8.1: grammar versus length limit versus reservation

**Problem.** A value can break both its grammar and its length limit. Only strings (3.5) give an
order. The reference: names check grammar, then length, then reservation (a 65-character invalid
name is `E_CANON_NAME`/`E_CANON_ARG_NAME`; a 65-character `dm_...` name is `E_CANON_LIMIT`); numbers
check grammar then length (129 zeros: `E_CANON_NUMBER`); licences check form then length (65 dashes:
`E_CANON_LICENCE`; a 600-character `https://` URL with a space: `E_CANON_LICENCE`). DNS lengths are
part of the DNS grammar (`E_CANON_NAME`), as 4.5 says.

**Resolution.** As the reference.

**Proposed wording (4.5).** "A value is checked against its lexical form first and its length limit
second; argument names are then checked for reserved names."

## DEF-09. 2.3 / 4.5: where the 512-character function-name limit applies

**Problem.** "`function_name`: 512 characters in `<namespace>/<function>`". Cells, references and
URIs carry the namespace and function separately; it is not said that the limit applies to
`ns + "/" + fn` there, nor where in the JCS-ordered walk it is checked, nor whether a namespace
alone (`publisher`) has a limit.

**Resolution.** As the reference: for cells and references, `len(ns) + 1 + len(fn) <= 512` is
checked after all the cell's or reference's own members, and before the receipt members that follow
`cell` (a cell whose name is too long and whose `fn_hash` is bad is `E_CANON_HEX`; with a bad
`computed_by` instead it is `E_CANON_LIMIT`); in URIs after the namespace and the function name; for descriptor `inputs` per
entry. `publisher` on its own has no length limit beyond its DNS name and segments.

**Proposed wording (2.3).** "The 512-character limit applies to the fully qualified name, also when
the namespace and the function name are carried separately (cells, references, URIs); it is
checked after both parts are valid."

## DEF-10. 8.1: the licence has no lexical definition in the prose

**Problem.** "An SPDX licence identifier (`CC-BY-4.0`) or an `https://` URL" does not define either
form: is the identifier checked against the SPDX list? Which characters may a URL contain? Is the
scheme case-sensitive? Only `receipt.schema.json` answers (`^[A-Za-z0-9][A-Za-z0-9.+-]*$`, at most
64; `^https://[!-~]+$`, at most 512).

**Resolution.** The schema's patterns, as the reference does: the SPDX list is not consulted
(`Not-A-Real-Licence` is accepted), `HTTPS://...` and a bare `https://` are `E_CANON_LICENCE`, a
value that starts with `https://` is judged as a URL only.

**Proposed wording (8.1).** "`licence` is either an SPDX identifier, `[A-Za-z0-9][A-Za-z0-9.+-]*`
(at most 64 characters; not checked against the SPDX list), or a URL: `https://` followed by one or
more printable ASCII characters other than space (`%x21-7E`), at most 512 characters in all. A value
starting with `https://` is a URL. Otherwise `E_CANON_LICENCE`; over-long values `E_CANON_LIMIT`."

## DEF-11. 9.1 / 10.2: which code a bad key reference gets

**Problem.** `E_CANON_NAME` covers an invalid "key reference" and `E_CANON_HEX` covers a key id that
is "not lowercase hex of the right length"; for `computed_by` both apply.

**Resolution.** As the reference: split at the first `#`; no `#` is `E_CANON_NAME` (the vector
`receipt-computed-by-bare-key-id`), a bad host is `E_CANON_NAME`, then the part after `#` must be 16
lowercase hex digits (`E_CANON_HEX`; a second `#` lands here).

**Proposed wording (9.1).** "A key reference without `#` or with an invalid host is
`E_CANON_NAME`; the text after the first `#` must be 16 lowercase hex digits (`E_CANON_HEX`)."

## DEF-12. 10.1 steps 2-3: JSON types of typed scalars and the slice marker

**Problem.** Step 2 says "right JSON types" (`E_SCHEMA`), while 3 says "a value whose JSON type does
not match its declared type fails with `E_CANON_TYPE`". The boundary is only visible in the vectors
(`scalar-number-json-number` is `E_SCHEMA`, `scalar-boolean-as-string` is `E_CANON_TYPE`).

**Resolution.** Step 2: `type` must be a JSON string, `value` a JSON string or boolean, an argument
either an object or exactly the string `"*"` (any other string, e.g. `"**"`, is `E_SCHEMA`); null is
`E_SCHEMA`. Step 3: unknown type names, and a string for `boolean` or a boolean for any other type,
are `E_CANON_TYPE`. Within a scalar, `type` is checked before `value` (JCS order). The reference
agrees.

**Proposed wording (10.1 step 2).** "...every argument is the string `"*"` or an object with exactly
`type` (a JSON string) and `value` (a JSON string or boolean)..." and in 3: "A string `value` for
type `boolean`, or a boolean for any other type, is `E_CANON_TYPE`."

## DEF-13. 6.1: what "outside the IEEE 754 double range" means

**Problem.** Overflow is clearly rejected; underflow (`1e-400`) and integers beyond 2^53 are not
addressed.

**Resolution.** As the reference: only numbers that round to infinity are rejected; `1e-400`
parses as 0 and `123456789012345678901234567890` as the nearest double (JCS
`1.2345678901234568e+29`). This never affects a Datumesh hash (no Datumesh object contains JSON
numbers), only the `jcs` kind and which receipts fail with `E_PARSE_JSON` versus `E_SCHEMA`.

**Proposed wording.** "...numbers whose magnitude rounds to infinity are rejected; any other number
is read as the nearest double (so underflow gives 0)."

## DEF-14. 3.5 / D4: Unicode 15.1 normalisation data is needed, not only the assigned list

**Problem.** 3.5 pins the assigned code points to Unicode 15.1 and ships
`tools/unicode-15.1-assigned.txt`, and argues that later Unicode versions give the same NFC answer.
It does not say what an implementation on an older Unicode version must do. Python 3.10's
`unicodedata` is Unicode 13: with it, `"a" U+1E08F U+0316` (U+1E08F is a Unicode 15.0 combining
mark of class 230) is NFC, but under 15.1 it is not (U+0316, class 220, must come first). Any
character assigned between the runtime's version and 15.1 that has a non-zero combining class or a
decomposition has the same problem. An implementation that checks assignment against the 15.1 list
but NFC with older data accepts such strings.

**Resolution.** The package ships Unicode 15.1 tables for assignment, canonical combining classes,
canonical decompositions, primary composites and NFC_Quick_Check=No, generated by
`tools/gen_unicode.py` from Python 3.13's unicodedata 15.1.0, and never calls `unicodedata`. The
tests compare against 15.1 exhaustively (on 3.13) and through 30,693 fixture strings computed with
15.1 (on every version).

**Proposed wording (3.5).** "NFC is decided with Unicode 15.1 normalisation data (or any later
version: by the stability policy the answer is the same for assigned 15.1 code points).
Implementations whose platform has older Unicode data must bring their own; an older version can
accept strings that are not NFC under 15.1."

## DEF-15. 9.2: the key document's members and types are only in the schema

**Problem.** 9.2 lists rules about `host`, `keys`, `id`, `valid_to` and redirects, but not the exact
member set, member types, `alg` (`"ed25519"`), `proto` (`"datumesh/1"`), that `valid_from` is
required and an instant, whether extra members are allowed, or whether `valid_to: null` means
open-ended. `keydoc.schema.json` answers most of this. "No key may appear twice" does not say
whether by id or by public key.

**Resolution.** As the schema and the reference: exactly `host`, `keys`, `proto`; each key exactly
`alg`, `id`, `public`, `valid_from` and optional `valid_to` (a string instant, so `null` is
`E_KEY_DOC`); extra members are `E_KEY_DOC`. Duplicates are rejected by id and by public key. A
small-order or non-canonical `public` is not a document error; receipts signed with it fail with
`E_SIGNATURE` (the reference behaves the same).

**Proposed wording (9.2).** "The document has exactly the members `host` (the DNS name it was
fetched from), `keys` and `proto` (`"datumesh/1"`). Each key has exactly `alg` (`"ed25519"`), `id`,
`public`, `valid_from` (an instant) and optionally `valid_to` (an instant later than `valid_from`;
absent means open-ended). No two keys share an id or a public key. A public key that is not a valid
point is not a document error; signatures made with it fail in step 6."

## DEF-16. 9.3 / 11: responses the spec does not describe

**Problem.** (a) A 200 response with no body (the vector `env` format allows `{"status": 200}`): not
covered; the reference crashes on it. (b) A non-integer status such as `"200"`: not covered. (c)
Resolving keys for a host that is not a DNS name: not covered; the reference accepts a document for
host `Bad` when asked for `Bad`.

**Resolution.** (a) `E_KEY_DOC`. (b) `E_KEY_UNAVAILABLE` (matches the reference). (c) Divergence:
`keys_from_response` and `fetch_keys` return `E_KEY_UNAVAILABLE` for a host that is not a DNS name
(2.1), without fetching anything.

**Proposed wording (9.3, 11).** "A 200 response without a document is `E_KEY_DOC`. Keys are only
resolved for hosts that are DNS names (2.1)."

## DEF-17. 10.1 step 7.1: descriptor checks, and what "obtain" means

**Problem.** "It must hash to `cell.fn_hash` (`E_FN_HASH_MISMATCH`) and be canonical (sections 6-7)"
gives no code or order for a descriptor that hashes correctly but is not canonical. The vector
`recompute` format does not say whether `"descriptor": null` means absent.

**Resolution.** The hash is checked first (over the JCS of the descriptor as given), then the
descriptor is validated and reported with the codes of steps 2-3 and a path under `descriptor`
(the reference does both; e.g. a hash-matching descriptor with a `valid: true` number argument is
`E_CANON_TYPE`). Divergence: `null` is treated as absent (`E_FN_UNAVAILABLE`; the reference
reports `E_FN_HASH_MISMATCH`), and a descriptor given as JSON text is parsed (the reference hashes
it as a JSON string). A `recompute` without `value` is a caller error (`TypeError`); it crashes the
reference.

**Proposed wording (7.1).** "Obtain the descriptor (`E_FN_UNAVAILABLE` if there is none). Its
canonical bytes must hash to `cell.fn_hash` (`E_FN_HASH_MISMATCH`). It must then be canonical
(sections 6-7); a failure is reported with the codes of steps 2-3." Consider a distinct code
(e.g. `E_FN_INVALID`): today a bad descriptor looks like a canonical-form failure of the receipt.

## DEF-18. 10.1 step 7.5: the prose order contradicts the vector `receipt-input-invalid`

**Problem.** 7.5 says: "obtain the input receipt (`E_INPUT_UNAVAILABLE`), which must hash to the
listed hash; verify it through step 6 (`E_INPUT_INVALID`)". In `invalid/receipt-input-invalid` the
supplied input has had its value changed to `"2"`, so it hashes to `2dfc36ba...`, not the listed
`501f744d...`. Read in order, the prose gives `E_INPUT_UNAVAILABLE` ("the one found has another
hash", 10.2), but the vector expects `E_INPUT_INVALID`. The prose and a vector disagree, which 11
calls a bug in the document.

**Resolution.** Follow the vector, as the reference does: look the input up by hash
(`E_INPUT_UNAVAILABLE` if absent), verify it through step 6 (`E_INPUT_INVALID`), then compare its
hash (`E_INPUT_UNAVAILABLE`), then the declared-input check (`E_INPUT_UNDECLARED`), then `asof`
(`E_TIME_ORDER`). A valid receipt supplied under the wrong hash is `E_INPUT_UNAVAILABLE`.

**Proposed wording (7.5).** "For each hash in `inputs`, in order: obtain the receipt offered for it
(`E_INPUT_UNAVAILABLE` if none); verify it through step 6 (`E_INPUT_INVALID`); check that it hashes
to the listed hash (`E_INPUT_UNAVAILABLE`); check that it is a cell of a declared input function
(`E_INPUT_UNDECLARED`); check it has the same `asof` (`E_TIME_ORDER`)."

## DEF-19. 10.1 step 7.2: order of argument checks

**Problem.** "(`E_ARG_UNKNOWN`, then `E_ARG_MISSING`), each with its declared type (`E_ARG_TYPE`)"
can be read per argument or as passes.

**Resolution.** As the reference: all unknown arguments (JCS order), then all missing ones, then
types. A cell missing one argument and mistyping another is `E_ARG_MISSING`.

**Proposed wording.** "First any argument the function does not declare (`E_ARG_UNKNOWN`), then any
declared argument not bound (`E_ARG_MISSING`), then any argument whose type differs from its
declaration (`E_ARG_TYPE`), each in JCS order of names."

## DEF-20. 10.1 step 4: `valid` checks without the descriptor

**Problem.** Step 4 checks that every member of `valid` equals the same-named argument and is a
date, instant or string, but `valid` is an argument map, so it also gets the name rules
(`E_CANON_ARG_NAME`), the 32 limit and slice markers in steps 2-3; and a member of `valid` that is
absent from `cell.args` is not explicitly covered.

**Resolution.** As the reference: names in `valid` are argument names in step 3; a slice marker in
`valid` is `E_SLICE` (step 4, after `cell.args`); a member absent from `cell.args`, different from
it, or of type number/boolean is `E_VALID_MISMATCH`; all before `E_TIME_ORDER`.

**Proposed wording (step 4).** "Every member of `valid` exists in `cell.args`, equals it (same type
and lexical value), and is a date, instant or string (`E_VALID_MISMATCH`)."

## DEF-21. 3.3: a bad calendar date inside an instant

**Problem.** An instant contains "a date as in 3.2"; whether `2023-02-29T00:00:00.000000Z` is
`E_CANON_INSTANT` or `E_CANON_DATE` is only implied by the `E_CANON_INSTANT` row ("not a real time").

**Resolution.** `E_CANON_INSTANT` (the reference agrees).

**Proposed wording (3.3).** "Any failure, including an impossible calendar date, is
`E_CANON_INSTANT`."

## DEF-22. 11: minor format points inferred from the vectors

- `keys` vectors: `key_ids` lists the ids in document order (inferred from `keys/https-document`).
- `receipt` vectors: `canonical` is the signed payload (without `sig`), `sig` is the receipt's `sig`
  member; `level` is the expected verification level. Clear in 11 but easy to misread as the full
  canonical receipt.
- Vector `canonical` strings may contain U+2028 (`jcs/escapes`), which some JSON-lines tooling
  treats as a line break; the conformance runner here escapes all non-ASCII output for that
  reason. Worth a sentence in 11 for harness authors.

# spec-0.4.0

Spec commit `dedd132` (the `spec-0.4.0` draft; the tag is to be put on it, or on a later commit).
This library is 0.4.0 and conforms: of the 978 vectors, the 432 for verifier libraries pass, through
the API and through `tools/run_vectors.py`; the 546 of kinds `formula`, `formula-eval`, `excel` and
`decimal` are for formula evaluators and are skipped (this library evaluates no function).
`tests/test_spec_0_4_0.py` tests each change through the API. Implemented from SPEC.md, units.md,
the schemas and the vectors; `tools/canon.py` was run as a black box only (`check` over probe
vectors, and `tools/oracle_fuzz.py`, 12,000 mutated vectors over three seeds, one with this library on Python 3.10, with no disagreement after DEF-42), and
none of `tools/*.py`, `tests/*`, `crosscheck/*` (except its README) or `DESIGN-0.4.0.md` was read.

| Entry | Status at dedd132 |
|---|---|
| DEF-40 | Resolved (10.1 step 7.1), with the wording proposed here: "An implementation whose interface also takes text in place of a parsed value says which it takes; text is then the obtained bytes." This library takes both: a `str` or `bytes` descriptor is JSON text, as before; so are manifests and member receipts. Closed. |
| DEF-41 | Resolved (10.1 step 7.6), with the wording proposed here: "A verifier that does not attempt step 7 reports no code." No change. Closed. |
| DEF-34 | Open again for `spec-0.4.0`: the tag does not exist yet. README and the packaging test name `spec-0.4.0`; the packaging test pins commit `dedd132`. That commit is not yet on `github.com/datumesh-com/datumesh-spec` either (it was fetched from `/root/datumesh-spec`), so a fresh clone with `--recurse-submodules`, and CI, cannot check the submodule out until it is pushed. |

The changes of the revision, each implemented (SPEC 10.1, "What verifier libraries of `spec-0.4.0` must do"):

- **Step 3.** An `inputs` entry is a receipt hash or a slice entry `slice:<64 hex>:<64 hex>`;
  anything else `E_CANON_HEX` at `$.inputs[i]`; string order and uniqueness as before (receipt
  hashes sort before slice entries); one entry each for the 4,096 limit. Single-cell receipts are
  checked exactly as before.
- **Descriptors (7).** `signature.order` (array of strings, else `E_SCHEMA`; every argument once,
  else `E_CANON_SET`, checked after the arguments and before `returns`) and argument `extent`
  (array of strings or `{"hi", "lo"}` of strings, else `E_SCHEMA`; after `valid`: booleans and blobs
  `E_CANON_TYPE`; ranges only for dates and numbers, `E_CANON_TYPE`; values in their type's lexical
  form with that type's code, integer number range ends `E_CANON_NUMBER`; ascending in the type's
  order `E_CANON_SET`; at most 4096 `E_CANON_LIMIT`, after the order). The formula codes are not
  checked (DEF-46).
- **Slice objects and manifests (4.4, 15.13).** `canonicalize(obj, "slice")` and
  `canonicalize(obj, "manifest")` (never inferred), `slice_id`, `members_hash`, `slice_entry`.
- **Step 7.5.** Each slice entry in its place: the manifest from `recompute["manifests"]`
  (`E_INPUT_UNAVAILABLE` if none), parsed strictly, structure, canonical form, then its slice id and
  members hash (`E_INPUT_UNAVAILABLE`); the slice's function declared (`E_INPUT_UNDECLARED`); each
  member obtained, signature-valid, hashed, a member of the slice and not a second version of a
  cell already seen (`E_SLICE_MEMBER`), `asof` at or before the receipt's. `tx` is the latest of
  every input receipt's and member's `tx`; with none (only empty slices, or no inputs), no rule.
- **Step 7.6.** `E_INPUT_SUPERSEDED`, success at level `signed`, path `$.inputs`, when the value
  differs and `recompute["lineage"]` replaces an input (DEF-45). Step 7.7 runs after it.
- **Envelopes (5.5).** `not_covered` may carry `fault`, one of the six evaluation faults
  (`FAULT_CODES`), exposed as `EnvelopeResult.fault`; on any other outcome, or any other value,
  `E_ENVELOPE`. `error` may now carry `E_SLICE_MEMBER` and `E_INPUT_SUPERSEDED` (they are in 10.2).
- **Units, limits, codes.** `min h d km deg` (the embedded list regenerated); `extent` 4096,
  `members` 1048576; `E_SLICE_MEMBER` after `E_INPUT_UNDECLARED`, `E_INPUT_SUPERSEDED` after
  `E_EVAL_UNAVAILABLE` in `ERROR_CODES`; `SUCCESS_CODES`.

## DEF-42. 4.4: where a version slice's "cell without markers" is checked

**Problem.** 4.4 writes a version slice as `{"cell": <cell without markers>, "from", "to"}` and says
a slice object "is checked in JCS order like a cell", and 10.2 lists `E_SLICE` at step 4 (after all
canonical-form checks) for receipts. It does not say whether a marker in the version slice's cell
is found with the cell (before `from` and `to`) or after the whole object, like a receipt's
`E_SLICE`. `{"cell": <cell with "*">, "from": "bad", ...}` is `E_SLICE` one way and
`E_CANON_INSTANT` the other. I first did the latter; `tools/oracle_fuzz.py` found the reference
tool does the former.

**Resolution.** The cell is checked whole in its place: its canonical form, then no marker
(`E_SLICE`), then `from` and `to`. For a membership slice, "no open or ranged argument" (`E_SLICE`)
comes after the whole object's canonical form (the reference tool agrees).

**Proposed wording (4.4, after "checked in JCS order like a cell").** "A version slice's `cell` is
checked in its place: its canonical form, then that it has no slice marker (`E_SLICE`), before
`from` and `to`. A membership slice without an open or ranged argument is `E_SLICE` after the
canonical form of the whole object."

## DEF-43. 4.4: a range object's `type` comes after `hi` and `lo` in JCS order

**Problem.** "A slice object is checked in JCS order like a cell", but in a range object
`{"hi", "lo", "type"}` the ends come before `type` in JCS order, and the ends' lexical rules depend
on `type`. For a typed scalar the question never arose (`type` < `value`).

**Resolution.** `type` first (`E_CANON_TYPE` for one that is not `date`, `instant`, `number` or
`string`), then `hi`, then `lo`, each by the lexical rules of that type. The reference tool agrees
on the probes tried (an unknown type with bad ends is `E_CANON_TYPE`). The same order for an
extent range (no `type` member there: the declaration's type is already checked).

**Proposed wording (4.4).** "In a range object, `type` is checked first, then `hi` and `lo` by the
lexical rules of that type."

## DEF-44. 4.4: a version slice with `from` after `to`

**Problem.** 4.4 says "a range with `lo` after `hi` is empty, not an error", but says nothing of a
version slice's `[from, to]`.

**Resolution.** Accepted as an empty interval: no version is a member (the reference tool also
accepts it, and an empty manifest for it verifies).

**Proposed wording (4.4).** "... is empty, not an error; so is a version slice with `from` after `to`."

## DEF-45. 10.1 step 7.6: what counts as a replaced input for `E_INPUT_SUPERSEDED`

**Problem.** 7.6 says the verifier "checks whether an entry of the receipt's `inputs` was replaced in
that lineage by a receipt of the same cell with a later `tx` (signature-valid through step 6), or by
an entry for the same slice id with another members hash". Several details are open:
(a) whether "the same cell" includes `fn_hash` (a correction under a rebinding is a different cell
by 4.4, but plausibly "the same cell" to a reader); (b) whether the replacing receipt must hash to
its lineage entry, and be of a declared input function, and have an `asof` at or before the
receipt's (it answers a later evaluation, so it may not); (c) whether a slice replacement needs its
manifest ("with the receipts and manifests of those not listed" suggests it is offered, but the
test is on the entry alone); (d) what a malformed lineage entry means; (e) "superseded at a `tx`
earlier than the receipt's own" reads like a condition but is stated as an explanation.

**Resolution.** (a) The same cell id: `ns`, `fn`, `fn_hash` and arguments. (b) The replacing
receipt must be obtained from `recompute["inputs"]`, be signature-valid through step 6 and hash to
its entry; nothing else is checked (not its `asof`, not its function). (c) No manifest is needed:
an entry `slice:<id>:<other hash>` with the receipt's slice id is a replacement. (d) Entries are
compared as given: a non-string is a `TypeError` (a caller's mistake), any string is taken as an
entry, so a malformed string that starts `slice:<same id>:` counts as a replacement (the reference
tool agrees). (e) Not checked. On every probe the reference tool agreed (replacement missing,
invalid, with another hash, with an equal `tx`, with another `fn_hash`, with a later `asof`;
slice replacements with and without manifest; an empty lineage).

**Proposed wording (7.6).** "... replaced in that lineage: a receipt hash by another entry whose
receipt is obtained, is signature-valid through step 6, hashes to that entry, and has the same cell
id (4.4) with a later `tx`; a slice entry by another entry with the same slice id. Nothing else
about the replacing entry is checked."

## DEF-46. 7 / 15.6 / 10.2: formula descriptor rules in a verifier

**Problem.** 7 says "Formula descriptors always carry it (`E_FORMULA_ORDER`)", and 15.6 makes a
formula descriptor whose body is not the print of its AST, or whose `inputs` differ from the
derived set, non-canonical (`E_FORMULA_NOT_CANONICAL`, `E_FORMULA_INPUTS`). But 10.2 says "The
formula codes of section 15.11 are not verification codes", and 10.1 says a verifier needs no
formula evaluator. Step 7.1 checks the descriptor "is canonical (sections 6-7, units included)":
it is not said whether that includes these three rules for `lang = "formula"`.

**Resolution.** Not checked: a formula descriptor without `order`, with a body that does not
parse, or with other `inputs`, is canonical here if it meets sections 6-7 otherwise. The reference
tool's `check` agrees (it accepts both a `formula` descriptor without `order` and one whose body is
not a formula). `ERROR_CODES` has no formula code.

**Proposed wording (7, after "Formula descriptors always carry it").** "That, and the rules of
15.6, are checked by `define` and formula evaluators; a verifier's canonical-form check of a
descriptor (10.1 step 7.1) does not include them."

## DEF-47. 11: telling a slice object from a manifest in a `slice` vector

**Problem.** The `slice` kind's input is "JSON text of a slice object (4.4) or a manifest (15.13)",
and the outputs differ (`members_hash` and `entry` only for a manifest). An invalid input that is
neither (`invalid/slice-schema`) must still be routed to one of the two checks, and 11 does not say
how.

**Resolution.** A manifest when the parsed input is an object with a `members` or `slice` member,
otherwise a slice object. Every vector agrees.

**Proposed wording (11, `slice` row).** "... or a manifest (15.13), which is an object with a
`members` or `slice` member; anything else is checked as a slice object."

---

# spec-0.3.0

Spec commit `3bac3d4` (the `spec-0.3.0` draft; the tag is to be put on it, or on a later commit).
This library is 0.3.0 and conforms: 365/365 vectors, through the API and through
`tools/run_vectors.py`. `tests/test_spec_0_3_0.py` tests each change through the API.

| Entry | Status at 3bac3d4 |
|---|---|
| DEF-16 | (b) resolved (9.3, 11): only the integer 200 is a retrieved document; `"200"`, any other value, or no status is `E_KEY_UNAVAILABLE`. `keys_from_response` already did this; vectors `invalid/keys-status-string`, `invalid/keys-status-missing`. Fully closed. |
| DEF-17 | Resolved (10.1 step 7.1, 11, D35), with a change here: a `None` descriptor is a JSON `null` offered and is `E_FN_HASH_MISMATCH`; only a `recompute` without the `descriptor` member is `E_FN_UNAVAILABLE`. That was a divergence (null as absent); `verify(..., {"descriptor": None, ...})` now gives another code. A `recompute` without `value` is no longer a `TypeError`: it means evaluation is unavailable (`E_EVAL_UNAVAILABLE`). Text or bytes are still parsed strictly first, as 7.1 now says for bytes; see DEF-40. Closed. |
| DEF-34 | Open again for `spec-0.3.0`: the tag does not exist yet. README and the packaging test name `spec-0.3.0`; the packaging test pins commit `3bac3d4`. |

The other changes of the revision, each implemented:

- **D17 revised (8.2, 10.1 step 7.5).** An input receipt's `asof` at or before the receipt's;
  only a later one is `E_TIME_ORDER` (path `$.inputs[i]`). `tx` must still equal the latest input
  `tx`. Instants compare as strings (3.3).
- **D31 revised (5.5 step 5).** `ok`, like `stale`, accepts a receipt `asof` at or before the
  requested `asof` (`E_ENVELOPE` at `$.receipt.asof` when later). `invalid/envelope-wrong-asof` is
  now valid.
- **`E_EVAL_UNAVAILABLE` (10.1 step 7.6, 10.2, D34).** Added to `ERROR_CODES` after
  `E_VALUE_MISMATCH`. `verify` with a `recompute` that has no `value` returns, once 7.1-7.5 pass,
  `ok=True`, `level="signed"`, `code="E_EVAL_UNAVAILABLE"`, `path="$.value"`. Step 7.7 still
  runs: on pass `blob_checked` is true and the code is kept, on failure the result is the ordinary
  failure (`E_BLOB_MISMATCH`, or `E_SCHEMA` for content of a non-blob value). An `error`
  envelope may carry the code (it is in 10.2, so `check_envelope` accepted it as soon as it was
  in the list). The runner emits `code` only for such a result.
- **3.7.** The 128-character limit was already on the whole media type, with no per-name limit.

## DEF-40. 10.1 step 7.1 / 11: a descriptor given as text, in an API that takes parsed values too

**Problem.** 7.1 says a verifier that obtains the descriptor *as bytes* parses them strictly, and
11 says a vector's `descriptor` is a JSON value, a JSON string being a string value. A library
whose API takes both parsed values and JSON text (this one, everywhere: `canonicalize`,
`verify`'s receipt, `resolved_unit`) must choose what a Python `str` means. The text does not
say, and the two readings give different codes for the same call.

**Resolution.** As for every other argument of this library, a `str` (or `bytes`) descriptor is
JSON text and is parsed strictly first (parse failures keep their codes, `E_PARSE_JSON` or
`E_PARSE_DUPLICATE_KEY`, at path `descriptor`). A caller who wants to offer a JSON string value
passes its JSON text (`json.dumps(s)`); the conformance runner does this for a vector's string
descriptor, so `invalid/receipt-descriptor-text` is `E_FN_HASH_MISMATCH`.

**Proposed wording (7.1, after "parses them strictly first").** "An implementation whose
interface also takes text in place of a parsed value says which it takes; text is then the
obtained bytes."

## DEF-41. 10.1 step 7 / 11: no code when step 7 is not attempted

**Problem.** 7.6 reports `E_EVAL_UNAVAILABLE` when "the verifier cannot evaluate the function".
A verifier that does not attempt recomputation at all (step 7 is optional) also cannot evaluate
it. Only 11 ("`code` ... when `recompute` has no `value`") and the vectors without `recompute`,
which carry no `code`, show that skipping step 7 reports nothing.

**Resolution.** `verify` without `recompute` reports `code="OK"` at level `signed`, as before;
`E_EVAL_UNAVAILABLE` only when `recompute` is given without `value`.

**Proposed wording (7.6).** "... recomputation stops here with `E_EVAL_UNAVAILABLE`. A verifier
that does not attempt step 7 reports no code."

---

# spec-0.2.1

Spec commit `bfe5a38` (the `spec-0.2.1` draft, text-only; not yet tagged). It writes down most of the
rules this log asked for. This library is 0.2.1 and conforms (338 vectors). Two changes were needed:
the 64-level nesting limit of 6.1 (checked after the byte order mark and UTF-8, before anything
else), and an unreadable signature in `parse_uri` is now `E_SCHEMA` in step 5 rather than a
`TypeError`. Everything else the revision states was already done; `tests/test_spec_0_2_1.py`
tests each statement, and its 76 cases agree with the reference tool.

| Entry | Status at bfe5a38 |
|---|---|
| DEF-02 | Fully resolved: 5.1 states the path split and that a value may contain `=`. |
| DEF-03 | Resolved: 5.4 step 3 spells out the per-parameter order (`asof` first, then name, reserved, duplicate, order). |
| DEF-05 | Resolved: 5.4 step 7. |
| DEF-06 | Resolved: 4.5 "Containers" (count before members). |
| DEF-07 | Resolved: 4.5 (`inputs`: entries, order, count). |
| DEF-08 | Resolved: 4.5 "Values and names". |
| DEF-09 | Resolved: 4.5 "Function names". |
| DEF-10 | Resolved: 8.1 licence grammar. |
| DEF-11 | Resolved: 9.1. |
| DEF-12 | Resolved: section 3 (`value` not string or boolean is `E_SCHEMA`). |
| DEF-13 | Resolved: 6.1 (underflow is not an error). |
| DEF-14 | Resolved: 3.5 (15.1 normalisation data or later; bring your own). |
| DEF-15 | Resolved: 9.2 exact members; an invalid curve point is not a document error. |
| DEF-16 | (a) and (c) resolved (9.3); (b) a non-integer status is still not covered. |
| DEF-17 | Hash-before-canonical resolved (7.1). Still open: whether a `null` descriptor is "absent" (this library: `E_FN_UNAVAILABLE`) and whether a descriptor may be given as text. |
| DEF-19 | Resolved: 7.2. |
| DEF-20 | Resolved: step 4 runs in the listed order. |
| DEF-21 | Resolved: 3.3. |
| DEF-22 | Resolved: 11 (`key_ids` order, U+2028/U+2029). |
| DEF-36 | Mostly resolved since 1400247; the form of a well-formed request is still implied. |
| DEF-38 | Resolved: 5.4 step 5 (`E_SCHEMA`, after steps 1-4, JCS order; unknown types `E_CANON_TYPE` when a value is read). |

Remaining open: DEF-16(b), DEF-17 (null descriptor), DEF-34 (tags), DEF-39 below.

**Commit 58eb0d9** (339 vectors). 9.3 now says keys are resolved only for DNS names: `fetch_keys`
does not fetch for any other host (`E_KEY_UNAVAILABLE`, as before), but interpreting a response
offered for such a host gives `E_KEY_DOC` (new vector `invalid/keys-host-not-dns-name`). This
library gave `E_KEY_UNAVAILABLE` there (DEF-16(c)) and now gives `E_KEY_DOC` for a 200, whatever
its body; any other status stays `E_KEY_UNAVAILABLE` (the reference agrees). The other
clarifications were already followed: more than 64 keys is `E_KEY_DOC` (4.5); a mesh host is a DNS
name (`uri_to_https` checks it); a malformed request is a caller error (`TypeError`/`ValueError`,
5.5), which also resolves DEF-36; the `recompute` object (11) matches DEF-17's handling of an
absent descriptor and missing inputs; Ed25519 uses libsodium (PyNaCl), whose cofactorless check
accepts the mixed-order vector. 6.1 (b1924f5) applies the nesting limit to parsed values too,
which resolves DEF-39 as this library already did. Still open: DEF-16(b) (a non-integer status is
now excluded from vectors by 11, but not defined for libraries), whether a `null` descriptor is
absent (DEF-17), and DEF-34 (tags).

## DEF-39. 6.1: the nesting limit for values that are not text

**Problem.** 6.1 limits the nesting of a *text*. `canonicalize`, `verify` and `jcs` also take
already-parsed values, which have no text; the rule does not say whether a parsed value nested more
than 64 levels deep is acceptable.

**Resolution.** Applied to parsed values too: a value whose text would have more than 64 levels is
`E_PARSE_JSON`, so the result does not depend on whether a caller passes text or a parsed object.

**Proposed wording (6.1).** "The same limit applies to a value given to an implementation already
parsed: more than 64 nested arrays and objects is `E_PARSE_JSON`."

# spec-0.2.0

## Status at commit 2a77580

The spec moved from `0c7accc` to `2a77580`, which takes up most of the entries below. This library
now conforms to `2a77580` (317 vectors). Against the reference tool at `2a77580`, 20,000 mutated
vectors (four seeds) and the 447 cases of the test tables give no disagreement at all: the URI
divergences of DEF-01/DEF-02 are gone because the reference now follows the prose. (One table case,
a descriptor given as text with a duplicate member, cannot be expressed as a vector member and was
not compared.)

| Entry | Status at 2a77580 |
|---|---|
| DEF-01 | Resolved: 5.4 step 1 checks the whole outer grammar before any name; reference agrees. |
| DEF-02 | Resolved: 5.1 defines the authority; userinfo and ports are `E_PARSE_URI`; new vectors. |
| DEF-04 | Resolved the other way: `parse` takes the signature as given. This library no longer validates it (DEF-38). |
| DEF-10 | Open for 8.1; the `quote.authorise` rule is now spelled out in 5.5. |
| DEF-17 | Partly: units.md 3 now checks the hash before the descriptor, as 7.1 does; 7.1 itself still does not say it. |
| DEF-18 | Resolved: 7.5 verifies the input receipt, then checks its hash. |
| DEF-23 | Resolved, with a changed order: the cell (structure, canonical), then the hash, then the descriptor (structure, canonical), then substitution; only referenced arguments are examined; 10.2 has a "unit" marker. |
| DEF-24 | Resolved: 7 has a "Check order" paragraph. |
| DEF-25 | Resolved: units.md 1 says `{"arg": "Bad"}` is `E_CANON_UNIT` and other shapes are `E_SCHEMA` in step 2. |
| DEF-26 | Resolved in units.md 2.4 (year `0000`, the 64 limit is `E_CANON_UNIT`, an index unit is a literal but not a rate side); SPEC 7.1 names index units as literals since commit 1400247. |
| DEF-27 | Resolved: verification never resolves units (7.1, units.md 3). |
| DEF-28 | Resolved, with a change: content for a non-blob value is now `E_SCHEMA`; 7.7 runs last; `blob_checked` reports it. But see DEF-35. |
| DEF-29 | Resolved, with a change: integer members are written `0` or `[1-9][0-9]*`; `30.0`, `3e1`, `-0` are `E_ENVELOPE`. The check needs the number's source text, which this library now reads. |
| DEF-30 | Resolved: 5.5 step 2. |
| DEF-31 | Resolved: amount limit, authorise rule and withdrawn currencies stated; new outcome `bad_request` (400) with the URI codes; `error` may not carry `E_ENVELOPE`. |
| DEF-32 | Resolved: 5.5 step 5 binds the receipt to the request (cell id, and `asof` when asked). `check_envelope` takes `request`. See DEF-36, DEF-37. |
| DEF-33 | Resolved for the `unit` input shape (11). |
| DEF-34 | Open until the tag exists. |

New entries for `2a77580`: DEF-35 to DEF-38, at the end of this section.

**Commit 1400247** (vectors and wording only; units.md and the schemas are unchanged, so the embedded
unit list is the same): the two blob receipt vectors carry `"blob_checked": true`, 7.1 names index
units as literals, and 5.5 says that a malformed request description is the caller's error and that
outcomes without a receipt have nothing to bind. This library conforms (317 vectors, no code change).

| Entry | Status at 1400247 |
|---|---|
| DEF-35 | Resolved: the vectors carry `blob_checked` (it was a generator bug). |
| DEF-36 | Resolved: 5.5 now says what this library does. The exact form of a request (64 lowercase hex, an instant) is still implied rather than stated. |
| DEF-37 | Decided by the spec author as written: the binding, `asof` included, applies to `stale` too. Closed. |

**Commit 240a830**: DEF-37 is resolved by a new rule in 5.5 step 5: when the request carried `asof`, an `ok` receipt's `asof` equals it and a `stale` receipt's `asof` is at or before it (instants compare as strings; D31). New vectors `envelope/stale-earlier-asof` and `invalid/envelope-stale-later-asof` (319 in all). This library implements it.
| DEF-38 | Open (minor): what `parse` does with a type outside the six is still implied. |

## Entries written at commit 0c7accc

Spec revision: commit `0c7accc` of datumesh-spec (the `spec-0.2.0` draft, to be tagged once both
libraries conform). Written from SPEC.md, `units.md`, the schemas (including
`envelope.schema.json`) and the vectors only. `tools/canon.py` was again used only as a black box:
its `check` command over vectors I wrote into a scratch copy of the spec, and its `--help` usage
text. It never crashed on these inputs, so no traceback (and no source line) was printed this time.
Nothing under `spec/tests/` was opened.

**All 290 vectors can be reproduced from SPEC.md, units.md, the schemas and the vectors.** None
needed the reference tool. The reference was used to settle the points below, which no vector
decides; the expected codes in the case tables of `tests/test_units.py`, `tests/test_envelope.py`
and `tests/test_blob.py`, and the whole URI table of `tests/test_uri.py` (398 cases in all), were
run through it, and every one agrees except the URI rows marked as the DEF-01/DEF-02 divergences. `tools/oracle_fuzz.py` now also mutates unit, envelope and blob vectors: 23,000 mutated vectors
over five seeds gave no disagreement other than the known URI class of DEF-01/DEF-02 (userinfo,
ports and the empty query, which `spec-0.2.0` and its reference still treat as before).

No deliberate divergence from the reference was added in this step. Open from `spec-0.1.1` and
unchanged in the `spec-0.2.0` text: DEF-01, DEF-02 (the reference still reports `E_CANON_NAME` for
userinfo and ports), DEF-17 and DEF-18 (10.1 step 7.5 still says "obtain ... which must hash to the
listed hash; verify it through step 6", which the vector `receipt-input-invalid` contradicts).

## DEF-23. 7.1 / units.md 3: what resolving a unit checks, and in which order

**Problem.** units.md 3 describes resolution only for well-formed input: substitute the cell's
argument values into the return unit. It does not say:

(a) that the descriptor must be the cell's function. The vector `invalid/unit-fn-hash-mismatch`
expects `E_FN_HASH_MISMATCH`, a code the unit rules never mention;
(b) in which order the cell, the descriptor, the hash and the resolution are checked;
(c) whether the cell must bind exactly the function's arguments (4.4: "A cell binds every argument
its function declares, and no others"), or only the ones the unit refers to;
(d) which codes a referenced argument that is absent or not a string gets (units.md lists only
`E_CANON_UNIT` and `E_SLICE`);
(e) for a rate, whether `of` or `per` is resolved first (it decides between `E_SLICE` and
`E_CANON_UNIT` when both sides are bad).

Also, 10.2 marks codes raised while parsing URIs ("URI") and envelopes ("envelope"), but not codes
raised while resolving a unit, although resolution raises `E_CANON_UNIT`, `E_SLICE`,
`E_FN_HASH_MISMATCH`, `E_ARG_MISSING` and `E_ARG_TYPE`.

**Resolution.** As the reference, probed: (b) the structure of the cell, then of the descriptor
(`E_SCHEMA`, both before anything else), then the cell's canonical form, then the hash
(`E_FN_HASH_MISMATCH`), then the descriptor's canonical form (units included), then resolution.
So a descriptor with a bad unit shape and a wrong hash is `E_SCHEMA`, while a descriptor with a bad
unit literal and a wrong hash is `E_FN_HASH_MISMATCH`. (c) Only referenced arguments are examined:
a cell missing an unreferenced argument, with an extra argument, or with a mistyped unreferenced
argument still resolves, and a slice in an unreferenced argument is fine. (d) A referenced argument
that is absent is `E_ARG_MISSING`; one whose type is not `string` is `E_ARG_TYPE`; a slice marker is
`E_SLICE`. (e) `of` completely (substitution and the currency check), then `per`.

Note that step 7.1 of verification checks a descriptor in the other order: the hash first, then its
structure (DEF-17; the reference agrees), so the same bad descriptor is `E_SCHEMA` in one procedure
and `E_FN_HASH_MISMATCH` in the other. I think (c) is too lax for a protocol that rejects rather
than repairs: a cell that does not bind its function's arguments is not a cell of that function,
and giving it a unit is a guess.

**Proposed wording (units.md 3, new first paragraph).** "Resolution takes a descriptor and a cell
(4.4) and checks, reporting the first failure: the structure of the cell, then of the descriptor
(`E_SCHEMA`); the cell's canonical form; that the descriptor hashes to `cell.fn_hash`
(`E_FN_HASH_MISMATCH`); the descriptor's canonical form (section 7). It then substitutes: for each
argument reference, `of` before `per`, the cell must bind the argument (`E_ARG_MISSING`), not as a
slice (`E_SLICE`), with type `string` (`E_ARG_TYPE`), and its value must be a literal unit, or on a
side of a rate a currency code (`E_CANON_UNIT`). Arguments the unit does not refer to are not
examined." (Or, preferably, check all of 10.1 step 7.2 first.) In 10.2 add a "unit" marker to the
Step column for these codes, and say in 10.1 step 7.1 whether a descriptor's hash or its structure
is checked first, the same way in both procedures.

## DEF-24. 7 / 7.1: checks inside a `returns` object, and step 2 versus step 3 for units

**Problem.** "Within a declaration, `type` is checked first (`E_CANON_TYPE`), then `unit`, then
`valid`" covers argument declarations. For a `returns` object it is not said. Taken literally, "a
`returns` object whose type is not `number` ... fails with `E_CANON_UNIT`" makes
`{"type": "decimal", "unit": "1"}` an `E_CANON_UNIT`, but the reference reports `E_CANON_TYPE`.
Separately, "Any other JSON shape for a unit is `E_SCHEMA`" does not say that this is a step-2
check made over the whole descriptor before any step-3 check: a descriptor with an invalid
`code.lang` (`E_CANON_NAME`, earlier in JCS order) and `"unit": 5` is `E_SCHEMA` in the reference.

**Resolution.** As the reference. Step 2 (whole descriptor first): a declaration has exactly `type`
(a string), `valid` (a boolean) and optionally `unit`; `returns` is a string or an object with
exactly `type` (a string) and optionally `unit`; a unit is a string, `{"arg": <string>}` or
`{"of", "per"}` whose sides are strings or `{"arg": <string>}`. Step 3, `returns` as an object:
`type` must be a known type (`E_CANON_TYPE`), then `number` (`E_CANON_UNIT`), then `unit` must be
present (`E_CANON_UNIT`) and valid (`E_CANON_UNIT`). `returns: "number"` is `E_CANON_UNIT`, an
unknown bare name `E_CANON_TYPE`.

**Proposed wording (7).** "The JSON shapes (declarations, `returns`, units) are checked in step 2
for the whole descriptor (`E_SCHEMA`). In step 3, a declaration is checked `type`
(`E_CANON_TYPE`), then `unit`, then `valid`; a `returns` object is checked `type` (a known type,
`E_CANON_TYPE`; then `number`, `E_CANON_UNIT`), then `unit` (present and valid, `E_CANON_UNIT`)."

## DEF-25. 7.1 / units.md 1: argument references and rate sides that are not well formed

**Problem.** (a) `{"arg": "Bad"}` and `{"arg": "asof"}`: the schema's `unitArg` requires an
argument name, suggesting `E_CANON_ARG_NAME` (or `E_SCHEMA`), while 7.1 says only that the
argument must exist and be a string (`E_CANON_UNIT`). (b) A rate side that is neither a string nor
an argument reference (`{"of": {"of": "USD", "per": "EUR"}, ...}`, `{"of": 1, ...}`): units.md says
"rates of rates cannot be written" and "Each is a currency code ... or an argument reference",
which reads as `E_CANON_UNIT`, but also "a rate is an object with exactly `of` and `per`. Any other
JSON shape is `E_SCHEMA`", which says nothing about the sides.

**Resolution.** As the reference: (a) `E_CANON_UNIT`, since the value names no string argument;
`{"arg": 5}` is `E_SCHEMA`. (b) `E_SCHEMA` for a side that is not a string or an
`{"arg": <string>}` object; a string side that is not a currency code (`"kg"`, `"1"`,
`"index:2015=100"`) is `E_CANON_UNIT`.

**Proposed wording (units.md 1).** "... a rate is an object with exactly `of` and `per`, each a
string or an argument reference. Any other JSON shape, including a rate inside a rate, is
`E_SCHEMA`. A reference whose `arg` is not the name of a `string` argument of the signature
(including a string that is not a valid name) is `E_CANON_UNIT`."

## DEF-26. units.md 2.4 / 7.1: index units

**Problem.** (a) "at most 64 characters" gives no code (`E_CANON_LIMIT` would follow 4.5).
(b) "a real calendar year, month or day, in the forms of SPEC.md 3.2": 3.2's year range
`0001`-`9999` presumably applies, so `index:0000=1` is not a unit, but this is indirect.
(c) SPEC 7.1 calls a literal "a string listed in `units.md`, such as ... `"index:2015=100"`", but
index units are a pattern, not listed; whether an argument reference may resolve to an index unit
(units.md 3: "a literal unit from section 2") follows only if indices count as literals.

**Resolution.** As the reference: (a) `E_CANON_UNIT` (a 65-character index unit is not a unit);
(b) year `0000` is rejected, as are month `00`/`13`, `2023-02-29` and one-digit months; (c) index
units are literals, also as the value of a referenced argument (`index:2015=100` resolves to
itself; `index:2015=0` is `E_CANON_UNIT`).

**Proposed wording (units.md 2.4).** "A string of the form `index-unit` is a literal unit; one
longer than 64 characters, or whose period is not a real year, month or day in 0001-9999, or whose
value is not a canonical number greater than zero, is not a unit (`E_CANON_UNIT`)." In SPEC 7.1:
"a literal: a string listed in `units.md` or an index unit (units.md 2.4)".

## DEF-27. 10.1 step 7: does verification resolve units?

**Problem.** Step 7.1 says the descriptor must "be canonical (sections 6-7, units included)", and 7.1
says "A substituted value must itself be a listed unit ... (`E_CANON_UNIT`)". It is not said whether
step 7 (or any verification step) resolves the receipt's unit. A receipt of `fx_rate` with
`quote = "usd"` has no resolvable unit.

**Resolution.** As the reference: verification never resolves the unit. That receipt is
signature-valid and passes step 7 (`level: recomputed`); `resolved_unit` reports `E_CANON_UNIT`
for the same cell. A client that displays the unit will hit that error.

**Proposed wording (10.1, after step 7).** "Verification does not resolve the receipt's unit; a
receipt whose unit cannot be resolved (units.md 3) can still be signature-valid and fully verified.
A client that needs the unit resolves it separately." (Or add a step 7.4b that resolves it, if a
receipt with no unit should not verify.)

## DEF-28. 10.1 step 7.7: ordering with steps 7.1-7.6, and the verification level

**Problem.** 7.7 "MAY run directly after step 6, without 7.1-7.6". When a verifier recomputes and
also has the content, the order is not stated: content that does not match and a value that does
not match could report either code. Nor is it said what a receipt that passed 7.7 alone is:
"fully verified" is defined as passing step 7, and the vector `receipt/blob-value` (with
`blob_hex`, without `recompute`) expects level `signed`. Content supplied for a receipt whose type
is not `blob` is not covered either.

**Resolution.** As the reference: with `recompute`, 7.1-7.6 run first (`E_FN_UNAVAILABLE` and
`E_VALUE_MISMATCH` win over `E_BLOB_MISMATCH`), then 7.7. Without `recompute`, 7.7 runs after step
6 and the level stays `signed`; with both, `recomputed`. Content for a non-blob receipt is ignored
(the reference does the same). The length is compared before the hash (both are
`E_BLOB_MISMATCH`).

**Proposed wording (10.1 step 7.7).** "... It runs last: after 7.6 when the verifier recomputes,
otherwise directly after step 6. Passing it does not change the level: a receipt that passed steps
1-6 and 7.7 is signature-valid, and one that passed all of step 7 is fully verified. Content offered
for a value that is not a blob is not examined."

## DEF-29. 5.5: "JSON numbers with integral values"

**Problem.** `age_seconds` and `retry_after_seconds` are "a non-negative integer" and "JSON numbers
with integral values, at most 2^53 - 1". Not said: whether `30.0`, `3e1` or `1.0e0` are integral
(they are, as values), whether `-0` is non-negative, and whether the test is on the decimal text or
on the IEEE 754 double the parser produces (6.1 refers to doubles): `0.99999999999999999999` is
not an integer as a decimal but parses to the double 1.

**Resolution.** As the reference: the test is on the double. `30.0`, `3e1`, `-0`, `-0.0` and
`0.99999999999999999999` are accepted (as 30, 30, 0, 0 and 1); `1.5`, `-1`, `9007199254740992`,
`true` and `"30"` are `E_ENVELOPE`; `1e400` is `E_PARSE_JSON` (6.1).

**Proposed wording (5.5).** "... are JSON numbers. Read as IEEE 754 doubles (6.1), their value
must be an integer from 0 to 2^53 - 1, so `30`, `30.0` and `3e1` are the same and `-0` is 0."
(Or require the plain integer spelling `0 / [1-9][0-9]*` on the text, which is stricter and fits
"one spelling" better; envelopes are not hashed, so either is safe.)

## DEF-30. 5.5: which envelope failures are `E_ENVELOPE` and which keep receipt codes

**Problem.** Step 2 checks "the members against the table and the rules above", with `receipt`
defined as "a receipt object (section 8)"; step 4 verifies the receipt "with that procedure's
codes". Whether a `receipt` member that is not a JSON object, or an object that is not a valid
receipt (missing member), fails in step 2 (`E_ENVELOPE`) or in step 4 (`E_SCHEMA`) is open.
Similarly, `reason` "follows the string rules (3.5) with the `summary` limit": the codes of 3.5
(`E_CANON_STRING`, `E_CANON_LIMIT`) or `E_ENVELOPE`?

**Resolution.** As the reference: in step 2 `receipt` must be a JSON object (`"x"`, `[]`:
`E_ENVELOPE`); everything else about it is step 4 with the receipt codes (a missing member is
`E_SCHEMA`, a bad value `E_CANON_NUMBER`, a slice `E_SLICE`, a tampered one `E_SIGNATURE`, an
unknown host `E_KEY_UNAVAILABLE`). Every failure of `reason`, `quote`, `superseded_by`, `trust`,
`error` and the seconds members is `E_ENVELOPE`, including string-rule failures of `reason`
(empty, NFD, control characters, unassigned code points, over 1024 bytes). Members are examined in
JCS order; all of them only produce `E_ENVELOPE`, so only the reported path depends on it.

**Proposed wording (5.5 step 2).** "Check the members against the table and the rules above; every
failure, including the string rules for `reason`, is `E_ENVELOPE`. Here `receipt` need only be a
JSON object; it is checked as a receipt in step 4."

## DEF-31. 5.5: `quote` and `error` details

**Problem.** (a) `amount` is "a number in the form of 3.1 greater than zero": whether the 128
character limit of 3.1 applies. (b) `authorise` is "an `https://` URL in the form of a licence URL
(8.1)", and 8.1 never defines that form (DEF-10); only the schema does (`^https://[!-~]+$`, at most
512). (c) `currency` "a currency code from `units.md`" admits the withdrawn codes kept for
historical rates (`GRD`), which a mesh cannot be paid in. (d) `error` is "a code from 10.2": that
includes `E_ENVELOPE` itself and the URI codes. But `error` is only valid with a 5xx status
(vector `envelope-error-client-status`), and no outcome has a 4xx status other than 402, 403, 404
and 429, so a mesh has no way to report a malformed request (`E_PARSE_URI`, `E_ARG_MISSING`): with
400 it is `E_ENVELOPE`, with 500 it claims a server failure.

**Resolution.** As the reference: (a) 129 characters is `E_ENVELOPE`; (b) the schema's pattern
and limit (`http://`, `HTTPS://`, a bare `https://`, a space, or 513 characters are `E_ENVELOPE`);
(c) `GRD` is accepted; (d) any of the 41 codes of 10.2 is accepted, `OK` and unknown codes are not.

**Proposed wording (5.5).** "`amount`: a number (3.1, at most 128 characters) greater than zero.
`authorise`: `https://` followed by one or more of `%x21-7E`, at most 512 characters.
`currency`: a currency code of units.md 2.1." For (d), either add an outcome for client errors
(e.g. `bad_request`, status 400, member `error`), or state that malformed requests are answered
without an envelope.

## DEF-32. 5.5: nothing ties the receipt to the request

**Problem.** The client check of 5.5 verifies the embedded receipt and its `trust` label, but never
checks that the receipt answers the cell that was requested (its `cell` against the URI's
reference, with `fn_hash` against the function the client resolved) or the requested `asof`
(`ok`: "The receipt answers the cell as of the requested `asof`"). A mesh, or anyone who can make
one return a body, can answer `GET .../fx_rate?quote=USD...` with a valid, primary-labelled receipt
for `quote=GBP`, or for another `asof`, and the envelope passes. Section 12 says envelopes are the
mesh's claims, but this is a check the client *can* make.

**Resolution.** Not implemented, because `check_envelope(status, body, keys)` (the contract's API)
has no request to compare with; the library's documentation says the envelope only states that this
mesh made a well-formed statement about a receipt its signer signed (5.5's last sentence). A caller
must compare `receipt.cell` with `parse_uri(...)` of its request.

**Proposed wording (5.5, new step 5).** "5. If there is a receipt, its `cell.ns`, `cell.fn` and
`cell.args` equal the requested reference's (5.4), and for `ok` its `asof` equals the requested
`asof` when one was given (`E_ENVELOPE`)." Consider also stating what `stale` allows (an older
`asof`).

## DEF-33. 11: details of the `unit` and `envelope` vector formats

- `unit` vectors: `input` is the JSON text of `{"cell", "descriptor"}`. Inferred, as the reference
  does: any other member, a missing member, or a member that is not an object is `E_SCHEMA` (a
  member that is a JSON string is a value, not JSON text to be parsed again).
- `envelope` vectors: the outputs `trust` and `receipt_hash` appear exactly when the body has a
  receipt; for `not_covered` and the other outcomes without a receipt only `outcome` is given.
  `status` is always an integer in the vectors; the spec does not say what a non-integer status
  is (this library: `E_ENVELOPE`, as a status that matches no outcome).
- `receipt` vectors: `blob_hex` is the content for step 7.7. With it, the expected `level` is still
  `signed` (DEF-28).
- The vectors and the schemas agree: `defs.schema.json`'s `currency` and `unitLiteral` lists equal
  the `units-…` blocks of units.md (checked by `tests/test_units.py`), and `envelope.schema.json`
  matches the table in 5.5. The schema's `integer` type for the seconds members also accepts `30.0`
  (JSON Schema 2020-12 counts integral numbers as integers), consistent with DEF-29.

## DEF-34. README of the spec: the `spec-0.2.0` tag does not exist yet

Not a SPEC.md defect, but it affects this library's README: the README tells users to
`git clone --branch spec-0.2.0`, which fails until the commit is tagged. The packaging test runs the
README example against the `spec/` submodule at `0c7accc` and accepts either the commit (now 2a77580) or the tag.
The package metadata links to `blob/spec-0.2.0/SPEC.md`, which also resolves only once tagged.

## DEF-35. 11: `blob_checked` is an output no vector carries

**Problem (2a77580).** Section 11 lists for receipt vectors "`blob_checked` (true) when `blob_hex` is
given", and `vector.schema.json` defines the field, but neither valid vector with `blob_hex`
(`receipt/blob-value`, `receipt/blob-value-recomputed`) contains it. A harness that compares a
runner's output with exactly the fields of the file cannot see the output that 11 requires, and a
runner that emits it differs from the file.

**Resolution.** The runner emits `blob_checked` whenever `blob_hex` is given, as 11 says; the
tests derive the expected value (`true` for valid vectors) from that rule, and would use a
`blob_checked` field if a vector had one.

**Proposed fix.** Add `"blob_checked": true` to the two vector files (the generator should write
it), so that the vectors carry every output 11 names.

## DEF-36. 5.5 step 5: the request's own form, and outcomes without a receipt

**Problem.** "A library takes the requested cell id and `asof` as inputs" does not say what a
malformed request is (a cell id that is not 64 lowercase hex digits, an `asof` that is not an
instant), nor, explicitly, that step 5 is skipped for outcomes without a receipt.

**Resolution.** The request is the caller's data, not the mesh's statement, so a malformed one is
a caller error (`TypeError` for a non-mapping, `ValueError` for bad members or extra members), not
`E_ENVELOPE`. For `not_covered`, `unlicensed`, `payment_required`, `rate_limited`, `bad_request`
and `error` the request is not compared with anything (the reference agrees: `not_covered` with
any requested cell id passes).

**Proposed wording (5.5 step 5).** "... Step 5 applies only when there is a receipt. The requested
cell id is 64 lowercase hex digits and the requested `asof` an instant (3.3); a library rejects a
request that is not, as a caller error, before examining the envelope."

## DEF-37. 5.5 step 5: `stale` and the requested `asof`

**Problem.** For `stale`, the receipt is "the last receipt the mesh knows for the cell", which
would normally answer an earlier `asof` than the one requested, yet step 5 says "The same applies
to the receipt of a `stale` envelope": with an explicit `asof` in the request, a stale receipt
must have exactly that `asof`. Then `stale` can only be served for requests without `asof`, or by
a mesh that once answered exactly that `asof`. If that is intended, it is worth saying; if not,
`stale` needs its own rule (e.g. the receipt's `asof` is not later than the requested one).

**Resolution.** As written, and as the reference does: `asof` equality for `stale` too
(`stale` with a later requested `asof` is `E_ENVELOPE`).

**Proposed wording.** Either "For `stale`, a request with `asof` is answered only by a receipt with
that `asof`" (explicit), or "For `stale`, the receipt's `asof` is not later than the requested
`asof`."

## DEF-38. 5.4: what "taken as given" means for a signature

**Problem.** `parse` "does not check" the signature, but it still has to read argument types from
it. Not said: what happens when the types cannot be read (no `args`, an argument without a string
`type`), or when a type is not one of the six.

**Resolution.** A signature whose argument types cannot be read is a caller error (`TypeError`).
Anything else is used as given: a type outside the six fails when a value is typed with it
(`E_CANON_TYPE`), and nothing else in the signature is examined (a number argument without a unit,
`valid: true` on a number, `returns: "number"` are all accepted). The reference agrees on the
cases it can express (`decimal` is `E_CANON_TYPE`, `blob` types the value as a blob).

**Proposed wording (5.4).** "... `parse` reads only each argument's `type` from it; a value whose
declared type is not one of the six is `E_CANON_TYPE`."
