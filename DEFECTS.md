# SPEC.md defects found while implementing datumesh-verify-py

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
