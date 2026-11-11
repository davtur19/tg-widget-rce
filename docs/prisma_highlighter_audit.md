# Prisma code-block highlighter — native audit (Telegram 13.2.0 / 72799)

Status: **concluded, negative for memory corruption.** No write, use-after-free or
out-of-bounds *write* is reachable from attacker-controlled code text in the
Prisma highlighter as shipped in `libtmessages.49.so` 72799. This lead therefore
does **not** provide a second Telegram-local ACE primitive. What it does provide
is a fully mapped, reproducible harness for the component plus a proof-shaped
argument for why the reachable anomaly classes are exception-mediated rather
than memory-unsafe, so the lead can be closed with evidence instead of a guess.

Owner: reverse-engineering subagent. Date: 2026-11-03.
Artifacts: `lab/prisma_highlighter_audit/` (see `README.md` there).
Target IDB: `<HOME>/ailocal/Telegram/.opencode/idbs/libtmessages_49_arm64_media_annotated.i64`
(input `/tmp/opencode/tg49_72799.so`, md5 `2c0caa68a07fc26f79d13519af6c3526`).

---

## 0. Verdict summary

| Question | Answer | Evidence |
|---|---|---|
| Is the highlighter invoked when a chat with a crafted code block is opened, with no extra tap? | **Yes** | `MessageObject.generateLayout` → `CodeHighlighting.getHighlighted(...)` (§2) |
| Is it invoked from notifications / chat-list previews? | **No** | only 6 call sites in the whole tree, all layout/editor/articler viewer (§2) |
| Does the native code match the public source? | **Yes** — bridge is byte-identical to `PrismaEngine.cpp`; libprisma is upstream master `94640c6` | IDA function map + constant/depth checks (§3) |
| Any write / UAF / overflow reachable from code text? | **No finding.** 2.1M+ ASan/UBSan executions and an invariant-instrumented build produced zero memory errors and zero invariant violations | §6, §7 |
| What *is* reachable? | Exceptions (message renders unhighlighted), and algorithmic cost bounded by `64*len+1024` regex searches | §5, §8 |
| Residual risk | Boost.Regex internals (fixed patterns × hostile text); `grammars.dat` is a trusted asset | §8 |

A **crash is not ACE**. Nothing in this document should be read as a working
exploit; there is none.

---

## 1. Why this lead looked promising

`org.telegram.utils.code.highlight.PrismaHighlighter` is a JNI façade over
Telegram's fork of libprisma, a C++ port of Prism's tokenizer. It parses raw
message text with 3 981 hand-written regular expressions, builds a tree with
raw `new`/`delete` linked-list nodes, and converts it to an `int[]` of spans.
That is exactly the shape of component where a text-triggered heap bug would
live, and it runs on a background worker inside the messenger process.

The previous primitive (widget chat) can insert a message locally containing an
arbitrary `TL_messageEntityPre` / `messageEntityCode` block, so the text and the
language tag are both attacker-controlled. The only open question was whether
the native code has a memory-safety defect.

---

## 2. Java layer: call sites and exact arguments

### 2.1 Entry points (all in `prisma/bridge/PrismaJni.cpp`)

```
nativeCreate(byte[] grammars)                    -> jlong   (PrismaJni.cpp:79)
nativeHighlight(long, String text, String language) -> int[] (PrismaJni.cpp:100)
nativeGetLanguages(long)                         -> String[] (PrismaJni.cpp:124)
nativeGetTokenNames(long)                        -> String[] (PrismaJni.cpp:157)
nativeDestroy(long)                              -> void     (PrismaJni.cpp:152)
```

`nativeHighlight` converts both Java strings with
`GetStringLength`/`GetStringChars` (`PrismaJni.cpp:35-67`) — i.e. raw UTF-16
code units, **including unpaired surrogates**, which Java does not prevent.
That is the only attacker-controlled input that reaches the native code.

The `language` argument is `String.toLowerCase(Locale.ROOT)` + a small alias
table (`PrismaHighlightingService.normalizeLanguage`, `:142-159`), so it is
attacker-influenced too (`fc`→`func`, `fif`→`fift`, `tl-b`→`tlb`,
`c++`→`cpp`, `c#`→`csharp`).

`prisma_android::Engine::highlight` then:

1. rejects empty text or empty language (`PrismaEngine.cpp:222`),
2. `encodeUtf8(text)` — UTF-16 → UTF-8 with a parallel `vector<int32_t>` that
   maps every **byte** back to a UTF-16 index (`PrismaEngine.cpp:134-172`),
3. lowercases A–Z in the language (`:225-227`),
4. `highlighter_->tokenize(bytes, language)` (`:229`),
5. `flatten(tokens, source, 0, source.bytes.size(), -1, tokenNameIds_, ranges)`
   (`:230`), which validates and emits 5 `int32` per syntax node.

### 2.2 Reachability — chat open, no tap

`MessageObject.generateLayout(TLRPC.User)` (`MessageObject.java:8701`) builds
`textLayoutBlocks`; inside it, for a code block:

```java
sb = CodeHighlighting.getHighlighted(blockText.toString(), range.language);   // :8943 (single block)
sb = CodeHighlighting.getHighlighted(blockText.toString(), range.language);   // :8983
sb = CodeHighlighting.getHighlighted(text.subSequence(range.start, range.end).toString(), range.language); // :9406
sb = CodeHighlighting.getHighlighted(text.subSequence(startCharacter, endCharacter).toString(), range.language); // :9433
```

`generateLayout` is called from `MessageObject` measurement paths
(`:2028, :3559, :3726, :3736, :3775, :6871, :8564`) and from
`MessagePreviewParams.generateLayout` (`:519`), i.e. when a `ChatMessageCell`
measures the message. **Opening the chat is enough**; no tap on the code block
is needed (the tap only toggles expansion/selection later).

`CodeHighlighting.getHighlighted` (`CodeHighlighting.java:324-351`) caches a
`LockedSpannableString` (8 entries / 64 KiB, `:319-322`) and dispatches the
native tokenize to a dedicated daemon thread `PrismaHighlight` through
`PrismaHighlightingService` (`:259-294`, `:133-139`). So the native call runs
**off the UI thread**; a fault there kills the process and produces a tombstone
for the `PrismaHighlight` thread, not the main thread.

**No notification or chat-list preview path.** A tree-wide grep for
`CodeHighlighting.` yields only:
`MessageObject` (the 4 sites above), `ui/iv/RichTextCell.java:663`
(`highlightEditable`, the rich-text *editor*), and
`ui/ArticleViewer.java:13936` (instant view). Notification text is produced by
`MessageObject.messageText`/`getName` and never calls the highlighter. The
`CodeHighlighting.Span` references in `MediaDataController`, `CustomHtml`,
`CopyUtilities` are the *entity* class, unrelated to this native path.

### 2.3 What the text can be

The text is the code block's content, i.e. a substring of the message body.
Incoming message length is capped by the server/client (4 096 UTF-16 units for
regular messages), so the native input is at most a few kilobytes. The harness
therefore fuzzes up to 4 096 UTF-16 units (8 192 bytes) which is already above
what the device can deliver.

---

## 3. Native identity: the shipped binary is `PrismaEngine.cpp` + libprisma `94640c6`

The bridge is compiled into the app (not a separate `.so`), so the first job was
to prove which revision of each part is in `72799`. All addresses below are in
IDB `libtmessages_49_arm64_media_annotated.i64` (image base 0, 80 526 functions);
names were added and the IDB saved in place.

| Address | Size | Identity | Proof |
|---|---|---|---|
| `0x99d7ac` | 572 | `JNI nativeHighlight` | matches `PrismaJni.cpp:100-122` exactly: handle==0 → `"Highlighter is closed"`, two `JavaString` ctors, `NewIntArray(count)` at `[x10,#0x598]`, `SetIntArrayRegion` guarded by `count >= 1` at `[x10,#0x698]`, `ReleaseStringChars` in both exits |
| `0x99d9fc`/`0x99da78`/`0x99db04` | 124/108/44 | `JavaString` ctor / `value()` / dtor | n/a |
| `0x99b2c8` | 352 | `prisma_android::Engine::highlight` | vtable offsets for `NewIntArray`/`SetIntArrayRegion`, then `flatten(..., 0, bytes.size(), -1, this+0x20, &result)` |
| `0x99b474` | 2188 | `encodeUtf8` | 4-byte branch (`0xF0|cp>>18`), `0xFFFD` replacement, per-byte `offsets.push_back(start)` |
| `0x99c260` | 112 | `Utf8Text::endOffset` | skips `(b & 0xC0)==0x80`, then `offsets.at()` |
| `0x99bd44` | 568 | `flatten` | `if (a4<a3 || len > a4-a3) throw "Invalid tokenizer range"`; `size/5 >= 0x7FFFFFFB → "Too many syntax tokens"`; `unordered_map::at` with `"unordered_map::at: key not found"`; recursive self-call with `(offset, offset+len)`; final `"Tokenizer changed text length"` |
| `0x99c654` | 476 | `vector<int32_t>` range insert | n/a |
| `0x99c830` | 252 | `tokenNameIds_.at` | n/a |
| `0x17fb564` | 996 | `SyntaxHighlighter::tokenize(const string&, const string&)` | `state.depth=0`, `state.searchesLeft = 64*len + 1024` (`LSL #6` + `0x400`), then `tokenize(state,text,grammar)` and `highlightEmbedded(state,list,0,text,fixed,named)` |
| `0x17fba6c` | 684 | `SyntaxHighlighter::tokenize(State&, string_view, Grammar*)` | first instruction block `if (*(int*)state >= 32) return TokenList(text)` → **kMaxDepth==32 confirmed in the shipped binary**; saves `state.searchesFrom`, resizes back on exit |
| `0x17fbd40` | 2208 | `highlightEmbedded` | self-recursive, calls `highlightParts` twice |
| `0x17fc5e0` | 500 | `highlightParts` | `if (parts.empty()) return`, then per part `appendSlice(..., part.start, part.start+len, ...)` and `syntax.m_children.swap(children)` |
| `0x17fc818` | 932 | `appendSlice` | 24-byte `SliceCursor` vector, `cursors.size()==depth` growth, `node->isSyntax()` split, recursive descent into children |
| `0x17fcbbc` | 3736 | `matchGrammar` | self-recursive, calls `matchGreedy` twice and `tokenize(state,...)` for `inside` |
| `0x17fda54` | 2228 | `matchGreedy` | `find_if` over a 48-byte `GreedySearch` vector + `Pattern::search` inline |

Conclusions:

* The **bridge** (`PrismaEngine.cpp`, `PrismaJni.cpp`) in the shipped binary is
  the file present at `Android/TMessagesProj/jni/prisma/bridge/` in this repo —
  identical guard-for-guard.
* The **engine** in `72799` is *not* the pinned `31a5d6f` (that revision has no
  `State`/`searchesLeft`, no `GreedySearch` cache, no `highlightEmbedded`).
  It is upstream `TelegramMessenger/libprisma` **master `94640c6`**
  ("Update grammars"), proven by the `kMaxDepth==32` guard, the
  `64*len+1024` budget, the 48-byte greedy cache, and `highlightEmbedded` /
  `highlightParts` / `appendSlice` all being present.
* `assets/grammars.dat` in `72799` (md5 `aab771533f6455a2aed4535542d07055`,
  635 267 bytes) is **newer than any public libprisma commit** (master has
  634 492). The audit therefore fuzzes the **shipped grammar blob**, not the
  repo's, so grammar-level behavior matches the device.

---

## 4. Memory model of the parser (the only place a write could come from)

Everything else in the pipeline is `std::string` / `std::vector` /
`std::unordered_map`, i.e. bounds-checked by construction. The hand-managed
memory is `TokenList` (`libprisma/TokenList.h`, `TokenList.cpp`):

* circular doubly-linked list with a **head sentinel**; `~TokenList` walks
  `head->next` until it sees `head` again and `delete`s each node, then the head;
* `Text` node holds a `std::string_view` **into the caller's text buffer**;
* `Syntax` node owns a child `TokenList` by value plus `m_type`, `m_alias`,
  `m_length`;
* `addAfter(node, ...)` and `removeRange(node, count)` are the only mutators;
  `removeRange` does `node->next = item->next; node->next->prev = node;
  delete item;`.

So a write primitive requires one of:

* (A) `removeRange` deleting the **head sentinel** → later `addAfter` writes
  through a freed `head` (`node->next = newNode`), or
* (B) a node being `delete`d while still reachable from a live `currentNode`
  iterator → write into freed memory on the next `addAfter`, or
* (C) a double free through two links to the same node.

### 4.1 (A) is unreachable — `removeCount` cannot overrun

`matchGrammar` computes `removeCount` by walking from `currentNode` and stops at
`head`:

```cpp
for (TokenListPtr k = currentNode;
     k != tokenList.head && (p < to || !k->isSyntax()); k = k->next)
{ removeCount++; p += k->length(); }
removeCount--;
```

`removeCount` therefore equals the number of *real* nodes from `currentNode`
to the last one; `removeRange(removeFrom, removeCount)` starts at
`removeFrom->next == currentNode`, so it stops exactly on the last real node and
the final `item == head` exits by `i == count`, not by deleting head. The only
insertion between the count and the removal is the optional `before` node,
which is *prepended* (`removeFrom = addAfter(currentNode->prev, before)`), so the
removed set is unchanged.

`removeRange` is also reached from `appendSlice`-built lists only through
`~TokenList`, and `highlightParts` only *swaps* whole child lists.

### 4.2 (B) is unreachable — `currentNode` is re-seated before use

In the greedy branch the code may advance `currentNode` across nodes
(`while (from >= p)`), but then:

* `if (currentNode->isSyntax()) continue;` — the **head sentinel inherits the
  base `TokenListNode::isSyntax()` which returns `true`**, so head can never
  reach `dynamic_cast<Text&>(*currentNode)` or the removal path;
* after `removeRange`, `currentNode` is immediately overwritten with the freshly
  allocated `Syntax` returned by `addAfter(removeFrom, ...)`, so the loop
  increment `pos += currentNode->length(), currentNode = currentNode->next`
  never touches a removed node;
* the nested rematch
  `matchGrammar(..., currentNode->prev, pos, &nestedRematch)` starts iterating
  at `currentNode->prev->next == currentNode`, and because `currentNode` is a
  `Syntax` node with `length == match.size() > 0`, the nested pass can only
  remove nodes *after* it (a match starting at its first byte hits the
  `isSyntax()` continue; a match starting earlier is never visited because the
  nested pass does not walk backwards). `removeRange` repairs `next`/`prev` of
  the surviving neighbours, so the outer iterator stays valid.

### 4.3 (C) is unreachable — links are only ever written in one place each

`addAfter` and `removeRange` set both directions of every affected edge; no path
unlinks a node without deleting it, and no path links a node twice.

### 4.4 The second, independent gate: `flatten`

Even if the tokenizer produced a structurally wrong tree, nothing reaches the
JVM until `flatten` accepts it (`PrismaEngine.cpp:174-203`):

* `offset > limit || node.length() > limit - offset` → `"Invalid tokenizer range"`
* `ranges.size() > INT32_MAX - 5` → `"Too many syntax tokens"`
* `names.at(type)` / `names.at(alias)` → `std::out_of_range` (both are always in
  the set: `validateGrammars` inserts every token name and every pattern alias,
  and `""` is seeded)
* recursion limit is implied by the tokenizer's `kMaxDepth == 32`
* closing `offset != limit` → `"Tokenizer changed text length"`

and `Utf8Text::endOffset` cannot index past `offsets` because
`offsets.size() == bytes.size() + 1` by construction (`encodeUtf8` pushes one
entry per emitted byte, then one terminator) and every call site passes
`byteOffset <= bytes.size()`.

### 4.5 The third gate: Java `validateRecords`

`PrismaHighlighter.java:72-104` rejects any record array that is not
non-decreasing, non-empty, inside `text.length()`, name-index in range, parent
index `< own index`, and code-point aligned. `PrismaTokenStyles.resolve`
(`:103-137`) then indexes `nameStyles[typeId]` with that validated id. So even a
native logic error surfaces as `IllegalStateException` (logged, message renders
without highlighting), never as an out-of-bounds Java access.

---

## 5. Enumerated candidate bug classes and their disposition

| # | Candidate | Disposition |
|---|---|---|
| 1 | `removeRange` deletes head → dangling list root (write into freed heap) | **Unreachable**, §4.1; asserted in the instrumented build, never fired |
| 2 | `currentNode` use-after-free after a nested rematch | **Unreachable**, §4.2; ASan-clean over the whole corpus |
| 3 | double free via duplicated links | **Unreachable**, §4.3 |
| 4 | UTF-8 length expansion (surrogate pairs → 4 bytes) overflow | `encodeUtf8` uses `std::string` growth; `offsets`/`bytes` sized from the same loop; `text.size() > INT32_MAX` rejected (`PrismaEngine.cpp:135`) |
| 5 | `offsets.at()` out of range in `endOffset` | Impossible: `offsets.size() == bytes.size()+1`, callers clamp (§4.4) |
| 6 | ranges array overflow / `jsize` truncation | Guard at `INT32_MAX-5`; `NewIntArray` is additionally guarded by `count>=1`; the JVM caps at `INT_MAX` anyway |
| 7 | Token-name / alias id out of range → OOB in Java styles | Both ids come from `unordered_map::at` over a validated name set; Java re-validates |
| 8 | Recursion depth (stack overflow) | `kMaxDepth == 32` in `tokenize` (binary-confirmed at `0x17fba6c`) bounds *language* nesting; `flatten`/`appendSlice` depth is bounded by that tree depth. The **nested-rematch** recursion inside `matchGrammar` has no depth counter — see §8.1 |
| 9 | Integer truncation of `size_t` lengths | All lengths are `size_t`; the only narrowing is `static_cast<int32_t>` of UTF-16 offsets, and `text.size() <= INT32_MAX` is enforced first |
| 10 | Lifetime bug across `nativeCreate`/`nativeHighlight`/`nativeDestroy` | `Engine` is a raw pointer owned by `finalize`-free Java object guarded by `synchronized` (`PrismaHighlighter.java:54-70, 199-205`); `tokenize`/`close` cannot interleave; one `PrismaHighlightingService` singleton, one worker thread |
| 11 | `Pattern::search` invalid iterator range when `pos > text.size()` | **Provably unreachable** (§5.1) |
| 12 | `matchGreedy` cache stale across texts | `State.searchesFrom` partitions the cache per `tokenize(text)` call and truncates on exit; `tokenize` for embedded content uses its own partition |
| 13 | `appendSlice` slicing outside the source list | Instrumented assertion `to <= total`, `from <= to`, `part.start+len <= content.size()`; never fired |
| 14 | `syntax.m_children.swap()` on a non-`Syntax` node | `parts` is only populated in the `type()=="embedded-language"` branch where the node is a `Syntax` |
| 15 | Boost.Regex internal bug on fixed pattern × hostile text | **Not covered** — residual risk, §8 |
| 16 | `grammars.dat` malformed / attacker-writable | Loaded once from `getAssets()` (`CodeHighlighting.java:262-273`); `validateGrammars` (`PrismaEngine.cpp:56-117`) checks the whole structure including every index; not text-reachable |

### 5.1 Why `pos > text.size()` cannot happen (candidate 11)

`pos` accumulates `node.length()` from `startPos = 0` over a list whose total
length starts equal to `text.size()`. Every replacement preserves the total:

`before + match + after` where `before = str.substr(0, from)` and
`after = str.substr(from + match.length())`. If `from + match.length() <=
str.size()` the sum is exactly `str.size()`. If not — i.e. `to > p` when the
affected-node walk ends — `after` is empty and the total would grow. But the walk
`while (p < to || !k->isSyntax())` only stops early at `head`, and there
`p == total >= to` because `to = matchIndex + match.length() <= text.size()`
(the regex match lies inside `text`) and the induction hypothesis says
`total == text.size()`. A caught exception can leave a *partially rebuilt* list,
but the parent splices it in as a child whose declared length is
`match.size()`, so the parent's total is unchanged; the inconsistency stays
inside that child and `flatten` rejects it before any record is emitted.

---

## 6. Harness

`lab/prisma_highlighter_audit/` builds four artefacts from the *shipped*
sources and the *shipped* grammar blob:

```
harness/build_all.sh   # fuzz_highlight, sweep, sweep_checked      (31a5d6f tree)
harness/build_new.sh   # fuzz_new, sweep_new                       (94640c6 tree = shipped)
harness/patch_checked_new.py   # 9 invariant assertions, see below
```

The fuzz target reproduces `nativeHighlight` exactly: it decodes its input as
raw UTF-16LE (unpaired surrogates included, as a Java `String` may contain),
selects the language from a byte, and calls
`prisma_android::Engine::highlight`. `PrismaEngine.cpp` is compiled verbatim, so
`validateGrammars`, `encodeUtf8`, `flatten` and the `unordered_map::at`
lookups are the shipped ones.

Grammar blob: `refs/grammars_72799.dat` = `assets/grammars.dat` extracted from
the installed 13.2.0 APK (`aab77153…`). Stats from
`harness/dump_grammars.py`: 3 981 patterns, 939 grammars, 390 language
identifiers, 891 token names; 649 greedy (`y`) patterns, 1 172 lookbehind (`l`)
patterns, 981 `inside` edges, 13 self-recursive grammars and 81 cyclic grammar
SCCs (the deep-nesting paths).

Instrumented build (`checked_new/`), i.e. the invariants of §4 turned into loud
aborts, plus ASan:

1. `matchGrammar`: `pos <= text.size()`
2. `removeRange`: `item != head` (would delete the sentinel)
3. `~TokenList`: walk terminates within `length + 2`
4. `addAfter`: `node != nullptr`
5. `matchGreedy`: `searchesFrom <= searches.size()`
6. `appendSlice`: `from <= to` and `to <= total source length`
7. `highlightParts`: `part.start + part.length <= content.size()`
8. `highlightEmbedded`: `pos <= text.size()`
9. `matchGrammar`: `pos <= text.size()` (both paths)

---

## 7. Empirical results

### 7.1 Deterministic sweep — all 390 languages × 19 hostile inputs

```
build/sweep_new        (94640c6, ASan)   runs=7410  exceptions=0  records=257443  max=400
build/sweep_checked_new (instrumented)   runs=7410  exceptions=0  violations=0
```
Inputs include the grammar "soup", 64-deep parenthesis nesting, 48-deep bracket
nesting, 40-deep tag nesting, 32-deep comment nesting, unterminated string and
comment, 400-byte single line, 300 digits, Fift/FunC `//`/`;;` comments,
HTML with `<style>`/`<script>`, JS template strings, JSON, Markdown fences, CSS,
C++ templates, and empty input.

### 7.2 Coverage-guided fuzzing (ASan, libFuzzer)

Three campaigns, all on the shipped `grammars.dat`:

| Campaign | Build | Workers | Languages | Execs | Final coverage |
|---|---|---|---|---|---|
| generic | `fuzz_highlight` (31a5d6f) | 4 | all (selector byte) | 387 486 | 1 427 edges |
| pinned | `fuzz_new` (94640c6) | 8 | js, html, markdown, cpp, css, php, python, brightscript | 1 147 525 | 1 091 – 1 281 edges/lang |
| pinned + invariants | `fuzz_checked_new` | 4 | js, html, markdown, cpp | 1 482 207 | 1 124 – 1 281 edges/lang |

**Total ≈ 3.0 M executions, 0 AddressSanitizer reports, 0 invariant aborts,
0 crashes, 0 timeouts.** (Counts as of 2026-11-03 06:45 UTC; the last campaign
was still running and saturated — per-language coverage had been flat for
~20 minutes.) Corpus: 4 191 distinct coverage-interesting inputs (17 MB) in
`corpus/main` plus per-language corpora totalling ~153 MB.

`-use_value_profile=1 -max_len=4096` (≥ the device's maximum code-block size).
Languages chosen because they own the deep `inside`/self-recursive grammars
(JavaScript has a 6-grammar SCC and self-recursion; HTML embeds CSS+JS;
Markdown embeds everything; BrightScript is the grammar named in the
`kMaxDepth` comment).

The one artifact produced is `refs/slow_unit_html.bin` (741 bytes). Re-measured
through `build/one_new` it takes **49 ms**, i.e. the "slow" classification was a
noise spike on a loaded machine, not reproducible slowness. No algorithmic
pathology was found at device-sized inputs.

---

## 8. What is real, but not ACE

1. **Algorithmic cost is bounded, not eliminated.** `searchesLeft =
   64 * text.size() + 1024` (`SyntaxHighlighter.h:57-78`,
   `SyntaxHighlighter.cpp:66-70`) caps the number of regex *searches*; each
   search is still a Boost.Regex match of one of the 3 981 fixed patterns
   against up to 4 KiB of attacker text. A pattern with catastrophic
   backtracking would be bounded only by Boost's own matcher, and Boost is the
   one component in this path that was not audited line by line. This is a DoS
   surface, not a write. It is also the only way to make the device spin inside
   `nativeHighlight` (worker thread, so an ANR is unlikely — the process just
   burns CPU).
2. **`grammars.dat` is trusted.** `validateGrammars` is a real structural
   validator (every count, every string length, every pattern/grammar index,
   trailing bytes), but it is not a proof of pattern safety. It only matters if
   an attacker can replace an app asset, which is a different (and already
   privileged) capability.
3. **`match_prev_avail` + `text.data() + pos`.** `Pattern::search` passes
   `text.data()+pos` to Boost, which is out-of-bounds if `pos > size`. §5.1
   shows `pos` cannot exceed `size`, and the instrumented build asserts it. If a
   future grammar change breaks the length invariant, this becomes an
   out-of-bounds *read* of unbounded length — a crash/info-flow bug, still not a
   write.
4. **Two lookbehind patterns have no capture group** (`\/\/.*` flags `ly` for
   `fift`, `;;.*` flags `ly` for `func`). `m[1]` is then out of range, but
   Boost's `match_results::operator[]` is bounds-checked
   (`match_results.hpp:199-209` returns `m_null`), so `matched` is false and the
   lookbehind branch is skipped. Verified in source, not a bug.

### 8.1 Residual: nested-rematch stack depth has no explicit cap

`94640c6` removed the `thread_local matchDepth` counter that `31a5d6f` had and
replaced it with `state.searchesLeft`. The `matchGrammar` self-call that
performs a nested rematch

```cpp
if (removeCount > 1)
    matchGrammar(state, text, tokenList, grammar, currentNode->prev, pos, &nestedRematch);
```

is therefore bounded only by (a) `rematch->reach` growing, and (b) the search
budget `64 * len + 1024`. Since reach grows by at least one byte per level, the
worst-case nesting depth is on the order of `text.size()` — 4 096 for a
maximum-size code block. Measured frame size in the shipped binary:
`matchGrammar` `frsize = 0x100` (+ saved registers, ≈0x140 ≈ 320 bytes), so
≈4 000 levels ≈ 1.3 MB against a ~1 MB default Java thread stack
(`Executors.newSingleThreadExecutor` → `new Thread(task, "PrismaHighlight")`,
`CodeHighlighting.java:133-139`).

Arithmetically this can overflow the stack; constructing it requires a greedy
pattern that spans several nodes, repeatedly, with strictly growing reach, in
one language — a contrived shape. **Measured**: the instrumented build records
the maximum nesting depth of this recursion, and over the whole corpus it never
exceeded **6**:

```
deterministic sweep (390 languages × 19 inputs)          max depth 5
corpus/main (4 191 coverage-interesting inputs)          max depth 6
corpus/pinned/javascript (1 688 inputs)                  max depth 5
corpus/pinned/html       (2 263 inputs)                  max depth 5
corpus/pinned/markdown   (1 316 inputs)                  max depth 5
corpus/pinned/cpp        (2 201 inputs)                  max depth 5
```

6 × 320 bytes ≈ 2 KB against a ~1 MB stack. So this is a bound worth knowing,
not a reachable crash: no SIGSEGV, no timeout and no sanitizer report in 2.1 M
executions. If a future grammar change made multi-node greedy matches nest, the
guard to add is a depth counter at the top of `matchGrammar`.

---

## 9. Device plan (only if a candidate ever appears)

Not executed, because there is no candidate. It is recorded so a future agent
does not have to re-derive it:

1. Build the PoC message with the existing widget-chat primitive (insert a
   `TL_messageEntityPre`/`Code` block whose text and language are the fuzzer
   artifact).
2. `adb logcat -c`; open the chat containing the message (this alone runs
   `generateLayout` → `getHighlighted` → `nativeHighlight` on the
   `PrismaHighlight` thread).
3. `adb shell am force-stop org.telegram.messenger.beta` then
   `am start` — **no reboot**.
4. `adb logcat -d` and `adb shell ls /data/tombstones` for a
   `DEBUG: *** *** ***` tombstone; the crashing thread name is the discriminator
   between a highlighter fault (`PrismaHighlight`) and anything else.
5. Treat a crash as **not** ACE. Only a faulting instruction inside
   `0x99b2c8..0x99c900` or `0x17fb500..0x17fe000` with a wild pointer *and* a
   reproducible corruption (not just a null/exception) would reopen the lead.

---

## 10. Falsification: what would change this verdict

* A `removeRange` call with `count >` the number of nodes from `node->next` to
  the last real node. Requires either a broken `prev` link or a list edited
  between the count and the removal — both excluded above and asserted in
  `checked_new`.
* A path where `parts[]` outlives the node it points at, or where
  `part.start + length` exceeds `content.size()` at the time of `appendSlice`.
  Asserted; never fired.
* A `Text` node surviving its `std::string_view` source. Only three buffers are
  ever viewed: `source.bytes` (alive for the whole `highlight`), the
  `string_view match` (a sub-view of the same), and `content` in
  `highlightParts` (alive until `appendSlice` has copied the spans out, then
  cleared). A future refactor that returns a `TokenList` from a temporary string
  would break this.
* A Boost.Regex memory-safety bug reachable from one of the 3 981 shipped
  patterns. Out of scope here; would need Boost-level fuzzing per pattern
  (`harness/dump_grammars.py` can emit the pattern list).

---

## 11. Artifacts

```
lab/prisma_highlighter_audit/
  README.md                       manifest + exact repro commands
  harness/fuzz_highlight.cpp      libFuzzer/standalone target (faithful nativeHighlight)
  harness/sweep.cpp               deterministic 390-language × 19-input sweep
  harness/make_corpus.py          seed corpus generator
  harness/dump_grammars.py        grammars.dat parser / stats / pattern dump
  harness/patch_checked.py        invariant instrumentation (31a5d6f tree)
  harness/patch_checked_new.py    invariant instrumentation (94640c6 tree)
  harness/build_all.sh            builds fuzz_highlight, sweep, sweep_checked
  harness/build_new.sh            builds fuzz_new, sweep_new (shipped generation)
  harness/run_pinned.sh           per-language libFuzzer launcher
  checked/  checked_new/          instrumented libprisma copies
  refs/grammars_72799.dat         assets/grammars.dat from the installed 13.2.0 APK
  refs/languages_72799.txt        390 language identifiers
  refs/slow_unit_html.bin         the only fuzzer artifact (49 ms, not a bug)
  refs/ida_function_map.txt       IDB names/addresses written this session
  corpus/                         seed + accumulated interesting inputs
  logs/                           campaign logs (coverage over time)
  out/                            artifact dir (one slow-unit, no crashes)
```

IDB: `<HOME>/ailocal/Telegram/.opencode/idbs/libtmessages_49_arm64_media_annotated.i64`
— saved in place with 18 `prisma_*` function names and 4 audit comments
(persisted; verified by re-querying the names after the save).
