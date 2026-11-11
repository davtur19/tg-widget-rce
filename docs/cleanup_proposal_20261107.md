# Proposta di pulizia — cartelle Android (`telegramandroidwidget/`) — 2026-11-07

**Solo proposta: nessun file è stato cancellato.** L'orchestratore decide le singole
cancellazioni dopo revisione. Host-only.

Scope: `telegramandroidwidget/` con esclusioni **`c2/`**, **`lab/qjs_postsnapshot/ios_n1/`**,
i file attivi dei subagent in corso e tutto ciò che è referenziato da report/certificazioni.

Regola applicata: `DELETE-SAFE` = ridondante (byte-identico) o ricostruibile e **non
referenziato**; `DELETE-MAYBE` = verifica orchestratore (stale, non referenziato o
referenziato solo marginalmente); `KEEP` = evidence/report/cert/attivo o referenziato da
un report.

Totale albero (esclusi c2/ e ios_n1/): **19 GB**. Candidati individuati: ~**14.2 GB**
(~9.8 GB DELETE-SAFE + ~4.4 GB DELETE-MAYBE — stime `du`, da confermare).

## Tabella candidati

| path | size | mtime | classe | motivo |
|---|---|---:|---|---|---|
| `lab/qjs_fork_audit/build/` | 1.50 GB | 2026-11-07 | DELETE-SAFE | 39 binari fuzz (fuzz_twidget_renderer ecc.) ricompilabili dagli `fuzz_*.cpp` in-tree |
| `lab/qjs_fork_audit/build-canon/` | 850 MB | 2026-11-07 | DELETE-SAFE | build ninja ricompilabile |
| `lab/dav1d_coldstart_fuzz/build/` | 908 MB | 2026-11-03 | DELETE-SAFE | build fuzz dav1d ricompilabile |
| `lab/decoder_fuzz/build/` | 729 MB | 2026-11-02 | DELETE-SAFE | build fuzz decoder ricompilabile |
| `lab/local_message_media_ace/build_ffmpeg_*` (5 dir) | 740 MB | 2026-11-03 | DELETE-SAFE | build ffmpeg ricompilabili |
| `lab/libvpx_deep/build/` | 274 MB | 2026-11-03 | DELETE-SAFE | build libvpx ricompilabile |
| `lab/qjs_advisories/build{,‑gcs‑latest,‑gcs‑7a,‑asan‑latest,‑asan‑7a}/` | 578 MB | 2026-11-05 | DELETE-SAFE | 5 build duplicate del fuzzer advisories |
| `lab/qjs_fork_audit/litehtml{,-clamped}/build-asan/` + build-rel* | 740 MB | 2026-11-07 | DELETE-SAFE | build ASan litehtml ricompilabili (sorgenti in-tree) |
| `lab/qjs_fork_audit/fuzz_new_fork/build{,_gcs}/` | 332 MB | 2026-11-07 | DELETE-SAFE | build fuzz ricompilabili |
| `lab/qjs_fork_audit/build-canon-{fuzzcmake,asanonly,fuzz,stl}/`, `build-tgfork*`, `build-cmake-*` | 533 MB | 2026-11-07 | DELETE-SAFE | build sperimentali ricompilabili |
| `lab/qjs_fork_audit/round7/build/` | 118 MB | 2026-11-07 | DELETE-SAFE | build run_e22_* ricompilabile (`round7/src` resta KEEP: referenziato da REPORT §9) |
| `lab/qjs_fork_audit/widget-sandbox/packages/` | 160 MB | 2026-11-07 | DELETE-SAFE | dipendenze npm rigenerabili |
| `lab/qjs_parser_audit/build/` | 204 MB | 2026-11-05 | DELETE-SAFE | build ricompilabile |
| `lab/sony_webp_chain/build/` | 132 MB | 2026-11-02 | DELETE-SAFE | build ricompilabile |
| `lab/qjs_n1/build/` | 125 MB | 2026-11-07 | DELETE-SAFE | build ricompilabile (N1 chain; sorgenti/poc restano) |
| `lab/qjs_fuzz{,_new}/build*`, `lab/qjs_state_fuzz/build/` | 418 MB | 2026-11-05 | DELETE-SAFE | build fuzz ricompilabili |
| `lab/v8_corpus/build-*` (6 dir) | 230 MB | 2026-11-05 | DELETE-SAFE | build V8/quickjs ricompilabili |
| `lab/sqlite_db_ace/build/` | 126 MB | 2026-11-03 | DELETE-SAFE | build ricompilabile |
| `lab/tgs_local_ace/fuzz/`, `lab/tgs_uaf_weaponization/build_*_asan/` | 202 MB | 2026-11-02/03 | DELETE-SAFE | binari fuzz ricompilabili |
| `lab/regexp1827_arena/build/`, `tlottie_gzip_audit/build/`, `qjs_regexp_audit/appmodel_*` | 85 MB | 2026-11-01/02 | DELETE-SAFE | build ricompilabili |
| `lab/qjs_fork_audit/zeroday_hunt_parser/device/updates/72929/base.apk` | 79.9 MB | 2026-11-07 | DELETE-SAFE | **byte-identico** a `Telegram-Beta-7292.apk` (sha `fe19d515…`); il secondo resta KEEP |
| `evidence/db_20261105/cache4.release72801.db` | 114.7 MB | 2026-11-05 | DELETE-SAFE | **byte-identico** a `…release72801.widget.db` (sha `b7eb5c1a…`); uno dei due basta |
| `lab/qjs_fork_audit/corpus_*` (34 dir) | ~250 MB | 2026-11-07 | DELETE-MAYBE | corpora fuzz twidget/litehtml; `corpus_canon_struct`/`corpus_canon_paint` citati da REPORT → escluderli o consolidare |
| `lab/qjs_state_fuzz/corpus/` | 233 MB | 2026-11-05 | DELETE-MAYBE | corpus fuzz state; i seed dei crash sono nei logs/artifacts (che restano) |
| `lab/decoder_fuzz/corpus/` | 528 MB | 2026-11-02 | DELETE-MAYBE | corpus video; i crash rilevanti sono documentati in `notes/decoder_fuzz.md` |
| `lab/dav1d_coldstart_fuzz/corpus/` | 277 MB | 2026-11-03 | DELETE-MAYBE | idem |
| `lab/libvpx_deep/corpus/` | 764 MB | 2026-11-03 | DELETE-MAYBE | corpus più grande dell'albero |
| `lab/fuzz_new_fork/corpus{,_gcs}/` | 127 MB | 2026-11-07 | DELETE-MAYBE | corpus fork |
| `lab/sqlite_db_ace/corpus/` + `runs/` | 261 MB | 2026-11-03 | DELETE-MAYBE | corpus+run sqlite fuzz |
| `lab/v8_corpus/corpus*`, `lab/qjs_fuzz{,_new}/corpus` | ~35 MB | 2026-11-05 | DELETE-MAYBE | corpora minori |
| `lab/libvpx_deep/logs/replay_focus.log` | 135 MB | 2026-11-03 | DELETE-MAYBE | log replay gigante; report già estratto |
| `lab/qjs_fork_audit/c2_tryhard/logs/` (dom_*.log) | 169 MB | 2026-11-07 | DELETE-MAYBE | log DOM grezzi; le conclusioni sono in `REPORT_c2_tryhard.md` |
| `lab/local_message_media_ace/logs/fuzz_*.log` | ~50 MB | 2026-11-03 | DELETE-MAYBE | log fuzz estratti in `notes/local_message_media_ace.md` |
| `lab/decoder_fuzz/logs/`, `lab/qjs_n1/logs/` | ~32 MB | 2026-11 | DELETE-MAYBE | log fuzz/campagna |
| altri `*.log` >1M (84 file totali) | ~55 MB | — | DELETE-MAYBE | log di run |
| `lab/armv7/tombstone_bigstack_*.txt` (2) | 4.3 MB | 2026-11-02 | DELETE-MAYBE | duplicati dei tombstone in `evidence/evidence_20261102/armv7_tombstones/` (KEEP) |
| `tools/patchwork/{survA,survB,poc3..8,diag,meas}.db*` | ~45 MB | 2026-11-02 | DELETE-MAYBE | DB misurazione keypad stale (campagna chiusa; `poc/` mp4/png restano) |
| `lab/dav1d_coldstart_fuzz/device/*.db` (7) | ~50 MB | 2026-11-03 | DELETE-MAYBE | snapshot DB device campagne chiuse |
| `lab/jni_media_bounds/uaf/device/work*/cache4*.db` (5) | ~35 MB | 2026-11-03 | DELETE-MAYBE | idem |
| `lab/poc_video/backup_20261103_145856/cache4.db` | 7.2 MB | 2026-11-03 | DELETE-MAYBE | backup DB intermedio |
| `lab/qjs_postsnapshot/ios6s_db/` | 50 MB | 2026-11-06 | DELETE-MAYBE | DB iOS 6s (campagna iOS; verificare con l'orchestratore prima) |
| `lab/qjs_postsnapshot/loaders/size_variants/sony_sweep/` | 76 MB | 2026-11-02 | DELETE-MAYBE | sweep dimensioni loader (report in `notes/aes_tiny_loader_72799.md`) |
| `apks/13.1.1 (7249).apk`, `13.1.2 (7250,7253).apk`, `13.2.0 (7254..7260,7278,7279,7287).apk`, `Android_Beta_13.2.1_(72919).apk` | ~780 MB | 2026-10/11 | DELETE-MAYBE | build beta superate; 72889 è l'unico APK attivo richiesto (KEEP). `beta_apk_matrix_20261105.md` elenca le versioni ma non i file |
| `macOSbeta-272030.zip` (root) | 122 MB | 2026-11-02 | DELETE-MAYBE | zip macOS beta; report in `notes/macos_beta_audit.md` |
| `lab/macos_beta/extract/` | 377 MB | 2026-11-02 | DELETE-MAYBE | estrazione app macOS |
| `lab/macos_beta/work/` | 175 MB | 2026-11-02 | DELETE-MAYBE | binari/strings estratti |
| `lab/qjs_fork_audit/mega_chain/device/` | 32 MB | 2026-11-07 | DELETE-MAYBE | artefatti device di un filone laterale |
| `lab/qjs_fork_audit/applibs/` (3×26 MB) | 78 MB | 2026-11-07 | DELETE-MAYBE | dump lib (72889/72801/7279) — 72929 lib resta in `device/updates/72929/lib/` |
| `lab/qjs_postsnapshot/widget_poc_1865_*.html`, `widget_loader_aes*` (root) | ~150 KB | 2026-11-01 | DELETE-MAYBE | widget N1/loader obsoleti; **referenziati per nome** in `notes/qjs_postsnapshot_f1865_report.md`/`aes_tiny_loader_72799.md` → per regola sarebbero KEEP: decisione orchestratore |
| `lab/qjs_fork_audit/zeroday_hunt_parser/device/widget/` — varianti pre-`c2560s`/`c4096s` (a..r, canary_*, parser_*, univ_*, calib) | ~2.3 MB | 2026-11-07 | DELETE-MAYBE | generazioni superate; le 6 `c2560s` + 2 `c2` + 6 `c4096s` sono KEEP. Citate per nome nei report storici |
| `lab/qjs_n1/widget/` (varianti non usate) | ~21 MB | 2026-11 | DELETE-MAYBE | widget N1 storici (attivo: solo il widget DB corrente) |
| `*.mp4` in lab/poc (258 file totali) | 30 MB | 2026-11 | DELETE-MAYBE | registrazioni di campagna (16 MB il keypad; corpus video duplicati in più dir) |

## KEEP (esempi rappresentativi — non esaustivo)

* `notes/` (2.8 MB), tutti i `REPORT*.md`/`RUNBOOK*.md`, `CERTIFICATION_5of5.md`,
  `UNIVERSAL_2BUILDS.md`, `device/logs/device_parser_rce/` (proof, png, audit).
* Tombstone referenziati dai report: `device/logs/tombstone_c{4096,4096c,c2560g,j,k,n,o}_*.txt`
  (4.8 MB) + tombstone in `evidence/`.
* `evidence/` (800 MB) tranne il duplicato byte-identico sopra.
* Sorgenti: `qjs_src/`, `qjs_src_7a23/`, `zeroday_hunt_parser/src{,_diag,_min}/`,
  `round7/src`, `litehtml*/src+include`, `n1_hookfree/` (referenziato da
  `gen_sibling_widgets.py`: `../../n1_hookfree/poc/A_ab.js`), `qjs_fuzz/src`,
  `libvpx_deep/src`, harness/fuzz `*.cpp`, `device/endG*.js`, `device/gen_*.py`.
* Widget attivi: `c2560_{final,debug,probe}_c2560s_{72929,host}.html`,
  `c2560_final_c2560s_c2_{72929,host}.html`, famiglia `c4096s`, `gen_c2_widget.py`.
* `lab/qjs_n1/db/final_base_20261107.db` (base deploy attiva) + `RESTORE_REPORT.md`.
* APK attivi: `apks/Android_Beta_13.2.1_(72889).apk`,
  `device/updates/72929/Telegram-Beta-7292.apk` + `lib/libtmessages.49.so` + `NOTE.md`.
* File dei subagent in corso (verificati prima dell'ok): `device/widget/c2560s*`,
  `/tmp/opencode/…` (fuori albero), `c2/` e `lab/qjs_postsnapshot/ios_n1/` (esclusi).

## Riepilogo numeri

| classe | voce | byte |
|---|---:|---:|
| DELETE-SAFE | 56 build dir (binari ricompilabili) | ~9.57 GB |
| DELETE-SAFE | duplicati byte-identici (1 APK + 1 DB) | ~195 MB |
| DELETE-MAYBE | 54 dir `corpus*` | ~2.08 GB |
| DELETE-MAYBE | log >1M (84 file, incluso c2_tryhard/dom_*.log) | ~385 MB |
| DELETE-MAYBE | DB stale lab/tools/poc (161 file) | ~359 MB |
| DELETE-MAYBE | APK beta superate | ~780 MB |
| DELETE-MAYBE | macos_beta (zip+extract+work) | ~674 MB |
| DELETE-MAYBE | widget/loader obsoleti, sweep, mp4 | ~130 MB |
| **KEEP** | evidence, report, sorgenti, attivi | resto |

**Top-10 candidati per dimensione:**
1. `lab/qjs_fork_audit/build/` — 1.50 GB (SAFE)
2. `lab/dav1d_coldstart_fuzz/build/` — 908 MB (SAFE)
3. `lab/qjs_fork_audit/build-canon/` — 850 MB (SAFE)
4. `lab/libvpx_deep/corpus/` — 764 MB (MAYBE)
5. `lab/local_message_media_ace/build_ffmpeg_*` — 740 MB (SAFE)
6. `lab/decoder_fuzz/build/` — 729 MB (SAFE)
7. `lab/qjs_advisories/build*` — 578 MB (SAFE)
8. `lab/decoder_fuzz/corpus/` — 528 MB (MAYBE)
9. `lab/macos_beta/extract+work` — 552 MB (MAYBE)
10. `lab/qjs_fork_audit/fuzz_new_fork/build{,_gcs}` — 332 MB (SAFE)

**Liberabile senza rischio (DELETE-SAFE): ~9.8 GB.** Con le DELETE-MAYBE: fino a ~14.2 GB
(previo ok dell'orchestratore voce per voce).

## Esecuzione (2026-11-07 20:11) — orchestrator, dopo verifica

Verifiche fatte prima di cancellare:
- duplicati **byte-identici** confermati: `base.apk` = `Telegram-Beta-7292.apk`
  (sha `fe19d515…`); `cache4.release72801.db` = `…widget.db` (sha `b7eb5c1a…`);
- build dir senza sorgenti unici; il `patched/libregexp_patched.c` di
  `qjs_advisories` è rigenerabile da `adv/fixes` + `src_*` in-tree;
- script/log di build (`build*.sh`, `build*.log`) e sorgenti tipo
  `appmodel_run.c` **non** cancellati;
- `c2/`, `ios_n1/`, `device/logs`, `mega_chain/`, i canon corpus e i file
  dei subagent attivi esclusi.

Eseguito: **242 elementi cancellati, ~14 GB liberati** (disco 51→64 GB
liberi; `df` 327→314 GB usati). Due no-op (corpus già dentro una dir
padre rimossa). Tenuti: evidence, report, certificazioni (incluso
`mega_chain/.../CERTIFICATION_5of5.md`), tombstone citati, sorgenti,
widget attivi `c2560s`/`c2`/`c4096s`, APK 72889 + 72929 + lib, canon
corpus, `ios6s_db`, `device/logs`, varianti widget storiche citate dai
report.

Nota di cautela: le dimensioni sono misurate oggi con `du`/`os.path.getsize`; prima di
cancellare le build conviene conservare una nota di ricompilazione per ogni campagna
(comandi già documentati nei rispettivi report in `notes/`).
