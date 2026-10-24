# Android packages

An APK is a zip ([filesystems.md](filesystems.md)), but what is in it is
stored in Android's own binary formats: `AndroidManifest.xml` and the
other compiled XML files as binary XML (AXML), the resources as
`resources.arsc`, the code as DEX and as native libraries under
`lib/<abi>/`. revkit reads them in the daemon: the manifest as XML text
and as fields, the resource table, the native libraries by ABI with their
JNI exports, the DEX files' native methods mapped to those exports, and a
Flutter app's Dart snapshot hash. `api_minor` 98, feature `android`.
jadx ([providers.md](providers.md)) still decompiles the Java; this is
what an analyst wants to know before that, and what links the Java to the
native code.

- [What is read](#what-is-read)
- [The manifest](#the-manifest)
- [Resources](#resources)
- [Native libraries and JNI](#native-libraries-and-jni)
- [Flutter](#flutter)
- [Interfaces](#interfaces)
- [Limits and hostile input](#limits-and-hostile-input)
- [Tests and fuzzing](#tests-and-fuzzing)
- [Known gaps](#known-gaps)

The code: `src/android` (`revkit::android`: the parsers, with no
dependency on the rest of revkit; `apk_layer.cc` is the adaptor that reads
an APK's members through a container session), `src/backend/android_api.cc`
(the three calls), `ui/src/ui/android.ts` (the dialog).

## What is read

| File | Format | What revkit takes from it |
| --- | --- | --- |
| `AndroidManifest.xml`, `res/**/*.xml` | binary XML: a string pool (UTF-8 or UTF-16), the resource map, namespaces, elements with typed attributes, character data | the document as XML text, attribute values typed (`true`, `16.0dip`, `#ff336699`, `@0x7f020000`) and references named from the resource table (`@string/app_name`) or resolved to their default-configuration value |
| `resources.arsc` | the resource table: a value pool, packages with type and key pools, type specs, types (dense, sparse, 16-bit offsets), entries (simple, compact and maps), configurations, shared libraries | every entry by id, type, key and configuration; a configuration as aapt2's qualifiers (`fr`, `en-rGB`, `b+zh+Hans`, `night`, `sw600dp`, `xxhdpi`, `v21`, ...) |
| `classes.dex`, `classes2.dex`, ... | DEX 035 to 041: the header, the string, type, proto and method id tables, class definitions and their class data | the classes (counted, named), and every method with `ACC_NATIVE`: its class, name and signature |
| `lib/<abi>/*.so` | ELF (32 and 64-bit, either byte order) | the machine, `DT_SONAME`, `DT_NEEDED`, the GNU build ID, the defined dynamic symbols (through the section headers, or through `PT_DYNAMIC` with `DT_HASH` or `DT_GNU_HASH` when the sections are stripped) |

Every format is parsed from AOSP's descriptions (`ResourceTypes.h`, the
Dalvik executable format, the JNI specification) by code written for
revkit, for hostile input: every offset and count is checked against the
bytes there are, and what doesn't decode becomes a warning rather than a
failure where the rest can still be read. Strings are kept as valid UTF-8
(modified UTF-8's surrogate pairs decoded, the rest as U+FFFD).

An attribute is named by its resource id when the id is a framework
attribute revkit knows (`0x0101021b` is `versionCode`), as Android looks
them up, so a manifest whose attribute names an obfuscator rewrote still
reads right; otherwise by the name stored in the string pool.

## The manifest

`AndroidPackage.manifest` (`AndroidManifest` in the API):

| Field | From |
| --- | --- |
| `package`, `version_code` (with `versionCodeMajor` in the high 32 bits), `version_name` | `<manifest>` |
| `min_sdk`, `target_sdk`, `max_sdk` | `<uses-sdk>` |
| `compile_sdk`, `compile_sdk_codename`, `platform_build_version_code`, `platform_build_version_name` | `<manifest>` (aapt2 writes them) |
| `uses_permissions` (with `max_sdk`), `permissions` (declared, with `protection_level`: `signature`, `dangerous|privileged`) | `<uses-permission>`, `<uses-permission-sdk-23>`, `<permission>` |
| `uses_features`, `uses_libraries`, `queries_packages` | `<uses-feature>` (or its GL ES version), `<uses-library>`, `<queries><package>` |
| `application_class`, `label`, `icon`, `theme`, `process`, `app_component_factory` | `<application>`: class names made fully qualified (`.App` and `App` are the package's), the label a string's text |
| `debuggable`, `allow_backup`, `uses_cleartext_traffic`, `extract_native_libs`, `test_only`, `large_heap`, `has_code`, `request_legacy_external_storage` | `<application>`, through references (`@bool/x`) too; unset when the manifest doesn't say, as Android's defaults then apply |
| `network_security_config` (`@xml/network_security_config`) and `network_security_config_file` (`res/xml/network_security_config.xml`, which `DecodeAndroidXml` shows) | `<application android:networkSecurityConfig>` and the table |
| `components` | `<activity>`, `<activity-alias>`, `<service>`, `<receiver>`, `<provider>`: kind, name, `exported`, `exported_explicit`, `enabled`, `permission`, `process`, a provider's `authorities`, read and write permissions and `grant_uri_permissions`, an alias's `target_activity`, `launcher` (MAIN and LAUNCHER), the intent filters (actions, categories, data: scheme, host, port, path, prefix, pattern, MIME type; priority, `autoVerify`) |
| `meta_data` | `<application>`'s `<meta-data>` |

`exported` is what Android decides: the attribute when it is there, else
true for a component with an intent filter (Android 12 refuses to install
such a manifest when it targets API 31, but older ones run), and for a
provider true only below target SDK 17. `exported_explicit` says whether
the manifest said so.

`manifest_xml` is the document as XML text with references named, as
apktool and jadx print it; `manifest_xml_resolved` has them replaced by
their default-configuration values (`android:label="Droid Test"`).

## Resources

`AndroidPackage.resources` summarizes the table: its packages (the app's
is `0x7f`), each type's distinct ids, values and configurations.
`ListAndroidResources` lists entries: one `type` (`string` is the strings
table) or all, one `config` (`""` the default, `fr`, `night`, `*` every
one), a `query` matching the key, the value or the name, paged. Each entry
has its `id`, `name` (`@string/app_name`), `key`, `config`, `value` (a
string's text, `true`, `#ff336699`, `16.0dip`, a file's path such as
`res/layout/main.xml`; a reference is followed to its default-configuration
value, at most eight hops, and named in `reference`) and `value_type`; a bag
(style, array, plurals, attr) has its `parent` and `items`
(`@android:attr/textColor = @color/primary`).

`DecodeAndroidXml` decodes any compiled XML file of the package (a layout,
`res/xml/*.xml`, the manifest), its references named from the package's
table, or resolved with `resolve`.

## Native libraries and JNI

`native_libraries` lists every `lib/<abi>/*.so` by ABI directory
(`arm64-v8a`, `armeabi-v7a`, `x86_64`, `x86`, `riscv64`), with what its
header says (a header that disagrees with the directory is a warning), its
exports' count, its `Java_*` exports and whether it exports `JNI_OnLoad`.
Their `path` is a session path: `ImportFromFileSystem` imports them as
programs, and with `import_libraries` the libraries they need are found
beside them in the same `lib/<abi>/` directory and linked
([filesystems.md](filesystems.md#libraries-of-imported-programs)), so a
JNI library and the libraries it calls come in as one linked set. Their
JNI exports are ordinary exported symbols there.

`native_methods` lists every native method the DEX files declare, with
its two JNI names (`Java_<class>_<method>`, and with `__<arguments>` for
an overloaded one, mangled as the JNI specification says: `_1` for `_`,
`_2` for `;`, `_3` for `[`, `_0xxxx` for anything else) and the libraries
exporting either. A method no library exports is bound at run time with
`RegisterNatives`, usually from `JNI_OnLoad` (or its library isn't in the
package): those are the ones worth reading `JNI_OnLoad` for.

The DEX reader is deliberately minimal: names and access flags from the
id tables and class data, no code. jadx is what decompiles the Java.

## Flutter

A Flutter app ships its engine as `lib/<abi>/libflutter.so` and its Dart
code compiled ahead of time as `lib/<abi>/libapp.so`. `flutter` says:

- `detected`: either library is there;
- per ABI: the four snapshot symbols `libapp.so` exports
  (`_kDartVmSnapshotData`, `_kDartVmSnapshotInstructions`,
  `_kDartIsolateSnapshotData`, `_kDartIsolateSnapshotInstructions`), and at
  the two data symbols Dart's snapshot header: the magic `f5 f5 dc dc`, the
  length, the kind (3 is full AOT in the Dart releases since 2.x; other
  numbers are kept as they are), the 32-character **snapshot hash** and the
  feature string (`product no-code_comments ... arm64 android
  compressed-pointers`); the VM's and isolate's hashes are compared
  (`hash_candidates` when they differ);
- `libflutter.so`'s GNU build ID (the engine build), and the labelled
  strings it carries: `Dart VM version: ...` (release engines usually strip
  it) and the Android clang toolchain line;
- `snapshot_hash`: the hash every ABI agrees on.

The snapshot hash identifies the Dart SDK release that built the
snapshot, which is what decides how its contents are laid out; mapping it
to a release needs a table of hashes revkit doesn't carry (reFlutter's,
for one). What to report follows rea's Flutter identification
(`docs/flutter-analysis.md` in rea, MIT); the code is revkit's. Reading
the snapshot's objects (classes, functions, the string pool) is not done.

## Interfaces

- **API**: `FileSystemService.GetAndroidPackage` (`session_id`, `path`:
  the APK, or a path inside it; `""` when the file system itself is one;
  `skip_native`, `skip_dex`), `DecodeAndroidXml` (`path`, `resolve`),
  `ListAndroidResources` (`path`, `type`, `config`, `query`, `offset`,
  `limit`). Viewer, and the session's owner, as the other file system reads
  ([api.md](api.md#android-packages)).
- **Python SDK**: `FileSystem.android_package(path="", native=True,
  dex=True)`, `android_xml(path, resolve=False)`,
  `android_resources(path="", type=, config=, query=, offset=, limit=)`,
  `android_strings(path="", config="")` (`{name: value}`).
- **TypeScript SDK**: `FileSystemSession.androidPackage`, `androidXml`,
  `androidResources`; `ANDROID_FEATURE`.
- **MCP**: `android_package` (the manifest's fields, resources summary,
  native libraries, native methods, Flutter), `android_resources`,
  `android_xml`, on a session from `open_filesystem`.
- **The UI**: the file system browser's **Android…** button (an APK opened
  directly) and **Android package…** in an APK's context menu
  ([ui.md](ui.md#android-packages)).

## Limits and hostile input

A member is read whole when it is at most 256 MiB (and within the
session's per-file limit); the native libraries and DEX files of one call
together at most 1 GiB (past it, the rest are listed unread, with a
warning); at most 512 libraries and 64 DEX files; 2^21 resource entries and
strings per pool; XML 256 elements deep, 2^20 nodes, 4096 attributes per
element; DEX id tables 2^22 entries; 2^20 dynamic symbols. References are
followed at most eight hops (a reference to itself resolves to nothing).

## Tests and fuzzing

- `revkit_android_tests` (`src/android/tests/android_test.cc`): APKs written
  at test time by `tests/data/android/make_apk.py`, which writes AXML (UTF-8
  and UTF-16 pools), `resources.arsc` (dense, sparse and compact entries,
  six configurations, a style bag, file references), a DEX with native
  methods (an overload, an underscore, an inner class, one left to
  `RegisterNatives`) and compiles JNI libraries (`native.c`, `helper.c`)
  and Flutter stand-ins (`flutter_app.c`, `flutter_engine.c`) for the host
  and, when `aarch64-linux-gnu-gcc` is installed, AArch64: the manifest's
  every field, the XML text both ways, the strings table per configuration,
  values of every kind, a layout, JNI names both ways, the native methods
  linked, Flutter's hash per ABI, a library with its section headers
  stripped (DT_GNU_HASH and DT_HASH), and truncations and flipped bytes of
  each format. The generator's output was checked against jadx 1.5.6
  (2026-10-18), which decodes the same manifest, resources (sparse and
  compact entries included), layout and DEX identically. aapt2 isn't
  installable from pip or npm, so it wasn't used.
- `python_sdk` (`sdk/python/tests/test_android.py`): the three calls end to
  end, an APK inside a zip, a native library imported with the library it
  needs linked and its JNI exports in the symbols, the MCP tools.
- `ts_sdk_filesystems`, `ui_e2e` (`ui/e2e/android.ts`).
- **Fuzzing** (`-DREVKIT_FUZZ=ON`, clang): `android_axml_fuzzer`,
  `android_arsc_fuzzer` (a table, then a document resolved against it),
  `android_dex_fuzzer`, `android_elf_fuzzer` (exports, Flutter's headers and
  engine strings) and `android_jni_fuzzer` (JNI names, configurations).

## Known gaps

- No real Flutter app was at hand: the snapshot header layout is checked
  on stand-ins built from Dart's `snapshot.h`, and the kind numbers of
  older Dart releases differ.
- Not read: the Dart snapshot's objects; DEX code (jadx's job); split APKs
  and app bundles (`.aab`, `.apks`, `.xapk` open as zips and each APK in them
  reads on its own, but they aren't put together); APK signatures (the v2+
  signing block); `resources.pb` (an app bundle's protobuf resources);
  OBB files.
- Overlayable, staged-alias and library chunks are skipped or only
  listed; resources of other packages (`@android:`) are named only for the
  framework attributes revkit knows.
- Native libraries stored compressed are decompressed to be read (within
  the session's limits); a library stored page-aligned is read in place.
