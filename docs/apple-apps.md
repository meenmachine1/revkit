# Apple applications

An iOS app arrives as an `.ipa` (a zip whose `Payload/` holds `Demo.app`),
a macOS one as an `.app` directory (often inside a zip or a disk image).
revkit opens both as file systems ([filesystems.md](filesystems.md)) and
reads what Apple's formats say about the app: its bundles and what their
`Info.plist` says, its main executable and the frameworks and extensions
it carries, property lists, code signatures and provisioning profiles.
`api_minor` 100, feature `apple-bundles`; Interface Builder's nibs and
storyboards and their UI actions traced to the Objective-C methods they
run, `api_minor` 101, feature `ui-actions`. Mach-O itself, Objective-C and
Swift are [macho.md](macho.md).

- [What a user sees](#what-a-user-sees)
- [Bundles](#bundles)
- [Info.plist](#infoplist)
- [Property lists](#property-lists)
- [Code signatures](#code-signatures)
- [Provisioning profiles](#provisioning-profiles)
- [Libraries in a bundle](#libraries-in-a-bundle)
- [Interface Builder and UI actions](#interface-builder-and-ui-actions)
- [API, SDKs, MCP and the UI](#api-sdks-mcp-and-the-ui)
- [Tests and fuzzing](#tests-and-fuzzing)
- [Where the formats come from](#where-the-formats-come-from)
- [Known gaps](#known-gaps)

The code: `src/apple` (`revkit::apple`: the plist, DER/CMS, code
signature, provisioning profile, Info.plist, NIBArchive, keyed archive and
Interface Builder readers, a library with no dependency but libcrypto), `src/container/apple.cc` (the formats named in
listings), `src/backend/apple_bundles.cc` (the bundle walk and the API's
messages), `ui/src/ui/apple.ts` (the views).

## What a user sees

Open `Demo.ipa` (File → Open file system…, or the Open dialog's **Open as
file system**):

- `Payload/Demo.app` has an `app` badge, `Frameworks/Greeter.framework` a
  `framework` one, `PlugIns/Share.appex` `appex`; `Info.plist` reads as
  `binary property list` (content kind `plist:binary`),
  `embedded.mobileprovision` as a provisioning profile, a compiled nib as
  `compiled nib (NIBArchive, 23 objects)`.
- Right-click the app → **Apple bundle…**: its name, identifier, version,
  platform and minimum OS; URL schemes, background modes, the privacy
  usage descriptions it shows the user, its document types and the
  types it exports and imports; the main executable and its code
  signature (identifier, team, hardened runtime, requirements, signer,
  entitlements), marked *read, not verified*; the bundles inside it (click
  one to open it); its storyboards and nibs; its provisioning profile;
  the whole Info.plist as a tree.
- **Import main executable** imports `Demo` with the frameworks it loads
  (`@rpath/Greeter.framework/Greeter` found in `Demo.app/Frameworks`);
  **Import with frameworks and extensions** imports every nested bundle's
  executable too.
- The bundle view's **UI actions**: every control's action in its
  storyboards and nibs, traced to the method that runs it once the main
  executable is imported: the `Tap me` button's touch-up-inside sends
  `buttonTapped:` to File's Owner, the storyboard scene's
  `ViewController`, which runs `-[ViewController buttonTapped:]` (click it
  to open the program there); a first-responder action resolves to the
  one class implementing it.
- Right-click a plist → **Property list…**: the plist as a tree (XML,
  binary, or a provisioning profile's); a keyed archive with its objects
  resolved.
- An imported Mach-O's details in the Open dialog have a **Signed** line
  (`com.example.demo · team ABCDE12345 · hardened runtime · 5
  entitlements`) and **Signature…**; the command palette has **Code
  signature and entitlements…** for the program open.

## Bundles

A directory is a bundle when its name has a bundle extension and it
holds what a bundle does (an `Info.plist`, `Contents/`, `Versions/` or
`Resources/`): `FileSystemEntry.bundle_kind` is the extension, one of
`app`, `framework`, `appex`, `bundle`, `xpc`, `plugin`, `kext`,
`systemextension`, `dext`, `qlgenerator`, `mdimporter`, `prefpane`,
`saver`, or `storyboardc` (a compiled storyboard; not a bundle to
describe). Names decide here, as they do for Apple's own tools.

**Layouts** (`AppleBundle.layout`):

| Layout | Seen as | Info.plist | Executable |
| --- | --- | --- | --- |
| `shallow` | iOS, tvOS, watchOS apps and frameworks | `Info.plist` (else `Resources/Info.plist`) | `<CFBundleExecutable>` |
| `deep` | macOS apps and bundles: `Contents/` | `Contents/Info.plist` | `Contents/MacOS/<CFBundleExecutable>` |
| `versioned` | macOS frameworks: `Versions/` | `Versions/Current/Resources/Info.plist` (links followed inside the layer; else the only version) | `Versions/Current/<CFBundleExecutable>` |

A bundle without `CFBundleExecutable` uses its name without the
extension. The platform is `macos` for the deep and versioned layouts,
else `ios`, unless `CFBundleSupportedPlatforms` names another
(`AppleTVOS` → `tvos`, `WatchOS`, `XROS` → `visionos`, the simulators).

**Inside a bundle** the walk (at most 50,000 entries, 12 directories
deep, never into a bundle it found nor through a link) collects:

- **Nested bundles** (at most 256), each with its role by where it sits,
  following the path conventions rea's Apple application inventory
  documents: `framework`, `app-extension` (`.appex`), `xpc-service`
  (`.xpc`), `plug-in` (in `PlugIns/`, or `.plugin`), `watch-app` (an app in
  `Watch/`), `login-item` (`Library/LoginItems/`), `helper-application`
  (`Helpers/`), `nested-application`, `resource-bundle` (a `.bundle` in
  `Resources/`), `bundle`; with its identifier, version, extension point
  and executable.
- **Interface Builder files**: `.nib` files and directories and
  `.storyboardc` directories (at most 2,000).
- `embedded.mobileprovision` (or macOS's `embedded.provisionprofile`) and
  `_CodeSignature/CodeResources`.

`GetAppleBundle` takes a bundle directory, a file inside one (its nearest
bundle), or a file that is a container (an `.ipa`: its `Payload/*.app`,
else an `.app` at its root; `apps` lists them all), or a directory holding
those. A zip of a macOS app (`ditto -c -k --keepParent`) opens the same
way: `MacDemo.app` at the zip's root.

## Info.plist

`AppleBundleInfo` names Apple's keys (the Information Property List
reference): `CFBundleIdentifier`, `CFBundleName`, `CFBundleDisplayName`,
`CFBundleExecutable`, `CFBundleVersion`, `CFBundleShortVersionString`,
`CFBundlePackageType`, `MinimumOSVersion` (else `LSMinimumSystemVersion`),
`CFBundleSupportedPlatforms`, `UIDeviceFamily` (as `iphone`, `ipad`, `tv`,
`watch`, `carplay`, `mac`, `vision`), the schemes of `CFBundleURLTypes`,
`LSApplicationQueriesSchemes`, `CFBundleDocumentTypes` (name, role,
handler rank, content types, extensions), `UIBackgroundModes`, every
`*UsageDescription` key (the privacy strings: camera, location, contacts,
...), `UTExportedTypeDeclarations` and `UTImportedTypeDeclarations`
(identifier, description, conformance, extensions, MIME types),
`UIRequiredDeviceCapabilities`, `NSExtension`'s
`NSExtensionPointIdentifier` and principal class, `NSPrincipalClass`, the
main storyboard and nib, the launch storyboard, `NSAppTransportSecurity`
(arbitrary loads, exception domains), and Xcode's `DTSDKName`, `DTXcode`
and `BuildMachineOSBuild`. `AppleBundle.info_plist` is the whole file.

## Property lists

`revkit::apple::parse` reads XML and binary (`bplist00`) property lists
into one tree, as CoreFoundation does, for hostile input:

- **XML**: UTF-8 (a byte-order mark dropped) or UTF-16 with its mark; the
  prolog, comments, processing instructions and a DOCTYPE (its internal
  subset skipped; only the predefined entities and character references
  are expanded, so no entity can expand); `dict`, `array`, `key`,
  `string`, `integer` (decimal or `0x` hex, signed; past 64 bits
  refused, as CoreFoundation refuses it), `real` (and `nan`, `inf`,
  `infinity` in any case and sign), `true`, `false`, `date` (ISO 8601,
  UTC), `data` (base64, characters outside the alphabet ignored, as
  CoreFoundation does). A repeated key keeps the last value in the first
  one's place. Markup inside a string, a key without a value or text after
  the document is an error.
- **Binary**: the trailer's sizes checked against the file, every offset
  inside the object area and every reference below the object count;
  integers of 1 to 16 bytes (16-byte ones as CoreFoundation writes values
  past `INT64_MAX`), reals, dates, data, ASCII, UTF-16 and UTF-8 strings,
  UIDs, arrays, sets (as arrays), dictionaries (string keys only).
- **Limits**: 64 MiB of input, 128 levels of nesting, 2,097,152 values and
  256 MiB of strings and data made. A binary plist's objects can be
  shared, so a small file could describe a huge tree: every value made
  counts, shared ones each time they are used, and a cycle is refused.

Integers keep their exact value: `PlistValue.integer_value` when it fits
`int64`, else `unsigned_value`. Dates are timestamps (CFAbsoluteTime from
2001 converted). NSKeyedArchiver archives are plists too:
`ReadPropertyListResponse.keyed_archive` says so, and their UIDs are
`uid_value`.

**Content kinds** ([filesystems.md](filesystems.md#content-kinds)):
`plist:xml`, `plist:binary`, `keyed-archive` (an NSKeyedArchiver plist),
`nib:archive` (a NIBArchive, iOS's compiled nib), `nib:keyed` (a keyed
archive with `IB.objectdata`, macOS's), `mobileprovision` (CMS signed
data around a plist), `ipa` (a zip whose first members are
`Payload/<name>.app/`, described `zip archive (iOS app)`). A code
signature SuperBlob on its own is `code signature (embedded signature
SuperBlob)`.

## Code signatures

`LC_CODE_SIGNATURE` points at an embedded signature, a SuperBlob
(`0xfade0cc0`) of blobs by slot. `revkit::apple::parse_code_signature`
reads:

| Blob | What is read |
| --- | --- |
| CodeDirectory (`0xfade0c02`, slot 0; alternates 0x1000 on) | version, flags with codesign's names (`adhoc`, `hard`, `kill`, `expires`, `restrict`, `enforcement`, `library-validation`, `runtime`: the hardened runtime, `linker-signed`), identifier, team id (0x20200), hash type and size, page size, code and special slot counts, code limit (64-bit from 0x20300), platform, which special slots hold a hash (`info-plist`, `requirements`, `resources`, `application`, `entitlements`, `der-entitlements`, the launch constraints), the executable segment (0x20400: base, limit, flags `main-binary`, `allow-unsigned`, `debugger`, `jit`, ...), the runtime version (0x20500), and its CDHash: the CodeDirectory's own hash, 20 bytes, as `codesign -dv` prints it |
| Requirements (`0xfade0c01`) | each requirement (`designated`, `host`, `guest`, `library`, `plugin`) decompiled to the requirement language, as `codesign -d -r-` prints it: `identifier "com.example.demo" and anchor apple generic and certificate leaf[subject.CN] = "..." and certificate 1[field.1.2.840.113635.100.6.2.1] /* exists */` (every operator and match of the language, with precedence) |
| Entitlements (`0xfade7171`) | the XML, and the plist parsed |
| DER entitlements (`0xfade7172`) | Apple's DER encoding of the same plist, parsed |
| CMS signature (`0xfade0b01`) | whether it is there (an ad-hoc signature has none or an empty one), its size, and its certificates' names: subject, common name, organizational unit (a developer certificate's team), issuer, validity |

**Nothing is verified.** No code page is hashed and compared, no CMS
signature checked, no certificate chain built or trusted; a signature
that claims Apple's anchor is reported as claiming it. A malformed blob
is a warning (`CodeSignature.warnings`), the rest still read. The
program's summary has it (`MachoSummary.code_signature`, with its offset
and size in the file), read from the stored file (a universal file's
loaded slice), and so does `AppleBundle.code_signature` for a bundle's
main executable.

## Provisioning profiles

`embedded.mobileprovision` is CMS SignedData (RFC 5652) whose content is
an XML plist. A small BER/DER reader (definite and indefinite lengths,
constructed octet strings, as OpenSSL's `-stream` writes them) takes the
plist out without checking the signature; `ProvisioningProfile` has its
`Name`, `UUID`, `AppIDName`, the entitlements' `application-identifier`,
`TeamIdentifier`, `TeamName`, `Platform`, `CreationDate`,
`ExpirationDate`, the device count, `ProvisionsAllDevices`,
`get-task-allow`, the number of developer certificates, the CMS wrapper's
certificates, the whole plist, and a `kind`: `development`
(get-task-allow), `enterprise` (all devices), `ad-hoc` (devices listed),
else `app-store`.

## Libraries in a bundle

`import_libraries` (`api_minor` 70 and 79; [filesystems.md](filesystems.md#libraries-of-imported-programs))
resolves a Mach-O's `@`-relative install names as dyld does, inside the
file system the program came from (or the host directory it was imported
from), before the older search by file name:

- `@executable_path` is the main executable's directory: the program
  imported, when it is an executable (`MH_EXECUTE`), inherited by the
  libraries it brings; unknown for a library imported by itself.
- `@loader_path` is the directory of the image whose load command (or
  `LC_RPATH`) it is.
- `@rpath/x` tries each `LC_RPATH` of the loading image (expanded), then
  those of the images that loaded it, nearest first, up to the main
  executable, each with `/x`.

Candidates are normalized (`a/../b`) and links followed inside the layer
only; the first that is a Mach-O of the program's CPU wins. So `Demo`
(`@rpath/Greeter.framework/Greeter`, rpath `@executable_path/Frameworks`)
finds `Demo.app/Frameworks/Greeter.framework/Greeter`, the extension
`Share` (rpath `@executable_path/../../Frameworks`) the same file, and a
macOS app (`@executable_path/../Frameworks`) `Contents/Frameworks/
Greeter.framework/Versions/A/Greeter` through `Versions/Current`. Absolute
install names (`/usr/lib/libSystem.B.dylib`, `/System/Library/...`) are
the system's: on macOS 11 and later they live in the dyld shared cache,
not in the app, and are listed as not found.

## Interface Builder and UI actions

`api_minor` 101, feature `ui-actions`. Interface Builder compiles a
storyboard to a `.storyboardc` directory of nibs and a `.xib` to a `.nib`
(a file, or a directory of nibs for several OS versions:
`runtime.nib`, else the newest `objects-<version>.nib`, else
`keyedobjects*.nib`, is the one read). Two encodings, both read as data,
never instantiated:

- **NIBArchive** (iOS): a header, then tables of objects (a class and a
  run of values), keys, values (integers, reals, booleans, nil, data,
  object references) and class names, with NIBArchive's variable-length
  integers. Every count is checked against its table's bytes, every
  reference against the object table; 32 MiB per nib, 256 MiB per
  request. Strings are `NSString` objects (`NS.bytes`), arrays `NSArray`
  objects of `UINibEncoderEmptyKey` references.
- **Keyed archives** (macOS nibs, and any NSKeyedArchiver plist): `$top`,
  `$objects` and UIDs, resolved by `KeyedArchive` (a field, the UID it
  holds, the string an object is, an `NSArray`'s `NS.objects`).
  `ReadPropertyList` with `resolve_keyed_archive` returns an archive as a
  tree of its objects: each with `$class`, arrays and dictionaries as
  themselves, an object expanded where it is first reached and later
  references and cycles as `{"$ref": uid, "$class": name}`, so the tree
  is as large as the archive.

**The object graph** (`InterfaceDocument`): each object's archived class
and run-time class (a `UIClassSwapper`'s `UIClassName`, an
`NSCustomObject`'s or `NSClassSwapper`'s `NSClassName`), its original
class, File's Owner and First Responder placeholders (`UIProxyObject`'s
`IBFilesOwner` and `IBFirstResponder`; a keyed nib's `NSRoot` and its
`FirstResponder` object), a label (an accessibility label, text, title),
its parent (`UISuperview`, `UISubviews`, a keyed nib's
`NSObjectsKeys`/`NSObjectsValues`), a storyboard controller's
`UINibName`; and the connections: outlets (`UIRuntimeOutletConnection`,
`NSNibOutletConnector`) and actions (`UIRuntimeEventConnection` with its
`UIEventMask`, `NSNibControlConnector`), each with source, destination
and label. UIKit's event masks are named as `UIControlEvents` names them
(`touchUpInside`, `valueChanged`, `editingChanged`, ...).

**File's Owner's class** is the action's target class when the target is
File's Owner:

- in a storyboard, the scene's controller names its view's nib
  (`UINibName`), so that nib's owner is the controller's custom class
  (`storyboard`);
- a standalone nib named as one of the program's classes
  (`SettingsController.nib`) is that class's: UIKit's default nib name is
  the view controller's class (`nib-name`);
- a keyed nib's `NSRoot` names its class (`archive`: `NSApplication` for
  `MainMenu.nib`);
- else it is whoever loads the nib, unknown statically.

**Resolution** (`UiAction.resolution`), in the program's Objective-C
metadata ([macho.md](macho.md#objective-c-and-swift)), as rea's
`trace_native_ui_action` joins UI wiring to class and selector
implementations, done statically: the target class's instance method of
the selector, or a superclass's in the program, or a category's
(`resolved`, with the method's name, the class implementing it, its
address and the function's current name); an unknown target class (the
first responder, an unknown owner) resolves when exactly one class in the
program implements the selector (`resolved-by-selector`), else
`ambiguous` (the candidates) or `unresolved`; a target class the program
doesn't define is `external` (`UIApplication`, `NSApplication`'s
`terminate:`). The program is the one named, else the session's project's
program imported from the bundle's main executable (by its container
path).

## API, SDKs, MCP and the UI

| Where | What |
| --- | --- |
| `FileSystemEntry.bundle_kind` | a directory's bundle kind, in every listing |
| `FileSystemEntry.content_kind` | `plist:xml`, `plist:binary`, `keyed-archive`, `nib:archive`, `nib:keyed`, `mobileprovision`, `ipa` (with `detect`) |
| `FileSystemService.GetAppleBundle{session_id, path, skip_info_plist?}` | `AppleBundle` (above) and `apps` (an .ipa's) |
| `FileSystemService.ReadPropertyList{session_id, path, max_values?, max_data_bytes?}` | `format` (`xml`, `binary`, `mobileprovision`), `root` (`PlistValue`; at most `max_values` values, default 20,000, at most 200,000, `truncated` and each container's `omitted` saying what was left out; data cut at `max_data_bytes`, default 4,096, `data_size` the whole), `values`, `keyed_archive` |
| `ProgramSummary.macho.code_signature` | `CodeSignature` |
| `FileSystemService.ListUiActions{session_id, path, program_id?, include_documents?}` (`api_minor` 101, feature `ui-actions`) | the actions (`UiAction`: document, storyboard, control's id, class and label, events and mask, selector, target and its class and how it is known, resolution, method, implementing class, implementation address, function name, candidates), outlets (`UiOutlet`), documents (`InterfaceDocument`: path, format, storyboard, File's Owner's class; with `include_documents` their objects and connections), the program resolved against, warnings. `path`: a bundle, an .ipa, a `.storyboardc` or a nib |
| `ReadPropertyListRequest.resolve_keyed_archive` (`api_minor` 101) | a keyed archive's objects resolved |
| Python | `FileSystem.apple_bundle(path)`, `FileSystem.property_list(path, resolve_keyed_archive=)`, `FileSystem.ui_actions(path, program_id=, include_documents=)`, `revkit.plist_value(v)` (a `PlistValue` as Python: str, int, float, bool, datetime, bytes, list, dict, None, `{"CF$UID": n}`), `Program.code_signature()`, `Program.entitlements()` |
| TypeScript | `FileSystemSession.appleBundle(path)`, `propertyList(path)`, `uiActions(path)`, `plistValue(v)`, `APPLE_BUNDLES_FEATURE`, `UI_ACTIONS_FEATURE` |
| MCP | `apple_bundle(session_id, path)`, `read_property_list(session_id, path, max_values, resolve_keyed_archive)`, `list_ui_actions(session_id, path, program_id)`; `list_filesystem` entries' `bundle_kind`; `program_summary`'s `macho.code_signature` (identifier, team, flags, entitlements, requirements, certificates, `"verified": false`) |
| UI | the file system browser's bundle badge, **Apple bundle…** (with its **UI actions**) and **Property list…**; the Open dialog's **Signed** line and **Signature…**; the palette's **Code signature and entitlements…** ([ui.md](ui.md#apple-bundles)) |

Viewer may call `GetAppleBundle`, `ReadPropertyList` and
`ListUiActions` (viewer of the program's project when it names one), on
sessions of their own, as the other reads.

## Tests and fuzzing

No Apple tool, SDK or binary is used. `tests/data/apple/build.sh` builds
the Mach-O files with clang and `ld64.lld` against hand-written `.tbd`
stubs (UIKit, AppKit, libobjc, libSystem): an iOS app executable with
Objective-C view controllers, a framework (`@rpath/Greeter.framework/
Greeter`), a share extension and a macOS build of the app with a
versioned framework. `make_bundle.py` (standard library only) lays out
`Demo.app`, `Demo.ipa` and `MacDemo.app` around them: Info.plists written
by `plistlib` (binary and XML), the main executable's ld64.lld signature
replaced by one it writes (a SHA-1 CodeDirectory and a SHA-256 alternate
hashing the real pages, requirements, XML and DER entitlements, a CMS blob
with two made-up certificates; nothing real is signed), a provisioning
profile (its own DER writer), a compiled storyboard and nibs (its own
NIBArchive writer, from the format's public description), an
NSKeyedArchiver nib, and single plists for the parsers. Everything is made
at test time; nothing binary is committed.

- `revkit_apple_tests` (`src/apple/tests/apple_test.cc`): binary and XML
  plists of every type read the same and round-trip; Info.plist keys from
  binary, XML and UTF-16 files; XML syntax (entities, CDATA, a DOCTYPE
  with an internal subset, repeated keys, hex integers, `-infinity`, data
  with junk) and 12 malformed documents; nesting and size limits; hostile
  binary plists (a cycle, sharing that doubles 40 times, references and
  strings past the file, non-string keys, a trailer outside it) and
  truncations; dates; the code signature's every part, its truncations and
  flipped bytes, and ld64.lld's own linker-signed signature; the
  provisioning profile, and OpenSSL's own `cms -sign` profiles, DER and
  BER (`-stream`: indefinite lengths, a constructed octet string).
- `revkit_backend_tests` `AppleApi.*` (`src/backend/tests/apple_test.cc`):
  the .ipa's listing (bundle kinds, content kinds), the iOS bundle from its
  root, its directory and a file inside (layout, Info.plist, executable,
  signature, nested bundles and their roles, interface files, profile), a
  framework and an extension by themselves, the macOS bundle and its
  versioned framework, property lists (a budget, a profile, a keyed
  archive, a Mach-O refused), `Demo` imported with its framework by
  `@rpath`, the extension linking the same one through
  `@executable_path/../..`, the macOS app finding `Versions/A` through
  `Versions/Current`, and the program summary's signature.
- `revkit_apple_tests` `AppleNib.*`, `AppleKeyedArchive.*`: a NIBArchive's
  tables, a standalone nib's and a storyboard scene's objects and
  connections (placeholders, a class swapper, parents, event names, a
  controller's nib name), a keyed nib's (custom objects, menu items and
  their menu), a keyed archive resolved (each object once), and hostile
  nibs (a version, tables out of order, truncations, flipped bytes).
- `revkit_backend_tests` `AppleApi.UiActions*`, `MacUiActions*`: the .ipa's
  three documents and six actions before any import (`no-program`), then
  with `Demo` imported: `buttonTapped:` and `sliderChanged:` to the scene's
  `ViewController` (owner from the storyboard), `copyAll:` by selector,
  `save:` through the nib's name, an undefined action unresolved, the
  outlets' classes, `external` against the framework; the macOS app's
  `MainMenu.nib` (`showAbout:` to its `AppDelegate`), and the keyed archive
  resolved through `ReadPropertyList`.
- `python_sdk` (`sdk/python/tests/test_apple.py`): the SDK and MCP tools.
- `ts_sdk_filesystems` (`sdk/ts/test/filesystems.ts`): an .ipa made with
  plistlib, its bundle and `plistValue` (a 64-bit unsigned as a bigint).
- `ui_e2e` (`ui/e2e/apple.ts`): the badge, Apple bundle…, a nested bundle,
  Import main executable, the UI actions resolved and a method opened,
  Property list…, Signed and Signature….
- **Fuzzing** (`apple_plist_fuzzer`, `apple_codesign_fuzzer`,
  `apple_provision_fuzzer`, `apple_nib_fuzzer`; the container's `guess()` through
  `container_bytecode_fuzzer`), seeded with the fixtures, run on
  2026-10-18 with ASan and UBSan: plist 2.9 million runs in 4 minutes,
  code signature 1.6 million in 3.5, provisioning profile 3.3 million in
  3.5, guess 10.9 million in 3, nibs (NIBArchive and keyed archives, with
  `resolve()`) 3.7 million in 4; nothing found.

## Where the formats come from

From their public descriptions: CoreFoundation's open-source
`CFBinaryPList.c` and Apple's plist DTD for property lists; Apple's
open-source Security framework (`cs_blobs.h`, the requirement language
`reqreader`/`reqdumper`) and libCoreEntitlements for code signatures and
DER entitlements; RFC 5652, RFC 5280 and X.690 for CMS, certificates and
BER/DER; the Bundle Programming Guide and Information Property List
reference for bundles; public write-ups of NIBArchive. No code is taken
from them. The bundle roles and the dyld path rules follow rea's
documentation (https://github.com/morluto/rea,
`docs/apple-application-analysis.md`), and the NIBArchive reader and the
connections' key names are ported from rea's
`src/artifacts/apple/NibArchive.ts`, `InterfaceBuilderAnalysis.ts` and
`src/domain/apple/interfaceBuilderKeyedArchive.ts` (MIT License,
Copyright (c) 2026 morluto; `src/apple/ib.cc`'s header,
THIRD_PARTY_NOTICES.md).

## Known gaps

- **Interface Builder**: `.xib` and `.storyboard` source files (XML)
  aren't read, only compiled nibs; segues (`UIStoryboardSegueTemplate`),
  gesture recognizers' actions (archived as target-action pairs on the
  recognizer, not as connections), bindings (`NSNibBindingConnector`) and
  user-defined runtime attributes are listed as objects, not traced; a
  Swift action's selector resolves only where the class is visible to
  Objective-C (`@objc`); an action sent to File's Owner of a nib loaded by
  name from code (not a storyboard's, not a class-named nib) resolves by
  selector only. What the action's method calls is the program's call
  graph ([api.md](api.md)).
- **Verification**: none, by design (above). `_CodeSignature/CodeResources`
  is found, its sealed hashes not compared.
- **Formats not read**: OpenStep (text) plists and `.strings` files, JSON
  plists, asset catalogs (`Assets.car`), disk images (`.dmg`: open the
  app's zip or directory instead), `.pkg` installers, a CodeDirectory's
  launch constraints (their blobs are listed) and a detached
  `_CodeSignature/CodeSignature`'s contents.
- **Libraries**: `LC_DYLD_ENVIRONMENT` and the `DYLD_*` variables aren't
  modeled; absolute install names aren't looked up in a dyld shared cache
  (there is no dyld cache loader).
