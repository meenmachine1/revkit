#!/bin/sh
# Builds the Apple application fixtures without an Apple SDK or binary:
# clang for arm64 iOS and macOS, ld64.lld against the hand-written .tbd
# stubs here, then make_bundle.py lays out the bundles around them.
#   build.sh CLANG LD64_LLD OUTDIR
# Writes OUTDIR/bin (the Mach-O files) and what make_bundle.py writes:
# Demo.app (iOS), Demo.ipa, MacDemo.app (macOS), plists/.
set -eu
clang=$1
ld=$2
out=$3
dir=$(cd "$(dirname "$0")" && pwd)
bin="$out/bin"
mkdir -p "$bin"
link() {  # platform out objs...
  platform=$1 o=$2
  shift 2
  "$ld" -arch arm64 -platform_version "$platform" 15.0 17.0 -adhoc_codesign -o "$o" "$@"
}
# iOS: the app, its framework and its extension.
"$clang" --target=arm64-apple-ios15 -O1 -c "$dir/greeter.c" -o "$bin/greeter-ios.o"
link ios "$bin/Greeter" -dylib -install_name @rpath/Greeter.framework/Greeter "$bin/greeter-ios.o" "$dir/libSystem.tbd"
"$clang" --target=arm64-apple-ios15 -fobjc-runtime=ios-15.0 -O1 -c "$dir/app.m" -o "$bin/app-ios.o"
link ios "$bin/Demo" -rpath @executable_path/Frameworks "$bin/app-ios.o" "$bin/Greeter" "$dir/UIKit.tbd" \
  "$dir/libobjc.tbd" "$dir/libSystem.tbd"
"$clang" --target=arm64-apple-ios15 -fobjc-runtime=ios-15.0 -O1 -c "$dir/share.m" -o "$bin/share-ios.o"
link ios "$bin/Share" -rpath @executable_path/../../Frameworks "$bin/share-ios.o" "$bin/Greeter" \
  "$dir/UIKit.tbd" "$dir/libobjc.tbd" "$dir/libSystem.tbd"
# macOS: the app and a versioned framework.
"$clang" --target=arm64-apple-macos12 -O1 -c "$dir/greeter.c" -o "$bin/greeter-mac.o"
"$ld" -arch arm64 -platform_version macos 12.0 14.0 -adhoc_codesign -dylib \
  -install_name @rpath/Greeter.framework/Versions/A/Greeter -o "$bin/Greeter-mac" "$bin/greeter-mac.o" "$dir/libSystem.tbd"
"$clang" --target=arm64-apple-macos12 -fobjc-runtime=macosx-12.0 -DDEMO_MAC -O1 -c "$dir/app.m" -o "$bin/app-mac.o"
"$ld" -arch arm64 -platform_version macos 12.0 14.0 -adhoc_codesign -rpath @executable_path/../Frameworks \
  -o "$bin/MacDemo" "$bin/app-mac.o" "$bin/Greeter-mac" "$dir/AppKit.tbd" "$dir/libobjc.tbd" "$dir/libSystem.tbd"
python3 -I "$dir/make_bundle.py" "$out"
