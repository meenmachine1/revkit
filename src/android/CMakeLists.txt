# revkit::android (docs/android.md): Android's binary XML, resources.arsc,
# the manifest's fields, a minimal DEX reader, JNI names, the native
# libraries' ELF facts and Flutter's Dart snapshot headers. No dependency on
# the rest of revkit: the image backend reads an APK's members through its
# container session and hands their bytes here.
add_library(revkit_android STATIC apk.cc arsc.cc axml.cc dex.cc manifest.cc native.cc)
add_library(revkit::android ALIAS revkit_android)
target_include_directories(revkit_android PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_compile_options(revkit_android PRIVATE -Wall -Wextra)
set_target_properties(revkit_android PROPERTIES POSITION_INDEPENDENT_CODE ON)

if(REVKIT_BUILD_TESTS)
  add_subdirectory(tests)
endif()
if(REVKIT_FUZZ)
  add_subdirectory(fuzz)
endif()

# An APK in a container session as revkit::android's ApkFiles (the image
# backend's and the tests').
add_library(revkit_android_fs STATIC apk_layer.cc)
add_library(revkit::android_fs ALIAS revkit_android_fs)
target_link_libraries(revkit_android_fs PUBLIC revkit::android revkit::container)
target_compile_options(revkit_android_fs PRIVATE -Wall -Wextra)
