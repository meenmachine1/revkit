# LLVM's demangler library (llvm/lib/Demangle), vendored unmodified.
add_library(llvm_demangle STATIC
  lib/DLangDemangle.cpp
  lib/Demangle.cpp
  lib/ItaniumDemangle.cpp
  lib/MicrosoftDemangle.cpp
  lib/MicrosoftDemangleNodes.cpp
  lib/RustDemangle.cpp)
target_include_directories(llvm_demangle SYSTEM PUBLIC include config)
target_compile_definitions(llvm_demangle PUBLIC LLVM_BUILD_STATIC)
