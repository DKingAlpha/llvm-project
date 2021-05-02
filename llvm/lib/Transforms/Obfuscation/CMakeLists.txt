add_llvm_component_library(LLVMObfuscation
    Utils.cpp
    DynStrEnc.cpp

    ADDITIONAL_HEADER_DIRS
    ${LLVM_MAIN_INCLUDE_DIR}/llvm/Transforms
    ${LLVM_MAIN_INCLUDE_DIR}/llvm/Transforms/Obfuscation

    DEPENDS
    intrinsics_gen

    COMPONENT_NAME
    Obfuscation
)
