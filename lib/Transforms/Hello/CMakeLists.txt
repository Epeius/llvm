# If we don't need RTTI or EH, there's no reason to export anything
# from the hello plugin.

add_llvm_loadable_module( LLVMfull_trace
  full_trace.cpp
  DEPENDS
  intrinsics_gen
  )
