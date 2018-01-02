#include <vector>
#include <map>
#include <cmath>
#include "llvm/Analysis/LoopInfo.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Metadata.h"
#include "llvm/IR/Type.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/PassRegistry.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <set>
#include <sstream>
#include <sys/stat.h>
#include "full_trace.h"

#define RESULT_LINE 19134
#define FORWARD_LINE 24601
#define SET_READY_BITS 95
#define DMA_FENCE 97
#define DMA_STORE 98
#define DMA_LOAD 99
#define SINE 102
#define COSINE 103

using namespace llvm;
using namespace std;

cl::opt<string> labelMapFilename("i",
                                 cl::desc("Name of the labelmap file."),
                                 cl::value_desc("filename"),
                                 cl::init("labelmap"));

cl::opt<bool>
    verbose("verbose-tracer",
            cl::desc("Print verbose debugging output for the tracer."),
            cl::init(false), cl::ValueDisallowed);

cl::opt<bool>
    traceAllCallees("trace-all-callees",
                    cl::desc("If specified, all functions called by functions "
                             "specified in the env variable WORKLOAD "
                             "will be traced, even if there are multiple "
                             "functions in WORKLOAD. This means that each "
                             "function can act as a \"top-level\" function."),
                    cl::init(false), cl::ValueDisallowed);

static Constant *createStringArg(const char *string, Module *curr_module) {
    Constant *v_string =
        ConstantDataArray::getString(curr_module->getContext(), string, true);

    ArrayType *ArrayTy_0 = ArrayType::get(
        IntegerType::get(curr_module->getContext(), 8), (strlen(string) + 1));

    GlobalVariable *gvar_array = new GlobalVariable(
        *curr_module, ArrayTy_0, true, GlobalValue::PrivateLinkage, 0, ".str");

    gvar_array->setInitializer(v_string);
    Constant *Idxs[] = {ConstantInt::get(Type::getInt32Ty(curr_module->getContext()), 0), 0 };
    Idxs[1] = Idxs[0];
    Constant * _tmp = ConstantExpr::getGetElementPtr(gvar_array->getValueType(), gvar_array, Idxs);
    return _tmp;
}

Tracer::Tracer() : FunctionPass(ID) {}

bool Tracer::doInitialization(Module &M) {
  auto &llvm_context = M.getContext();
  auto I64Ty = Type::getInt64Ty(llvm_context);
  auto I8PtrTy = Type::getInt8PtrTy(llvm_context);
  auto VoidTy = Type::getVoidTy(llvm_context);

  // Add external trace_logger function declarations.
  TL_log_entry = M.getOrInsertFunction("trace_logger_log_entry", VoidTy,
                                       I8PtrTy, I64Ty, nullptr);

  return false;
}

bool Tracer::runOnFunction(Function &F) {
  bool func_modified = false;

  curr_module = (F.getParent());

  func_modified |= runOnFunctionEntry(F);
  return func_modified;
}

bool Tracer::runOnFunctionEntry(Function& func) {
  // We have to get the first insertion point before we insert any
  // instrumentation!
  BasicBlock::iterator insertp = func.front().getFirstInsertionPt();

  Function::ArgumentListType &args(func.getArgumentList());
  std::string funcName = func.getName().str();

  InstEnv env;
  strncpy(env.funcName, funcName.c_str(), InstEnv::BUF_SIZE);
  printTopLevelEntryFirstLine(&(*insertp), &env, args.size());
  return true;
}

void Tracer::printTopLevelEntryFirstLine(Instruction *I, InstEnv *env,
                                         int num_params) {
  IRBuilder<> IRB(I);
  Constant *vv_func_name = createStringArgIfNotExists(env->funcName);
  Value* v_num_params = ConstantInt::get(IRB.getInt64Ty(), num_params);
  Value *args[] = { vv_func_name, v_num_params };
  IRB.CreateCall(TL_log_entry, args);
  errs() << env->funcName << " is processed\n";
}

Constant *Tracer::createStringArgIfNotExists(const char *str) {
  std::string key(str);
  if (global_strings.find(key) == global_strings.end()) {
    global_strings[key] = createStringArg(str, curr_module);
  }
  return global_strings[key];
}

char Tracer::ID = 0;
static RegisterPass<Tracer>
X("fulltrace", "Add full Tracing Instrumentation for Aladdin", false, false);
static void registerMyPass(const PassManagerBuilder &,
                                  legacy::PassManagerBase &PM) {
    PM.add(new Tracer());
}
static RegisterStandardPasses
    RegisterMyPass(PassManagerBuilder::EP_EarlyAsPossible,
                               registerMyPass);
