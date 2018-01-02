#include <fstream>
#include <map>
#include <string>

#include "llvm/Pass.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/BasicBlock.h"

using namespace llvm;
struct InstEnv {
    public:
        enum { BUF_SIZE = 256 };
        char funcName[BUF_SIZE];
};

class Tracer : public FunctionPass {
  public:
    Tracer();
    virtual ~Tracer() {}
    static char ID;

    virtual bool doInitialization(Module &M);
    virtual bool runOnFunction(Function& F);

  private:
    Module *curr_module;
    std::map<std::string, Constant*> global_strings;
    // Instrument function arguments for print-out upon entry.
    //
    // By printing the arguments from WITHIN the called function, rather than
    // OUTSIDE at the Call instruction, we resolve the problem of potentially
    // not knowing the complete function signature information.  This is
    // because the function may be defined in a different module than the one
    // from which it is being called, and in this case, it's impossible to know
    // what the function argument names are until we run the optimization pass
    // on that module.
    bool runOnFunctionEntry(Function& func);


    // Print the first line of a top-level function signature.
    //
    // This has the form "entry,func_name,num_params".
    void printTopLevelEntryFirstLine(Instruction *I, InstEnv *env,
                                     int num_params);

    // Get and set the operand name for this instruction.
    // Return a pointer to this vector value.
    //
    // The vector data is not guaranteed to have a memory address (it could be
    // just a register). In order to print the value, we need to get a pointer
    // to the first byte and pass that to the tracing function.  To do this, we
    // need to allocate a buffer, store the vector data into that buffer, and
    // return a pointer to the buffer.
    //
    // The buffer is allocated on the stack, so it can and SHOULD be reused;
    // otherwise, for vector-heavy workloads, we will easily run into the stack
    // size limit.
    Value *createVectorArg(Value *vector, IRBuilder<> &IRB);

    // Get a global string constant for str.
    //
    // If such a string has not been allocated a global variable before, then
    // create the argument and return the pointer to the Constant; otherwise,
    // just return the Constant*.
    Constant *createStringArgIfNotExists(const char *str);

    // References to the logging functions.
    Value *TL_log_entry;
};

