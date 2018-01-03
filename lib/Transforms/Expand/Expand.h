#ifndef EXPAND_H_
#define EXPAND_H_

#include "llvm/Pass.h"
#include "llvm/IR/Function.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;

namespace {

#define FACTORS 2 

class Expand : public FunctionPass {
public:
    static char ID;
    Expand() : FunctionPass(ID) {
        initLOG();
    }

    bool runOnFunction(Function &F) override ;

    ~Expand() {
        if (m_logFile) {
            m_logFile->flush();
            delete m_logFile;
        }
    }

private:
    llvm::raw_ostream *m_logFile;

private:
    void initLOG(void);

    bool processBasicBlock(BasicBlock *, Function *, LLVMContext &);

    /* ICMP instruction related methods */
    bool handleICMPInst(BasicBlock *, ICmpInst *, BranchInst*, LLVMContext &);
    void getUnsignedRange(unsigned factor, unsigned , APInt, APInt, unsigned &, unsigned &);
    void getSignedRange(unsigned factor, unsigned &, unsigned &);

    /* memcmp function related methods */
    bool handleCallMemcmpInst();

    llvm::raw_ostream &LOG() const;

}; // end of struct Expand

char Expand::ID = 0;

}  // end of anonymous namespace


#endif // EXPAND_H_
