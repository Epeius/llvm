#include "llvm/Pass.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"

#include "llvm/PassRegistry.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/Support/FileSystem.h"

#include "Expand.h"

using namespace llvm;

bool Expand::runOnFunction(Function &F)
{
    Module *M = F.getParent();
    std::string moduleName = M->getName().str();

    //TODO: read blacklist config from file
    LOG() << "Entering module: " << moduleName << "\n";
    if (moduleName == "readelf.c") {
        return false;
    }

    LOG() << "Entering in function: " << F.getName() << "\n";
    LLVMContext &C = F.getContext();
    bool mod = false;
    for (auto &BB : F) {
        std::string bbName = BB.getName().str();
        // Avoid expand ourselves.
        if (bbName.find("expand") != std::string::npos) {
            continue;
        }

        mod |= processBasicBlock(&BB, &F, C);
    }

    LOG() << "Function  is : " << F << "\n";
    return mod;
}

bool Expand::processBasicBlock(BasicBlock *BB, Function *F, LLVMContext &C) 
{
    bool mod = false;
    if (!BB) {
        LOG() << "Unknown basic block" << "\n";
        return mod;
    }

    TerminatorInst * TI = BB->getTerminator();
    if (!TI) {
        LOG() << "Basic block:\n " << *BB << "\n";
        LOG() << "Has no terminator!!!" << "\n";
        return mod;
    }

    LOG() << *BB << "\n";

#if 0
    if (isa<BranchInst>(TI)) {
        BranchInst *BI = cast<BranchInst>(TI);
        if (!BI) {
            continue;
        }
        if (!BI->isConditional()) { continue; }

        Value *condition = BI->getCondition();
        if (!condition) {
            continue;
        }
        if (isa<ICmpInst>(condition)) {
            ICmpInst *II = cast<ICmpInst>(condition);
            if (!II || !II->isEquality()) {
                continue;
            }
            errs() << "Get ICMP EQ/NEQ instruction: " << *condition << ", in function: " << F->getName() << "\n";
            mod != expandICMPInst(BB, II, BI, C);
            errs() << "Rebuild done!\n";
        }
    }
#endif

    return mod;
}

bool Expand::handleICMPInst(BasicBlock *BB, ICmpInst *II, BranchInst *BI, LLVMContext & C)
{
    bool is_unsigned = false;

    // 1st: Get the operands
    if (II->isSigned()) {
        errs() << "This is an Signed comparison\n";
    } else {
        assert(II->isUnsigned()); 
        errs() << "This is an Unsigned comparison\n";
        is_unsigned = true;
    }

    assert(II->getNumOperands() == 2 && "Weird comparison instruction's operands");

    Value *firstOperand  = II->getOperand(0);
    Value *secondOperand = II->getOperand(1);

    errs() << "First operand is " << *firstOperand << "\n";
    errs() << "Second operand is " << *secondOperand << "\n";

    bool is_first_operand_const = isa<Constant>(firstOperand);
    bool is_second_operand_const = isa<Constant>(secondOperand);

    // return if both operands are constant.
    if (is_first_operand_const && is_second_operand_const) {
        return false;
    }
    
    // currently we don't support both inconst operands.
    if (!is_first_operand_const && !is_second_operand_const ) {
        return false;
    }

    Value *target = is_first_operand_const ? firstOperand : secondOperand;
    Value *var    = is_first_operand_const ? secondOperand : firstOperand;

    ConstantInt * CI_target = cast<ConstantInt>(target);
    unsigned CI_target_value = CI_target->getZExtValue();
    unsigned width = CI_target->getBitWidth();

    APInt vMax, vMin;
    if (is_unsigned) {
        vMax = APInt::getMaxValue(width);
        vMin = APInt::getMinValue(width);
    } else {
        vMax = APInt::getSignedMaxValue(width);
        vMin = APInt::getSignedMinValue(width);
    }

    errs() << "Max: " << vMax << ", Min: " << vMin << ", and real value is " << CI_target_value << "\n";

    unsigned factor = 0;
    BasicBlock *block = NULL;
    if (is_unsigned) {
        for (; factor < FACTORS; factor++) {
            unsigned max;
            unsigned min;
            getUnsignedRange(factor, CI_target_value, vMax, vMin, max, min);

            if (!factor) {
                block = BasicBlock::Create(C, "expand", BB->getParent());
                IRBuilder<> builder(block);
                Value * _maxII = builder.CreateICmpEQ(var, ConstantInt::get(CI_target->getType(), max));
                builder.CreateCondBr(_maxII, BI->getSuccessor(0), BI->getSuccessor(1));
            } else {
                assert(block);
                BasicBlock * min_block = BasicBlock::Create(C, "expand", BB->getParent());
                IRBuilder<> min_builder(min_block);
                Value * _minII = min_builder.CreateICmpUGE(var, ConstantInt::get(CI_target->getType(), min));
                min_builder.CreateCondBr(_minII, block, BI->getSuccessor(1));

                BasicBlock * max_block = BasicBlock::Create(C, "expand", BB->getParent());
                IRBuilder<> max_builder(max_block);
                Value * _maxII = max_builder.CreateICmpULE(var, ConstantInt::get(CI_target->getType(), max));
                max_builder.CreateCondBr(_maxII, min_block, BI->getSuccessor(1));

                block = max_block;
            }
        }
        IRBuilder<> IRB(BI);
        IRB.CreateBr(block);
        II->eraseFromParent();
        BI->eraseFromParent();

        return true;
    }

    return false;
}

void Expand::getUnsignedRange(unsigned factor, unsigned target, APInt vMax, APInt vMin,  unsigned &max, unsigned &min)
{
    //TODO:
}

void Expand::getSignedRange(unsigned factor, unsigned &max, unsigned &min)
{
    //TODO:
}

bool Expand::handleCallMemcmpInst()
{
    return false;
}

/***************************************************************/

void Expand::initLOG()
{
    std::string path = "/tmp/expand.log";
    std::error_code error;
    llvm::raw_fd_ostream *f = new llvm::raw_fd_ostream(path, error, llvm::sys::fs::F_None);
    if (!f || error) {
        llvm::errs() << "Error opening " << path << ": " << error.message() << "\n";
        exit(-1);
    }

    m_logFile = f; 
}

llvm::raw_ostream& Expand::LOG() const 
{
    m_logFile->flush();
    return *m_logFile;
}
static RegisterPass<Expand> X("Expand", "Expand Comparison Instruction Pass",
                             false /* Only looks at CFG */,
                             false /* Analysis Pass */);

static void registerMyPass(const PassManagerBuilder &,
                                  legacy::PassManagerBase &PM) {
    PM.add(new Expand());
}
static RegisterStandardPasses
    RegisterMyPass(PassManagerBuilder::EP_EarlyAsPossible,
                               registerMyPass);
