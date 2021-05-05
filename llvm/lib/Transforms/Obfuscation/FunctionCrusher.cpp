#include "llvm/Transforms/Obfuscation/Obfuscation.h"
#include "llvm/Pass.h"
#include "llvm/Transforms/Utils/Local.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/Demangle/Demangle.h"

#include <vector>
#include <set>
#include <map>
#include <random>

using namespace llvm;

// FIXME:
// shuffle switch cases
// map random number to case id

cl::opt<bool> EnableBBVM("obf-fc", cl::desc("Obfuscation: enable Funciton Crusher"), cl::init(false));

StringRef FunctionCrusher::name() {
    return "obf-fc";
}

static struct EdgeInfo {
    BasicBlock* from_bb;
    Instruction* from_inst;
    int from_suc_index;
    BasicBlock* to_bb;
    Instruction* to_inst;
    int to_suc_index;
};


static bool valueEscapes(Instruction *Inst) {
  BasicBlock *BB = Inst->getParent();
  for (Value::use_iterator UI = Inst->use_begin(), E = Inst->use_end(); UI != E;
       ++UI) {
    Instruction *I = cast<Instruction>(*UI);
    if (I->getParent() != BB || isa<PHINode>(I)) {
      return true;
    }
  }
  return false;
}

// demote reg/phinode to stack to pass DomTree verifier
static void fixStack(Function *f) {
  // Try to remove phi node and demote reg to stack
  std::vector<PHINode *> tmpPhi;
  std::vector<Instruction *> tmpReg;
  BasicBlock *bbEntry = &*f->begin();

  do {
    tmpPhi.clear();
    tmpReg.clear();

    for (Function::iterator i = f->begin(); i != f->end(); ++i) {

      for (BasicBlock::iterator j = i->begin(); j != i->end(); ++j) {

        if (isa<PHINode>(j)) {
          PHINode *phi = cast<PHINode>(j);
          tmpPhi.push_back(phi);
          continue;
        }
        if (!(isa<AllocaInst>(j) && j->getParent() == bbEntry) &&
            (valueEscapes(&*j) || j->isUsedOutsideOfBlock(&*i))) {
          tmpReg.push_back(&*j);
          continue;
        }
      }
    }
    for (unsigned int i = 0; i != tmpReg.size(); ++i) {
      DemoteRegToStack(*tmpReg.at(i), f->begin()->getTerminator());
    }

    for (unsigned int i = 0; i != tmpPhi.size(); ++i) {
      DemotePHIToStack(tmpPhi.at(i), f->begin()->getTerminator());
    }

  } while (tmpReg.size() != 0 || tmpPhi.size() != 0);
}


PreservedAnalyses FunctionCrusher::run(Module &M, ModuleAnalysisManager &AM) {
    if (!EnableBBVM)
        return PreservedAnalyses::all();


    for (auto& F: M) {
        std::vector<BasicBlock*> origBBs;
        for (auto& BB : F) {
            origBBs.push_back(&BB);
        }
        for (auto BB: origBBs)
            if (BB != origBBs.front())
                crushBB(M, F, *BB);
        
        std::vector<BasicBlock*> newBBs;
        for (auto& BB : F) {
            newBBs.push_back(&BB);
        }

        std::map<BasicBlock*, BasicBlock*> dispatchMap;
        // create dispatcher
        // for (auto vmbegin=origBBs.begin(), vmend=std::next(vmbegin); vmbegin != origBBs.end(); vmbegin++, vmend++) {
        for (int x=1; x<origBBs.size(); x++) {
            BasicBlock* vmbegin = origBBs[x];
            BasicBlock* vmend = (x+1)<origBBs.size() ? origBBs[x+1] : nullptr;
            std::vector<BasicBlock*>::iterator newit_begin = std::find(newBBs.begin(), newBBs.end(), vmbegin);
            std::vector<BasicBlock*>::iterator newit_end = (vmend == nullptr) ? newBBs.end() : std::find(newBBs.begin(), newBBs.end(), vmend);
            const int orig_inst_count = newit_end - newit_begin;
            BasicBlock* loopEntryBB = BasicBlock::Create(F.getContext(), "loopentry", &F, vmbegin);
            BasicBlock* dispatchBB = BasicBlock::Create(F.getContext(), "dispatch", &F, loopEntryBB);
            BasicBlock* defaultBB = BasicBlock::Create(F.getContext(), "default", &F, vmend);
            IRBuilder<> IRB_dispatch(dispatchBB);
            Value* switchVarPtr = IRB_dispatch.CreateAlloca(Type::getInt32Ty(IRB_dispatch.getContext()));
            IRB_dispatch.CreateStore(ConstantInt::get(Type::getInt32Ty(IRB_dispatch.getContext()), 0), switchVarPtr);
            IRB_dispatch.CreateBr(loopEntryBB);
            IRBuilder<> IRB_loopentry(loopEntryBB);
            Value* switchVar = IRB_loopentry.CreateLoad(Type::getInt32Ty(IRB_loopentry.getContext()), switchVarPtr);
            SwitchInst* switchInst = IRB_loopentry.CreateSwitch(switchVar, defaultBB, orig_inst_count);
            auto it_destBB = newit_begin;
            for (int i=0; i<orig_inst_count; i++, it_destBB++) {
                BasicBlock* destBB = *it_destBB;
                // auto dest_id = (std::rand()<<16) || std::rand();
                switchInst->addCase(ConstantInt::get(Type::getInt32Ty(IRB_loopentry.getContext()), i), destBB);
            }
            it_destBB = newit_begin;
            for (int i=1; i<orig_inst_count; i++, it_destBB++) {
                BasicBlock* destBB = *it_destBB;
                destBB->back().eraseFromParent();
                IRBuilder<> IRB_dest(destBB);
                IRB_dest.CreateStore(ConstantInt::get(Type::getInt32Ty(IRB_dest.getContext()), i), switchVarPtr);
                IRB_dest.CreateBr(defaultBB);
            }
            IRBuilder<> IRB_default(defaultBB);
            IRB_default.CreateBr(loopEntryBB);

            // log
            dispatchMap[vmbegin] = dispatchBB;
        }

        // fix terminator of original blocks
        for (int x=0; x<origBBs.size(); x++) {
            BasicBlock* vmend = (x+1)<origBBs.size() ? origBBs[x+1] : nullptr;
            std::vector<BasicBlock*>::iterator newit_end = (vmend == nullptr) ? newBBs.end() : std::find(newBBs.begin(), newBBs.end(), vmend);
            BasicBlock* termBB = *std::prev(newit_end);
            Instruction* termInst = termBB->getTerminator();
            assert(termInst && "obfuscated BB has no TermInst");
            for (unsigned int i=0; i<termInst->getNumSuccessors(); i++) {
                auto newSucIt = dispatchMap.find(termInst->getSuccessor(i));
                assert (newSucIt != dispatchMap.end() && "obfuscated BB has unknown successor");
                termInst->setSuccessor(i, newSucIt->second);
            }
        }

        fixStack(&F);
    }

    return PreservedAnalyses::none();
}


void FunctionCrusher::crushBB(Module& M, Function& F, BasicBlock& BB) {

    // split all instructions to individual basic blocks
    BasicBlock* splitingBB = &BB;
    while (splitingBB->size() >= 2) {
        auto sp = splitingBB->begin();
        sp++;
        splitingBB = splitingBB->splitBasicBlock(sp);
    }
}
