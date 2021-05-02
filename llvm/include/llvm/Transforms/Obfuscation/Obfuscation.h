#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/Passes/PassBuilder.h"
#include "../../llvm/lib/IR/ConstantsContext.h"     // GetElementPtrConstantExpr

#include <map>

namespace llvm {
    
    class DynStrEnc : public PassInfoMixin<DynStrEnc> {
    public:
        static StringRef name();
        PreservedAnalyses run(Module &M, ModuleAnalysisManager &AM);
    private:
        int encrypted_count = 0;
        std::map<User*, GlobalVariable*> cstrings;
        Value* insertStrCode(Module& M, Function& F, Instruction* insert_point, GetElementPtrConstantExpr* gepce);

    };


    void inline injectObfuscationPasses(PassBuilder& pb) {
        pb.registerPipelineStartEPCallback([](ModulePassManager& MPM, PassBuilder::OptimizationLevel level) {
            MPM.addPass(DynStrEnc());
        });
        
    }
}

