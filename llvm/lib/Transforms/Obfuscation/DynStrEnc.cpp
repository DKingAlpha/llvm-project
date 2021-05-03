#include "llvm/Transforms/Obfuscation/Obfuscation.h"
#include "llvm/Pass.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/Demangle/Demangle.h"

#include <vector>
#include <set>
#include <random>

using namespace llvm;

cl::opt<bool> EnableDSE("obf-dse", cl::desc("enable dynamic string encryption"), cl::init(false));
cl::opt<bool> EnableDSEShuffle("obf-dse-shuffle", cl::desc("enable shuffle write in dynamic string encryption"), cl::init(true));

static struct SplittedElem {
    int id;
    int size;
    const char* ptr;
};

// 1, 2, 4, 8 Bytes
static int GetRandomSize(int limit) {
    int randnum = 1 << (std::rand() % 4);
    while (randnum > limit) {
        randnum /= 2;
    }
    return randnum;
}

StringRef DynStrEnc::name() {
    return "obf-dse";
}

Value* DynStrEnc::insertStrCode(Module& M, Function& F, Instruction* insert_point, GetElementPtrConstantExpr* gepce) {
    encrypted_count++;
    GlobalVariable* orig_str = cstrings.find(gepce->getOperandUse(0).getUser())->second;
    ConstantDataArray* orig_str_data = cast<ConstantDataArray>(orig_str->getInitializer());
    StringRef orig_raw = orig_str_data->getRawDataValues();   // with trailing 0
    int orig_raw_len = orig_raw.size();

    // generate trash
    char* random_raw = new char[orig_raw_len];
    assert(random_raw != nullptr && "insufficient memory"); 
    for (int i=0; i<orig_raw_len; i++) {
        random_raw[i] = std::rand() & 0xff;
    }
    std::vector<SplittedElem> random_raw_list;
    for (int i=0; i<orig_raw_len;) {
        int random_size = GetRandomSize(orig_raw_len-i);
        random_raw_list.push_back({i, random_size, random_raw+i});
        i+=random_size;
    }

    if (EnableDSEShuffle)
        std::shuffle(random_raw_list.begin(), random_raw_list.end(), std::default_random_engine(0));  // FIXME: specify seed

    // write trash
    IRBuilder<> IRB(insert_point);
    AllocaInst* AI = IRB.CreateAlloca(orig_str_data->getType());
    Value* AI8 = IRB.CreateBitCast(AI, ArrayType::get(Type::getInt8Ty(IRB.getContext()), orig_raw_len)->getPointerTo());
    for(auto it: random_raw_list) {
        Value* data_ptr = IRB.CreateGEP(AI8, SmallVector<Value*, 2>{
            ConstantInt::get(Type::getInt32Ty(IRB.getContext()), 0),
            ConstantInt::get(Type::getInt32Ty(IRB.getContext()), it.id)
        });
#define CREATE_STORE(SIZE) \
        Value* data_ptr_casted = IRB.CreateBitCast(data_ptr, Type::getInt##SIZE##PtrTy(IRB.getContext()));  \
        int##SIZE##_t tmp = *((int##SIZE##_t *)(it.ptr)); \
        IRB.CreateStore(IRB.getInt##SIZE(tmp), data_ptr_casted);

        if (it.size == 1) {CREATE_STORE(8)}
        else if (it.size == 2) {CREATE_STORE(16)}
        else if (it.size == 4) {CREATE_STORE(32)}
        else if (it.size == 8) {CREATE_STORE(64)}
#undef CREATE_STORE
    }
    
    // generate decrypt order
    std::vector<SplittedElem> decrypt_list;
    for (int i=0; i<orig_raw_len;) {
        int decrypt_size = GetRandomSize(orig_raw_len-i);
        decrypt_list.push_back({i, decrypt_size, orig_raw.data()+i});
        i+=decrypt_size;
    }

    if (EnableDSEShuffle)
        std::shuffle(decrypt_list.begin(), decrypt_list.end(), std::default_random_engine(0));  // FIXME: specify seed

    // decrypt trash to original data
    for (auto it : decrypt_list) {
        int decrypt_size = it.size;
#define DECRYPT_DATA(SIZE) \
            int##SIZE##_t data_a = *((int##SIZE##_t*)(random_raw+it.id));                           \
            int##SIZE##_t data_b = *((int##SIZE##_t*)(it.ptr));                                     \
            /* convert data_a to data_b  */                                                         \
            Value* gep_a = IRB.CreateGEP(AI8, SmallVector<Value*, 2>{                                \
                ConstantInt::get(Type::getInt32Ty(IRB.getContext()), 0),                            \
                ConstantInt::get(Type::getInt32Ty(IRB.getContext()), it.id)                         \
            });                                                                                     \
            Value* gep_a_casted = IRB.CreateBitCast(gep_a, Type::getInt##SIZE##PtrTy(IRB.getContext()));   \
            Value* v_a = IRB.CreateLoad(Type::getInt##SIZE##Ty(IRB.getContext()), gep_a_casted);    \
            Value* v_b = nullptr;                                                                   \
            int encrypt_method = std::rand() % 3;                                                   \
            if (encrypt_method == 0) {      /* xor */                                               \
                int##SIZE##_t xor_key = data_a ^ data_b;                                            \
                v_b = IRB.CreateXor(v_a, xor_key);                                                  \
            } else if (encrypt_method == 1) {   /* add */                                           \
                int##SIZE##_t add_key = data_b - data_a;                                            \
                v_b = IRB.CreateAdd(v_a, ConstantInt::get(Type::getInt##SIZE##Ty(IRB.getContext()), add_key)); \
            } else if (encrypt_method == 2) {   /* sub */                                           \
                int##SIZE##_t sub_key = data_a + data_b;                                            \
                v_b = IRB.CreateSub(ConstantInt::get(Type::getInt##SIZE##Ty(IRB.getContext()), sub_key), v_a); \
            }                                                                                       \
            IRB.CreateStore(v_b, gep_a_casted);

        if (decrypt_size == 1) { DECRYPT_DATA(8) }
        else if (decrypt_size == 2) { DECRYPT_DATA(16) }
        else if (decrypt_size == 4) { DECRYPT_DATA(32) }
        else if (decrypt_size == 8) { DECRYPT_DATA(64) }
#undef DECRYPT_DATA
    }

    // return final ptr
    Value* gep = IRB.CreateGEP(AI, SmallVector<Value*, 2>{
        ConstantInt::get(Type::getInt32Ty(IRB.getContext()), 0),
        ConstantInt::get(Type::getInt32Ty(IRB.getContext()), 0)
    });

    delete[] random_raw;
    return gep;
}

static bool isCStringOrWString(ConstantDataSequential* c) {
  // wchar_t is 16-bits on windows, 32-bits on *nix (according to wikipedia)
  if (!c->isString(8) && !c->isString(16) && !c->isString(32))
    return false;

  StringRef Str = c->getRawDataValues();

  // The last value must be nul.
  if (Str.back() != 0) return false;

  // wstring might contain \x00.
  return true;
}


PreservedAnalyses DynStrEnc::run(Module &M, ModuleAnalysisManager &AM) {
    if (!EnableDSE)
        return PreservedAnalyses::all();;

    encrypted_count = 0;
    cstrings.clear();

    for(auto& gv : M.globals()) {
        if (!gv.hasInitializer()) continue;
        if (!gv.isConstant()) { continue; }
        auto init = gv.getInitializer();
        if (!init->hasOneUse()) { continue; }
        ConstantDataArray* data = dyn_cast<ConstantDataArray>(init);
        if (!data) continue;
        if (!isCStringOrWString(data)) continue;
        for (auto U : gv.users()) {
            cstrings[U] = &gv;
            dbgs() << "adding " << demangle(std::string(gv.getName())) << "\n";
        }
    }

    // if cstring is referenced by a explicit global variable (e.g. const char* gv = "1234")
    // then DO NOT ENCRYPT THIS CSTRING !
    // otherwise the raw constant data is high likely to be leaked to another module.
    for (auto& gv : M.globals()) {
        if (gv.hasInitializer() && cstrings.find(gv.getInitializer()) != cstrings.end()) {
            GlobalVariable* affected_str = cstrings.find(gv.getInitializer())->second;
            for (auto it=cstrings.begin(); it != cstrings.end();) {
                if (it->second == affected_str) {
                    it = cstrings.erase(it);
                    dbgs() << "removing " << demangle(std::string(affected_str->getName())) << " (used by " << demangle(std::string(gv.getName())) << ")\n";
                } else {
                    it++;
                }
            }
        }
    }

    for (auto& F : M) {
        Value* replacement_cstr = nullptr;
        for (auto& BB : F) {
            for (auto& I : BB) {
                for(unsigned int i=0; i<I.getNumOperands(); i++) {
                    Value* v = I.getOperand(i);
                    GetElementPtrConstantExpr* gepce = dyn_cast<GetElementPtrConstantExpr>(v);
                    if (gepce && cstrings.find(gepce->getOperandUse(0).getUser()) != cstrings.end()) {
                        Instruction* insert_point = &I;
                        if (PHINode* phi = dyn_cast<PHINode>(&I)) {
                            insert_point = phi->getIncomingBlock(i)->getTerminator();
                        }
                        replacement_cstr = insertStrCode(M, F, insert_point, gepce);
                        I.setOperand(i, replacement_cstr);
                    }
                }
            }
        }
    }

    // remove original strings
    for (auto it=cstrings.begin(); it != cstrings.end(); it++) {
        it->second->eraseFromParent();
    }
    return PreservedAnalyses::none();
}
