//===-- CodeGen/AsmPrinter/DwarfException.cpp - Dwarf Exception Impl ------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file contains support for writing DWARF exception info into asm files.
//
//===----------------------------------------------------------------------===//

#include "DwarfException.h"
#include "llvm/ADT/Twine.h"
#include "llvm/BinaryFormat/Dwarf.h"
#include "llvm/CodeGen/AsmPrinter.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineModuleInfo.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/Mangler.h"
#include "llvm/IR/Module.h"
#include "llvm/MC/MCAsmInfo.h"
#include "llvm/MC/MCContext.h"
#include "llvm/MC/MCExpr.h"
#include "llvm/MC/MCSection.h"
#include "llvm/MC/MCStreamer.h"
#include "llvm/MC/MCSymbol.h"
#include "llvm/MC/MachineLocation.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/FormattedStream.h"
#include "llvm/Target/TargetLoweringObjectFile.h"
#include "llvm/Target/TargetMachine.h"
#include "llvm/Target/TargetOptions.h"
using namespace llvm;

DwarfCFIExceptionBase::DwarfCFIExceptionBase(AsmPrinter *A)
    : EHStreamer(A), shouldEmitCFI(false), hasEmittedCFISections(false) {}

void DwarfCFIExceptionBase::markFunctionEnd() {
  endFragment();

  // Map all labels and get rid of any dead landing pads.
  if (!Asm->MF->getLandingPads().empty()) {
    MachineFunction *NonConstMF = const_cast<MachineFunction*>(Asm->MF);
    NonConstMF->tidyLandingPads();
  }
}

void DwarfCFIExceptionBase::endFragment() {
  if (shouldEmitCFI && !Asm->MF->hasBBSections())
    Asm->OutStreamer->emitCFIEndProc();
}

DwarfCFIException::DwarfCFIException(AsmPrinter *A)
    : DwarfCFIExceptionBase(A), shouldEmitPersonality(false),
      forceEmitPersonality(false), shouldEmitLSDA(false) {}

DwarfCFIException::~DwarfCFIException() {}

/// endModule - Emit all exception information that should come after the
/// content.
void DwarfCFIException::endModule() {
  // SjLj uses this pass and it doesn't need this info.
  if (!Asm->MAI->usesCFIForEH())
    return;

  const TargetLoweringObjectFile &TLOF = Asm->getObjFileLowering();

  unsigned PerEncoding = TLOF.getPersonalityEncoding();

  if ((PerEncoding & 0x80) != dwarf::DW_EH_PE_indirect)
    return;

  // Emit references to all used personality functions
  for (const Function *Personality : MMI->getPersonalities()) {
    if (!Personality)
      continue;
    MCSymbol *Sym = Asm->getSymbol(Personality);
    TLOF.emitPersonalityValue(*Asm->OutStreamer, Asm->getDataLayout(), Sym);
  }
}

static MCSymbol *getExceptionSym(AsmPrinter *Asm,
                                 const MachineBasicBlock *MBB) {
  return Asm->getMBBExceptionSym(*MBB);
}

void DwarfCFIException::beginFunction(const MachineFunction *MF) {
  shouldEmitPersonality = shouldEmitLSDA = false;
  const Function &F = MF->getFunction();

  // If any landing pads survive, we need an EH table.
  bool hasLandingPads = !MF->getLandingPads().empty();

  // See if we need frame move info.
  AsmPrinter::CFIMoveType MoveType = Asm->needsCFIMoves();

  bool shouldEmitMoves = MoveType != AsmPrinter::CFI_M_None;

  const TargetLoweringObjectFile &TLOF = Asm->getObjFileLowering();
  unsigned PerEncoding = TLOF.getPersonalityEncoding();
  const Function *Per = nullptr;
  if (F.hasPersonalityFn())
    Per = dyn_cast<Function>(F.getPersonalityFn()->stripPointerCasts());

  // Emit a personality function even when there are no landing pads
  forceEmitPersonality =
      // ...if a personality function is explicitly specified
      F.hasPersonalityFn() &&
      // ... and it's not known to be a noop in the absence of invokes
      !isNoOpWithoutInvoke(classifyEHPersonality(Per)) &&
      // ... and we're not explicitly asked not to emit it
      F.needsUnwindTableEntry();

  shouldEmitPersonality =
      (forceEmitPersonality ||
       (hasLandingPads && PerEncoding != dwarf::DW_EH_PE_omit)) &&
      Per;

  unsigned LSDAEncoding = TLOF.getLSDAEncoding();
  shouldEmitLSDA = shouldEmitPersonality &&
    LSDAEncoding != dwarf::DW_EH_PE_omit;

  shouldEmitCFI = MF->getMMI().getContext().getAsmInfo()->usesCFIForEH() &&
                  (shouldEmitPersonality || shouldEmitMoves);
  beginFragment(&*MF->begin(), getExceptionSym);
}

void DwarfCFIException::beginFragment(const MachineBasicBlock *MBB,
                                      ExceptionSymbolProvider ESP) {
  if (!shouldEmitCFI)
    return;

  if (!hasEmittedCFISections) {
    if (Asm->needsOnlyDebugCFIMoves())
      Asm->OutStreamer->emitCFISections(false, true);
    else if (Asm->TM.Options.ForceDwarfFrameSection)
      Asm->OutStreamer->emitCFISections(true, true);
    hasEmittedCFISections = true;
  }

  Asm->OutStreamer->emitCFIStartProc(/*IsSimple=*/false);

  // Indicate personality routine, if any.
  if (!shouldEmitPersonality)
    return;

  auto &F = MBB->getParent()->getFunction();
  auto *P = dyn_cast<Function>(F.getPersonalityFn()->stripPointerCasts());
  assert(P && "Expected personality function");

  // If we are forced to emit this personality, make sure to record
  // it because it might not appear in any landingpad
  if (forceEmitPersonality)
    MMI->addPersonality(P);

  const TargetLoweringObjectFile &TLOF = Asm->getObjFileLowering();
  unsigned PerEncoding = TLOF.getPersonalityEncoding();
  const MCSymbol *Sym = TLOF.getCFIPersonalitySymbol(P, Asm->TM, MMI);
  Asm->OutStreamer->emitCFIPersonality(Sym, PerEncoding);

  // Provide LSDA information.
  if (shouldEmitLSDA)
    Asm->OutStreamer->emitCFILsda(ESP(Asm, MBB), TLOF.getLSDAEncoding());
}

/// endFunction - Gather and emit post-function exception information.
///
void DwarfCFIException::endFunction(const MachineFunction *MF) {
  if (!shouldEmitPersonality)
    return;

  emitExceptionTable();
}

void DwarfCFIException::beginBasicBlock(const MachineBasicBlock &MBB) {
  beginFragment(&MBB, getExceptionSym);
}

void DwarfCFIException::endBasicBlock(const MachineBasicBlock &MBB) {
  if (shouldEmitCFI)
    Asm->OutStreamer->emitCFIEndProc();
}
