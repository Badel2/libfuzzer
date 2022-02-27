//===- FuzzerTracePC.h - Internal header for the Fuzzer ---------*- C++ -* ===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
// fuzzer::TracePC
//===----------------------------------------------------------------------===//

#ifndef LLVM_FUZZER_TRACE_PC
#define LLVM_FUZZER_TRACE_PC

#include "FuzzerDefs.h"
#include "FuzzerDictionary.h"
#include "FuzzerValueBitMap.h"
#include "json.hpp"

#include <set>
#include <unordered_map>

using json = nlohmann::json;

namespace fuzzer {

// TableOfRecentCompares (TORC) remembers the most recently performed
// comparisons of type T.
// We record the arguments of CMP instructions in this table unconditionally
// because it seems cheaper this way than to compute some expensive
// conditions inside __sanitizer_cov_trace_cmp*.
// After the unit has been executed we may decide to use the contents of
// this table to populate a Dictionary.
template<class T, size_t kSizeT>
struct TableOfRecentCompares {
  static const size_t kSize = kSizeT;
  struct Pair {
    T A, B;
  };
  ATTRIBUTE_NO_SANITIZE_ALL
  void Insert(size_t Idx, const T &Arg1, const T &Arg2) {
    Idx = Idx % kSize;
    Table[Idx].A = Arg1;
    Table[Idx].B = Arg2;
  }

  Pair Get(size_t I) { return Table[I % kSize]; }

  Pair Table[kSize];

  void to_json(json& j) const {
    j["Table"] = json::array();
    for (size_t i = 0; i < kSize; i++) {
      auto pair = Table[i];
      json jPair = json::array();
      // HACK: serialize using T.to_json if T is FixedWord<64>
      // Because this struct is used with T=uint32_t, T=uint64_t, and T=Word
      // Both uint32_t and uint64_t can be converted to JSON automatically, so they do not need
      // the explicit conversion
      if constexpr (std::is_same<T, FixedWord<64>>::value) {
          json jA;
          pair.A.to_json(jA);
          jPair.push_back(jA);
          json jB;
          pair.B.to_json(jB);
          jPair.push_back(jB);
      } else {
          jPair.push_back(pair.A);
          jPair.push_back(pair.B);
      }
      j["Table"].push_back(jPair);
    }
  }
  void from_json(const json& j) {
    assert(j.at("Table").size() == kSize);
    for (size_t i = 0; i < j.at("Table").size(); i++) {
        auto pair = j.at("Table")[i];
        assert(pair.size() == 2);
        // Same hack as in to_json
        if constexpr (std::is_same<T, FixedWord<64>>::value) {
          Pair p;
          p.A.from_json(pair[0]);
          p.B.from_json(pair[1]);
          Table[i] = p;
        } else {
          T A = pair[0];
          T B = pair[1];
          Table[i] = Pair { A, B };
        }
    }
  }
};

template <size_t kSizeT>
struct MemMemTable {
  static const size_t kSize = kSizeT;
  Word MemMemWords[kSize];
  Word EmptyWord;

  void Add(const uint8_t *Data, size_t Size) {
    if (Size <= 2) return;
    Size = std::min(Size, Word::GetMaxSize());
    auto Idx = SimpleFastHash(Data, Size) % kSize;
    MemMemWords[Idx].Set(Data, Size);
  }
  const Word &Get(size_t Idx) {
    for (size_t i = 0; i < kSize; i++) {
      const Word &W = MemMemWords[(Idx + i) % kSize];
      if (W.size()) return W;
    }
    EmptyWord.Set(nullptr, 0);
    return EmptyWord;
  }

  void to_json(json& j) const {
    j["MemMemWords"] = json::array();
    for (size_t i = 0; i < kSize; i++) {
      auto w = MemMemWords[i];
      json jW;
      w.to_json(jW);
      j["MemMemWords"].push_back(jW);
    }
    // Do not serialize EmptyWord, it is just an empty word
  }
  void from_json(const json& j) {
    assert(j.at("MemMemWords").size() == kSize);
    for (size_t i = 0; i < kSize; i++) {
      MemMemWords[i].from_json(j.at("MemMemWords")[i]);
    }
    EmptyWord.Set(nullptr, 0);
  }
};

class TracePC {
 public:
  void HandleInline8bitCountersInit(uint8_t *Start, uint8_t *Stop);
  void HandlePCsInit(const uintptr_t *Start, const uintptr_t *Stop);
  void HandleCallerCallee(uintptr_t Caller, uintptr_t Callee);
  template <class T> void HandleCmp(uintptr_t PC, T Arg1, T Arg2);
  size_t GetTotalPCCoverage();
  void SetUseCounters(bool UC) { UseCounters = UC; }
  void SetUseValueProfileMask(uint32_t VPMask) { UseValueProfileMask = VPMask; }
  void SetPrintNewPCs(bool P) { DoPrintNewPCs = P; }
  void SetPrintNewFuncs(size_t P) { NumPrintNewFuncs = P; }
  void UpdateObservedPCs();
  template <class Callback> size_t CollectFeatures(Callback CB) const;

  void ResetMaps() {
    ValueProfileMap.Reset();
    ClearExtraCounters();
    ClearInlineCounters();
  }

  void ClearInlineCounters();

  void UpdateFeatureSet(size_t CurrentElementIdx, size_t CurrentElementSize);
  void PrintFeatureSet();

  void PrintModuleInfo();

  void PrintCoverage(bool PrintAllCounters);

  template<class CallBack>
  void IterateCoveredFunctions(CallBack CB);

  void AddValueForMemcmp(void *caller_pc, const void *s1, const void *s2,
                         size_t n, bool StopAtZero);

  TableOfRecentCompares<uint32_t, 32> TORC4;
  TableOfRecentCompares<uint64_t, 32> TORC8;
  TableOfRecentCompares<Word, 32> TORCW;
  MemMemTable<1024> MMT;

  void RecordInitialStack();
  uintptr_t GetMaxStackOffset() const;

  template<class CallBack>
  void ForEachObservedPC(CallBack CB) {
    for (auto PC : ObservedPCs)
      CB(PC);
  }

  void SetFocusFunction(const std::string &FuncName);
  bool ObservedFocusFunction();

  struct PCTableEntry {
    uintptr_t PC, PCFlags;

    void to_json(json& j) const {
        j["PC"] = PC;
        j["PCFlags"] = PCFlags;
    }
    void from_json(const json& j) {
        j.at("PC").get_to(PC);
        j.at("PCFlags").get_to(PCFlags);
    }
  };

  uintptr_t PCTableEntryIdx(const PCTableEntry *TE) const;
  const PCTableEntry *PCTableEntryByIdx(uintptr_t Idx);
  static uintptr_t GetNextInstructionPc(uintptr_t PC);
  bool PcIsFuncEntry(const PCTableEntry *TE) { return TE->PCFlags & 1; }

  void to_json(json& j) const {
/*
  TableOfRecentCompares<uint32_t, 32> TORC4;
  TableOfRecentCompares<uint64_t, 32> TORC8;
  TableOfRecentCompares<Word, 32> TORCW;
  MemMemTable<1024> MMT;
*/
    json jTORC4;
    TORC4.to_json(jTORC4);
    j["TORC4"] = jTORC4;
    json jTORC8;
    TORC8.to_json(jTORC8);
    j["TORC8"] = jTORC8;
    json jTORCW;
    TORCW.to_json(jTORCW);
    j["TORCW"] = jTORCW;
    json jMMT;
    MMT.to_json(jMMT);
    j["MMT"] = jMMT;

/*
  bool UseCounters = false;
  uint32_t UseValueProfileMask = false;
  bool DoPrintNewPCs = false;
  size_t NumPrintNewFuncs = 0;
*/
    j["UseCounters"] = UseCounters;
    j["UseValueProfileMask"] = UseValueProfileMask;
    j["DoPrintNewPCs"] = DoPrintNewPCs;
    j["NumPrintNewFuncs"] = NumPrintNewFuncs;

/*
  Module Modules[4096];
  size_t NumModules;  // linker-initialized.
  size_t NumInline8bitCounters;
*/
    // NumModules is simply the len of Modules, so it is not serialized
    j["Modules"] = json::array();
    for (size_t i = 0; i < NumModules; i++) {
      json jM;
      Modules[i].to_json(jM);
      j["Modules"].push_back(jM);
    }
    j["NumInline8bitCounters"] = NumInline8bitCounters;

/*
  struct { const PCTableEntry *Start, *Stop; } ModulePCTable[4096];
  size_t NumPCTables;
  size_t NumPCsInPCTables;
*/
    // NumPCTables is simply the len of ModulePCTable, so it is not serialized
    j["ModulePCTable"] = json::array();
    for (size_t i = 0; i < NumPCTables; i++) {
      json jM = json::array();
      for (auto it = ModulePCTable[i].Start; it < ModulePCTable[i].Stop; it++) {
        json j2;
        it->to_json(j2);
        jM.push_back(j2);
      }
      j["ModulePCTable"].push_back(jM);
    }
    j["NumPCsInPCTables"] = NumPCsInPCTables;

/*
  Set<const PCTableEntry*> ObservedPCs;
  std::unordered_map<uintptr_t, uintptr_t> ObservedFuncs;  // PC => Counter.
*/
    // TODO: who owns PCTableEntry?
    // If ObservedPCs must not own it, then we cannot simply deserialize ObservedPCs, it must point
    // to PCTableEntry that were allocated somewhere else
    //j["ObservedPCs"] = ObservedPCs;
    // Skipping serialization, to deserialize call:
    //UpdateObservedPCs();
    // Actually, we can convert PCTableEntry* into uintptr_t, so let's do that
    Set<uintptr_t> ObservedPCsAsIndexes {};
    for (auto opc : ObservedPCs) {
        ObservedPCsAsIndexes.insert(PCTableEntryIdx(opc));
    }
    j["ObservedPCs"] = ObservedPCsAsIndexes;
    j["ObservedFuncs"] = ObservedFuncs;

/*
  uint8_t *FocusFunctionCounterPtr = nullptr;
*/

    // TODO: to deserialize FocusFunctionCounterPtr simply make sure that
    // TPC.SetFocusFunction(FocusFunctionOrAuto);
    // is called

/*
  ValueBitMap ValueProfileMap;
  uintptr_t InitialStack;
*/
    json jValueProfileMap;
    ValueProfileMap.to_json(jValueProfileMap);
    j["ValueProfileMap"] = jValueProfileMap;
    // InitialStack probably does not need to be serialized, because it will be
    // reset by TPC.RecordInitialStack anyway.
    // But it can be a good check, if this value changed then the reset of the data may also be
    // wrong.
    //j["InitialStack"] = InitialStack;
  }

  void from_json(const json& j) {
    TORC4.from_json(j.at("TORC4"));
    TORC8.from_json(j.at("TORC8"));
    TORCW.from_json(j.at("TORCW"));
    MMT.from_json(j.at("MMT"));

    j.at("UseCounters").get_to(UseCounters);
    j.at("UseValueProfileMask").get_to(UseValueProfileMask);
    j.at("DoPrintNewPCs").get_to(DoPrintNewPCs);
    j.at("NumPrintNewFuncs").get_to(NumPrintNewFuncs);

    // Modules must be exactly the same as in the JSON file
    assert(j.at("Modules").size() == NumModules);
    for (size_t i = 0; i < NumModules; i++) {
      json jM = j.at("Modules")[i];
      Modules[i].from_json(jM);
    }
    j.at("NumInline8bitCounters").get_to(NumInline8bitCounters);

    // ModulePCTable must be exactly the same as in the JSON file
    assert(j.at("ModulePCTable").size() == NumPCTables);
    for (size_t i = 0; i < NumPCTables; i++) {
      json jM = j.at("ModulePCTable")[i];
      assert(jM.size() == ModulePCTable[i].Stop - ModulePCTable[i].Start);
      size_t j = 0;
      // TODO: not sure if it is possible to initialize ModulePCTable like this.
      // If it doesn't work, check if maybe it does not need to be serialized because
      // it is loaded before reading corpus or something.
      for (auto it = (PCTableEntry*) ModulePCTable[i].Start; it < ModulePCTable[i].Stop; it++) {
        const json& jMj = jM[j];
        it->from_json(jM[j]);
        j++;
      }
    }

    Set<uintptr_t> ObservedPCsAsIndexes {};
    j.at("ObservedPCs").get_to(ObservedPCsAsIndexes);
    for (auto opi : ObservedPCsAsIndexes) {
        ObservedPCs.insert(PCTableEntryByIdx(opi));
    }
    j.at("ObservedFuncs").get_to(ObservedFuncs);

    j.at("NumPCsInPCTables").get_to(NumPCsInPCTables);

    ValueProfileMap.from_json(j.at("ValueProfileMap"));
  }
private:
  bool UseCounters = false;
  uint32_t UseValueProfileMask = false;
  bool DoPrintNewPCs = false;
  size_t NumPrintNewFuncs = 0;

  // Module represents the array of 8-bit counters split into regions
  // such that every region, except maybe the first and the last one, is one
  // full page.
  struct Module {
    struct Region {
      uint8_t *Start, *Stop;
      bool Enabled;
      bool OneFullPage;

/*
      void to_json(json& j) const {
        j["StartStop"] = json::array();
        for (auto it = Start; it < Stop; it++) {
            j["StartStop"].push_back(*it);
        }
        j["Enabled"] = Enabled;
        j["OneFullPage"] = OneFullPage;
      }
      void from_json(const json& j) {
        // TODO: who does own the region? Who will free the memory?
        // Assuming that Region is already initialized...
        assert(Stop - Start == j.at("StartStop").size());
        j.at("Enabled").get_to(Enabled);
        j.at("OneFullPage").get_to(OneFullPage);
      }
*/
    };
    Region *Regions;
    size_t NumRegions;
    uint8_t *Start() { return Regions[0].Start; }
    uint8_t *Stop()  { return Regions[NumRegions - 1].Stop; }
    size_t Size()   { return Stop() - Start(); }
    size_t  Idx(uint8_t *P) {
      assert(P >= Start() && P < Stop());
      return P - Start();
    }
    void to_json(json& j) const {
        // Serialize Module as a single array, flattening all the Regions
        //Printf("serialize Module to JSON. size: %d:\n", Regions[NumRegions - 1].Stop - Regions[0].Start);
        j = json::array();
        for (uint8_t *x = Regions[0].Start; x < Regions[NumRegions - 1].Stop; x++) {
            j.push_back(*x);
        }
    }
    void from_json(const json& j) {
        size_t newSize = j.size();
        // The size must be exactly the same because I don't know how to
        // reallocate this data structure
        //Printf("loading Module from JSON. old module size: %d, new module size: %d:\n", Size(), newSize);
        assert(newSize == Size());
        /*
        Printf("loading Module from JSON. old module:\n");
        json old;
        to_json(old);
        Printf("%s\n", old.dump().c_str());
        */
        // TODO: who does own the region? Who will free the memory?
        // Assuming that Region is already initialized...
        for (size_t i = 0; i < Size(); i++) {
            Start()[i] = j[i];
        }
        // TODO: assuming that Enabled and OneFullPage are already initialized
    }
  };

  Module Modules[4096];
  size_t NumModules;  // linker-initialized.
  size_t NumInline8bitCounters;

  template <class Callback>
  void IterateCounterRegions(Callback CB) {
    for (size_t m = 0; m < NumModules; m++)
      for (size_t r = 0; r < Modules[m].NumRegions; r++)
        CB(Modules[m].Regions[r]);
  }

  struct { const PCTableEntry *Start, *Stop; } ModulePCTable[4096];
  size_t NumPCTables;
  size_t NumPCsInPCTables;

  std::set<const PCTableEntry *> ObservedPCs;
  std::unordered_map<uintptr_t, uintptr_t> ObservedFuncs;  // PC => Counter.

  uint8_t *FocusFunctionCounterPtr = nullptr;

  ValueBitMap ValueProfileMap;
  uintptr_t InitialStack;
};

template <class Callback>
// void Callback(size_t FirstFeature, size_t Idx, uint8_t Value);
ATTRIBUTE_NO_SANITIZE_ALL
size_t ForEachNonZeroByte(const uint8_t *Begin, const uint8_t *End,
                        size_t FirstFeature, Callback Handle8bitCounter) {
  typedef uintptr_t LargeType;
  const size_t Step = sizeof(LargeType) / sizeof(uint8_t);
  const size_t StepMask = Step - 1;
  auto P = Begin;
  // Iterate by 1 byte until either the alignment boundary or the end.
  for (; reinterpret_cast<uintptr_t>(P) & StepMask && P < End; P++)
    if (uint8_t V = *P)
      Handle8bitCounter(FirstFeature, P - Begin, V);

  // Iterate by Step bytes at a time.
  for (; P + Step <= End; P += Step)
    if (LargeType Bundle = *reinterpret_cast<const LargeType *>(P)) {
      Bundle = HostToLE(Bundle);
      for (size_t I = 0; I < Step; I++, Bundle >>= 8)
        if (uint8_t V = Bundle & 0xff)
          Handle8bitCounter(FirstFeature, P - Begin + I, V);
    }

  // Iterate by 1 byte until the end.
  for (; P < End; P++)
    if (uint8_t V = *P)
      Handle8bitCounter(FirstFeature, P - Begin, V);
  return End - Begin;
}

// Given a non-zero Counter returns a number in the range [0,7].
template<class T>
unsigned CounterToFeature(T Counter) {
    // Returns a feature number by placing Counters into buckets as illustrated
    // below.
    //
    // Counter bucket: [1] [2] [3] [4-7] [8-15] [16-31] [32-127] [128+]
    // Feature number:  0   1   2    3     4       5       6       7
    //
    // This is a heuristic taken from AFL (see
    // http://lcamtuf.coredump.cx/afl/technical_details.txt).
    //
    // This implementation may change in the future so clients should
    // not rely on it.
    assert(Counter);
    unsigned Bit = 0;
    /**/ if (Counter >= 128) Bit = 7;
    else if (Counter >= 32) Bit = 6;
    else if (Counter >= 16) Bit = 5;
    else if (Counter >= 8) Bit = 4;
    else if (Counter >= 4) Bit = 3;
    else if (Counter >= 3) Bit = 2;
    else if (Counter >= 2) Bit = 1;
    return Bit;
}

template <class Callback> // void Callback(uint32_t Feature)
ATTRIBUTE_NO_SANITIZE_ADDRESS ATTRIBUTE_NOINLINE size_t
TracePC::CollectFeatures(Callback HandleFeature) const {
  auto Handle8bitCounter = [&](size_t FirstFeature,
                               size_t Idx, uint8_t Counter) {
    if (UseCounters)
      HandleFeature(static_cast<uint32_t>(FirstFeature + Idx * 8 +
                                          CounterToFeature(Counter)));
    else
      HandleFeature(static_cast<uint32_t>(FirstFeature + Idx));
  };

  size_t FirstFeature = 0;

  for (size_t i = 0; i < NumModules; i++) {
    for (size_t r = 0; r < Modules[i].NumRegions; r++) {
      if (!Modules[i].Regions[r].Enabled) continue;
      FirstFeature += 8 * ForEachNonZeroByte(Modules[i].Regions[r].Start,
                                             Modules[i].Regions[r].Stop,
                                             FirstFeature, Handle8bitCounter);
    }
  }

  FirstFeature +=
      8 * ForEachNonZeroByte(ExtraCountersBegin(), ExtraCountersEnd(),
                             FirstFeature, Handle8bitCounter);

  if (UseValueProfileMask) {
    ValueProfileMap.ForEach([&](size_t Idx) {
      HandleFeature(static_cast<uint32_t>(FirstFeature + Idx));
    });
    FirstFeature += ValueProfileMap.SizeInBits();
  }

  // Step function, grows similar to 8 * Log_2(A).
  auto StackDepthStepFunction = [](size_t A) -> size_t {
    if (!A)
      return A;
    auto Log2 = Log(A);
    if (Log2 < 3)
      return A;
    Log2 -= 3;
    return (Log2 + 1) * 8 + ((A >> Log2) & 7);
  };
  assert(StackDepthStepFunction(1024) == 64);
  assert(StackDepthStepFunction(1024 * 4) == 80);
  assert(StackDepthStepFunction(1024 * 1024) == 144);

  if (auto MaxStackOffset = GetMaxStackOffset()) {
    HandleFeature(static_cast<uint32_t>(
        FirstFeature + StackDepthStepFunction(MaxStackOffset / 8)));
    FirstFeature += StackDepthStepFunction(std::numeric_limits<size_t>::max());
  }

  return FirstFeature;
}

extern TracePC TPC;

}  // namespace fuzzer

#endif  // LLVM_FUZZER_TRACE_PC
