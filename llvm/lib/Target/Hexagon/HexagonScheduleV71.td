//=-HexagonScheduleV71.td - HexagonV71 Scheduling Definitions *- tablegen -*-=//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

//
// ScalarItin and HVXItin contain some old itineraries still used by a handful
// of instructions. Hopefully, we will be able to get rid of them soon.
def HexagonV71ItinList : DepScalarItinV71, ScalarItin,
                         DepHVXItinV71, HVXItin, PseudoItin {
  list<InstrItinData> ItinList =
    !listconcat(DepScalarItinV71_list, ScalarItin_list,
                DepHVXItinV71_list, HVXItin_list, PseudoItin_list);
}

def HexagonItinerariesV71 :
      ProcessorItineraries<[SLOT0, SLOT1, SLOT2, SLOT3, SLOT_ENDLOOP,
                            CVI_ST, CVI_XLANE, CVI_SHIFT, CVI_MPY0, CVI_MPY1,
                            CVI_LD, CVI_XLSHF, CVI_MPY01, CVI_ALL,
                            CVI_ALL_NOMEM, CVI_ZW],
                            [Hex_FWD, HVX_FWD],
                            HexagonV71ItinList.ItinList>;

def HexagonModelV71 : SchedMachineModel {
  // Max issue per cycle == bundle width.
  let IssueWidth = 4;
  let Itineraries = HexagonItinerariesV71;
  let LoadLatency = 1;
  let CompleteModel = 0;
}

//===----------------------------------------------------------------------===//
// Hexagon V71 Resource Definitions -
//===----------------------------------------------------------------------===//

