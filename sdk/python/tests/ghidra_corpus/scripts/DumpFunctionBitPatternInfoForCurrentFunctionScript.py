## ###
# IP: GHIDRA
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Modified for revkit's Ghidra compatibility tests: ported from Ghidra 12.1.4's
# Ghidra/Features/BytePatterns/ghidra_scripts/DumpFunctionBitPatternInfoForCurrentFunctionScript.java
# to Python 3, with the Ghidra API calls as they were.
##
# Use this script to dump the information about the function bit patterns for the
# current function to the ghidra console.
# @category Functions

from ghidra.app.script import GhidraScript
from ghidra.bitpatterns.info import DataGatheringParams, FunctionBitPatternInfo
from ghidra.program.model.listing import Function

NUM_FIRST_BYTES = 10
NUM_FIRST_INSTRUCTIONS = 4
NUM_PRE_BYTES = 10
NUM_PRE_INSTRUCTIONS = 4
NUM_RETURN_BYTES = 12
NUM_RETURN_INSTRUCTIONS = 4
contextRegisters = None

params = DataGatheringParams()
params.setNumPreBytes(NUM_PRE_BYTES)
params.setNumFirstBytes(NUM_FIRST_BYTES)
params.setNumReturnBytes(NUM_RETURN_BYTES)
params.setNumPreInstructions(NUM_PRE_INSTRUCTIONS)
params.setNumFirstInstructions(NUM_FIRST_INSTRUCTIONS)
params.setNumReturnInstructions(NUM_RETURN_INSTRUCTIONS)
params.setContextRegisters(contextRegisters)

func = currentProgram.getFunctionManager().getFunctionContaining(currentAddress)
if func is None:
    popup("No function at currentAddress " + currentAddress.toString())
else:
    fStart = FunctionBitPatternInfo(currentProgram, func, params)
    printf("%s\n\n", fStart.toString())
