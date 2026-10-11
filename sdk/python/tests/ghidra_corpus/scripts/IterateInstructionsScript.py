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
# Ghidra/Features/Base/ghidra_scripts/IterateInstructionsScript.java
# to Python 3, with the Ghidra API calls as they were.
##
# Iterates over all instructions in the current program.
# @category Examples

from ghidra.app.script import GhidraScript
from ghidra.program.model.listing import Instruction

instruction = getFirstInstruction()
while True:
    if monitor.isCancelled():
        break
    if instruction is None:
        break
    buffer = []
    buffer.append(str(instruction.getMinAddress()))
    buffer.append(' ')
    buffer.append(instruction.getMnemonicString())
    buffer.append(' ')
    nOperands = instruction.getNumOperands()
    for i in range(nOperands):
        operand = instruction.getDefaultOperandRepresentation(i)
        buffer.append(operand)
        buffer.append(' ')
    println("".join(buffer))
    instruction = getInstructionAfter(instruction)
