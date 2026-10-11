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
# docs/GhidraClass/AdvancedDevelopment/contrib/gadc/ghidra_scripts/Lab5Script.java
# to Python 3, with the Ghidra API calls as they were.
##
# This script searches through all instructions that are
# moving a scalar into a register
# and sets an EOL comment in the form "[register] = [value]"
# @category GADC

from ghidra.app.script import GhidraScript
from ghidra.program.model.lang import Register
from ghidra.program.model.listing import Instruction
from ghidra.program.model.scalar import Scalar

instruction = getFirstInstruction()
while instruction is not None:
    if monitor.isCancelled():
        break
    if instruction.getNumOperands() != 2:
        instruction = getInstructionAfter(instruction)
        continue

    opObjects0 = instruction.getOpObjects(0)
    if len(opObjects0) != 1 or not isinstance(opObjects0[0], Register):
        instruction = getInstructionAfter(instruction)
        continue

    opObjects1 = instruction.getOpObjects(1)
    if len(opObjects1) != 1 or not isinstance(opObjects1[0], Scalar):
        instruction = getInstructionAfter(instruction)
        continue

    register = opObjects0[0]
    scalar = opObjects1[0]
    comment = "[" + register.getName() + "]=[" + scalar.toString(16, False, False, "", "") + "]"
    setEOLComment(instruction.getMinAddress(), comment)
    instruction = getInstructionAfter(instruction)
