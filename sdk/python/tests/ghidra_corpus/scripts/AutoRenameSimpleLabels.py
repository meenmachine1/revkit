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
# Ghidra/Features/Base/ghidra_scripts/AutoRenameSimpleLabels.java
# to Python 3, with the Ghidra API calls as they were.
##
# Renames labels that are just RET or branch instructions
# @category Symbol

from ghidra.app.script import GhidraScript
from ghidra.program.model.listing import CommentType, Instruction
from ghidra.program.model.symbol import FlowType, Reference, SourceType, Symbol, SymbolIterator


def isDefaultName(symbol):
    return symbol.getSource().isLowerOrEqualPriorityThan(SourceType.ANALYSIS)


iter = currentProgram.getSymbolTable().getAllSymbols(True)
modified_count = 0
while iter.hasNext() and not monitor.isCancelled():
    s = iter.next()
    startAddr = s.getAddress()
    if not startAddr.isLoadedMemoryAddress():
        continue
    inst = getInstructionAt(startAddr)
    if inst is None:
        continue
    flow = inst.getFlowType()
    operand = " "
    operand = inst.getDefaultOperandRepresentation(0)
    if operand is None:  # catch (NullPointerException excp)
        continue
    if flow.isFallthrough():
        continue
    if flow.isConditional():
        continue
    if flow.isTerminal():
        newName = "ret_" + startAddr.toString(False).upper()
        if s.getName().lower() == newName.lower():
            continue
        if not isDefaultName(s):
            continue
        println("Renaming RET @ " + startAddr.toString(False).upper() + ": " + s.getName() + " to " + newName)
        s.setName(newName, SourceType.ANALYSIS)
        modified_count += 1
    elif flow.isJump():
        newName = "branch_" + startAddr.toString(False).upper() + "_" + operand
        if inst.getOperandReferences(0) is None or len(inst.getOperandReferences(0)) == 0:
            continue
        ref = inst.getOperandReferences(0)[0]
        operand_sym = currentProgram.getSymbolTable().getSymbol(ref)
        if operand_sym is None:
            continue
        operand_addr = operand_sym.getAddress()
        if s.getName().lower() != newName.lower():
            if isDefaultName(s):
                if operand_addr == startAddr:
                    continue
                println("Renaming BR @ " + startAddr.toString(False).upper() + ": " + s.getName() + " to " + newName)
                s.setName(newName, SourceType.ANALYSIS)
                modified_count += 1
        comment = currentProgram.getListing().getComment(CommentType.REPEATABLE, operand_addr)
        if comment is not None and currentProgram.getListing().getComment(CommentType.REPEATABLE, startAddr) is None:
            currentProgram.getListing().setComment(startAddr, CommentType.REPEATABLE, comment)
println("Modified a total of " + str(modified_count) + " entries")
