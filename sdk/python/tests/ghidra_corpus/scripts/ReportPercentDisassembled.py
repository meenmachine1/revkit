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
# Ghidra/Features/Base/ghidra_scripts/ReportPercentDisassembled.java
# to Python 3, with the Ghidra API calls as they were.
##
# Reports the percentage of bytes in any executable section that were disassembled into instructions,
# or turned into defined data.
# This can be an "indicator" of how well the initial analysis was at finding all code.
#
# Assumes a program is open.
#
# @category Examples

from ghidra.app.script import GhidraScript
from ghidra.util import Msg

# find all the sections of memory marked as executable
prog = currentProgram
execMemSet = prog.getMemory().getExecuteSet()

# tally up all the bytes that have been marked as instructions
#   (probably faster ways to do this, but it works)
numPossibleDis = execMemSet.getNumAddresses()
instIter = prog.getListing().getInstructions(execMemSet, True)
instCount = 0
while instIter.hasNext():
    inst = instIter.next()
    instCount += inst.getLength()

dataIter = prog.getListing().getData(execMemSet, True)
dataCount = 0
while dataIter.hasNext():
    data = dataIter.next()
    if data.isDefined():
        dataCount += data.getLength()

# dump the info
total = instCount + dataCount
if numPossibleDis != 0:
    coverage = float(total) / float(numPossibleDis)
    percentage = coverage * 100
    Msg.info(None, "REPORT DISASSEMBLY EXTENT: " + prog.getName() + ": " + str(percentage) + "% disassembled.")
