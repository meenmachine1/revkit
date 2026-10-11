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
# Ghidra/Features/Base/ghidra_scripts/MakeFunctionsScript.java
# to Python 3, with the Ghidra API calls as they were.
##
# Script to ask user for a byte sequence that is a common function start
# make functions at those locations
# if code has only one block it asks the user where the data block is and splits the program into
# code and data blocks
# @category Functions

from ghidra.app.script import GhidraScript
from ghidra.program.model.address import Address
from ghidra.program.model.listing import Function
from ghidra.program.model.mem import Memory, MemoryBlock

memory = currentProgram.getMemory()
functionBytes = askBytes("Enter Byte Pattern", "Please enter your function byte pattern separated by spaces")
while (not monitor.isCancelled()) and ((functionBytes is None) or (len(functionBytes) == 0)):
    functionBytes = askBytes("Invalid Byte Pattern", "Please re-enter your function byte pattern in separated by spaces")
textBytes = ""
for i in range(len(functionBytes)):
    textBytes = textBytes + toHexString(functionBytes[i], True, False)
    textBytes = textBytes + " "
println("Searching for " + textBytes + ". . .")

memoryBlock = currentProgram.getMemory().getBlocks()
if len(memoryBlock) == 1:
    dataAddress = askAddress("Create data block", "Please enter the start address of the data section.")
    memory.split(memoryBlock[0], dataAddress)
    # get the blocks again to get new split one
    memoryBlock = currentProgram.getMemory().getBlocks()
    if memoryBlock[1].contains(dataAddress):
        memoryBlock[1].setName("Data")
        memoryBlock[1].setExecute(False)
    elif memoryBlock[0].contains(dataAddress):
        memoryBlock[0].setName("Data")
        memoryBlock[0].setExecute(False)

foundCount = 0
madeCount = 0
for i in range(len(memoryBlock)):
    if memoryBlock[i].isExecute():
        keepSearching = True
        start = memoryBlock[i].getStart()
        end = memoryBlock[i].getEnd()

        while keepSearching and (not monitor.isCancelled()):
            found = memory.findBytes(start, end, functionBytes, None, True, monitor)
            if (found is not None) and memoryBlock[i].contains(found):
                foundCount += 1
                testFunc = getFunctionContaining(found)
                if testFunc is None:
                    didDisassemble = disassemble(found)
                    if didDisassemble:
                        func = createFunction(found, None)
                        if func is not None:
                            println("Made function at address: " + found.toString())
                            madeCount += 1
                        else:
                            println("***Function could not be made at address: " + found.toString())
                else:
                    println("Function already exists at address: " + found.toString())
                start = found.add(4)
            else:
                keepSearching = False

if foundCount == 0:
    println("No functions found with given byte pattern.")
elif madeCount == 0:
    println("No new functions made with given byte pattern.")
