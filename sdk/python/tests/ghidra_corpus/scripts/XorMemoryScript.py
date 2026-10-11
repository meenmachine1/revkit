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
# Ghidra/Features/Base/ghidra_scripts/XorMemoryScript.java
# to Python 3, with the Ghidra API calls as they were.
##
# XOR's the memory of the current program.
# @category Analysis

from ghidra.app.script import GhidraScript
from ghidra.program.model.address import Address, AddressIterator, AddressSet, AddressSetView
from ghidra.program.model.mem import Memory, MemoryBlock

# default to the current memory block
memory = currentProgram.getMemory()
block = memory.getBlock(currentAddress)
set = AddressSet(block.getStart(), block.getEnd())

if currentSelection is not None and not currentSelection.isEmpty():
    set = currentSelection

xorValues = askBytes("XorValue", "Values to xor with selected memory:")

valueLength = len(xorValues)
xorIndex = 0
aIter = set.getAddresses(True)
while aIter.hasNext() and not monitor.isCancelled():
    addr = aIter.next()
    monitor.setMessage(addr.toString())
    xorValue = xorValues[xorIndex]
    b = memory.getByte(addr)
    b = b ^ xorValue  # (byte) (b ^ xorValue): both are signed bytes, so is the result
    memory.setByte(addr, b)
    xorIndex += 1
    xorIndex = xorIndex % valueLength
