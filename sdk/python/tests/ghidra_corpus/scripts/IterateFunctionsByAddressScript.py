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
# Ghidra/Features/Base/ghidra_scripts/IterateFunctionsByAddressScript.java
# to Python 3, with the Ghidra API calls as they were.
##
# Iterates over all functions in the current program
# starting at the minimum address of the program.
#
# @category Examples

from ghidra.app.script import GhidraScript
from ghidra.program.model.address import Address
from ghidra.program.model.listing import Function, FunctionIterator


def iterateForward():
    # Use the iterator, there is no easy way to use the function iterator on addresses
    #   If the function begins at address zero, you won't get the function without
    #   a lot of extra more complicated code.
    fiter = currentProgram.getFunctionManager().getFunctions(True)
    count = 0
    while fiter.hasNext():
        function = fiter.next()
        if monitor.isCancelled():
            break
        string = str(count) + "  :  " + function.getName() + " @ " + str(function.getEntryPoint())
        monitor.setMessage(string)
        println(string)
        count += 1
    println("found " + str(count) + " functions ")


def iterateBackward():
    minAddress = currentProgram.getMinAddress()
    address = currentProgram.getMaxAddress()
    count = 0
    while address.compareTo(minAddress) >= 0:
        if monitor.isCancelled():
            break
        function = getFunctionBefore(address)
        if function is None:
            break
        string = str(count) + "  :  " + function.getName() + " @ " + str(function.getEntryPoint())
        monitor.setMessage(string)
        println(string)
        address = function.getEntryPoint()
        count += 1
    println("found " + str(count) + " functions ")


forward = askYesNo("Iterate Function", "Do you want to iterate from low address to high address?")
if forward:
    iterateForward()
else:
    iterateBackward()
