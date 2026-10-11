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
# Ghidra/Features/Base/ghidra_scripts/IterateFunctionsScript.java
# to Python 3, with the Ghidra API calls as they were.
##
# Iterates over all functions in the current program.
# @category Examples

from ghidra.app.script import GhidraScript
from ghidra.program.model.listing import Function


def iterateForward():
    function = getFirstFunction()
    count = 0
    while True:
        if monitor.isCancelled():
            break
        if function is None:
            break
        string = str(count) + "  :  " + function.getName() + " @ " + str(function.getEntryPoint())
        monitor.setMessage(string)
        println(string)
        function = getFunctionAfter(function)
        count += 1
    println("found forward = " + str(count))


def iterateBackward():
    function = getLastFunction()
    count = 0
    while True:
        if monitor.isCancelled():
            break
        if function is None:
            break
        string = str(count) + "  :  " + function.getName() + " @ " + str(function.getEntryPoint())
        monitor.setMessage(string)
        println(string)
        function = getFunctionBefore(function)
        count += 1
    println("found forward = " + str(count))


forward = askYesNo("Iterate Function", "Do you want to iterate from low address to high address?")
if forward:
    iterateForward()
else:
    iterateBackward()
