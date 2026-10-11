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
# Ghidra/Features/Base/ghidra_scripts/CreateFunctionsFromSelection.java
# to Python 3, with the Ghidra API calls as they were.
##
# Create Multiple functions from a selection by starting at the top
# of the selection and creating a new function.  Then create a new function
# at the next address that didn't get added to the body of the first function.
# Continue doing this until all addresses have been used up.
#
# This is very useful when used with Search->DeadSubroutines
#
# @category Functions

from ghidra.app.script import GhidraScript
from ghidra.program.model.address import Address, AddressIterator

if currentSelection is not None and not currentSelection.isEmpty():
    iter = currentSelection.getAddresses(True)
    while iter.hasNext():
        addrStart = iter.next()
        if getFunctionContaining(addrStart) is not None:
            continue
        createFunction(addrStart, None)
