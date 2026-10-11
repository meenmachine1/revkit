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
# Ghidra/Features/Base/ghidra_scripts/FindTextScript.java
# to Python 3, with the Ghidra API calls as they were.
##
# Prompts the user for a search string and searches the
# program listing for the first occurrence of that string.
# @category Search

from ghidra.app.script import GhidraScript
from ghidra.program.model.address import Address

if currentAddress is None:
    println("NO CURRENT ADDRESS")
elif currentProgram is None:
    println("NO CURRENT PROGRAM")
else:
    search = askString("Text Search", "Enter search string: ")
    addr = find(search)
    if addr is not None:
        println("Search match found at " + str(addr))
        goTo(addr)
    else:
        println("No search matched found.")
