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
# Ghidra/Features/Base/ghidra_scripts/ExportFunctionInfoScript.java
# to Python 3, with the Ghidra API calls as they were.
##
# List function names and entry point addresses to a file in JSON format
# @category Functions

import json

from ghidra.app.script import GhidraScript
from ghidra.program.model.address import Address
from ghidra.program.model.listing import Function, FunctionIterator, Listing

NAME = "name"
ENTRY = "entry"

# Gson's pretty printer and JsonWriter -> Python's json module
outputFile = askFile("Please Select Output File", "Choose")
functions = []
listing = currentProgram.getListing()
iter = listing.getFunctions(True)
while iter.hasNext() and not monitor.isCancelled():
    f = iter.next()
    name = f.getName()
    entry = f.getEntryPoint()
    jsonObject = {NAME: str(name), ENTRY: entry.toString()}
    functions.append(jsonObject)
with open(str(outputFile), "w") as jsonWriter:
    json.dump(functions, jsonWriter, indent=2)
println("Wrote functions to " + str(outputFile))
