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
# Ghidra/Features/Base/ghidra_scripts/DeleteFunctionDefaultPlatesScript.java
# to Python 3, with the Ghidra API calls as they were.
##
# Removes default plate comments for all functions in the program or over a selection.
# " FUNCTION" is considered the default value for the plate comment.
# @category Update

from ghidra.app.script import GhidraScript
from ghidra.program.model.address import AddressSetView
from ghidra.program.model.listing import Function, FunctionIterator

DEFAULT_PLATE = " FUNCTION"

set = currentProgram.getMemory()
if currentSelection is not None and not currentSelection.isEmpty():
    set = currentSelection

updateCount = 0
iter = currentProgram.getFunctionManager().getFunctions(set, True)
while iter.hasNext():
    function = iter.next()
    comment = function.getCommentAsArray()
    if len(comment) == 1 and comment[0] == DEFAULT_PLATE:
        function.setComment(None)
        updateCount += 1

if updateCount > 0:
    cmt = "comments" if updateCount > 1 else "comment"
    println("Removed " + str(updateCount) + " default plate " + cmt + ".")
else:
    println("Did not find any default plate comments.")
