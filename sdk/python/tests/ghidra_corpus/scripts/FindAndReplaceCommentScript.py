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
# Ghidra/Features/Base/ghidra_scripts/FindAndReplaceCommentScript.java
# to Python 3, with the Ghidra API calls as they were.
##
# This script will replace all comments with values matching the given user search value with the given user replacement value.
# @category Update

from ghidra.app.script import GhidraScript
from ghidra.program.model.address import Address, AddressIterator
from ghidra.program.model.listing import Listing
from ghidra.program.model.mem import Memory

COMMENT_TYPES = ["EOL", "Pre", "Post", "Plate", "Repeatable"]

listing = currentProgram.getListing()
memory = currentProgram.getMemory()
toFind = askString("Enter Search String", "Search String: ")
toReplace = askString("Enter Replace String", "Replace String: ")
replaced = False

commentAddresses = listing.getCommentAddressIterator(memory, True)
while commentAddresses.hasNext():
    address = commentAddresses.next()
    for i in range(len(COMMENT_TYPES)):
        commentValue = listing.getComment(i, address)
        if commentValue is not None and toFind in commentValue:
            replaced = True
            # StringUtils.replace -> str.replace
            listing.setComment(address, i, commentValue.replace(toFind, toReplace))
            printf("\nChanged %s Comment at address %s.\n", COMMENT_TYPES[i], address.toString())
if not replaced:
    println("No comment found with that value")
