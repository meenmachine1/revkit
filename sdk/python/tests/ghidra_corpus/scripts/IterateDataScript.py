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
# Ghidra/Features/Base/ghidra_scripts/IterateDataScript.java
# to Python 3, with the Ghidra API calls as they were.
##
# Iterates over all defined data in the current program.
# @category Examples

from ghidra.app.script import GhidraScript
from ghidra.program.model.listing import Data

data = getFirstData()
while True:
    if monitor.isCancelled():
        break
    if data is None:
        break
    buffer = []
    buffer.append(str(data.getMinAddress()))
    buffer.append(' ')
    buffer.append(data.getMnemonicString())
    buffer.append(' ')
    buffer.append(str(data.getValue()))
    println("".join(buffer))
    data = getDataAfter(data)
