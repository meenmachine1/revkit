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
# Ghidra/Features/Base/ghidra_scripts/CountSymbolsScript.java
# to Python 3, with the Ghidra API calls as they were.
##
# Counts the symbols in the current program and prints the total.
# @category Symbol

from ghidra.app.script import GhidraScript
from ghidra.program.model.symbol import Symbol, SymbolIterator, SymbolTable

monitor.setMessage("Counting symbols...")
st = state.getCurrentProgram().getSymbolTable()
iter = st.getSymbolIterator(True)
count = 0
while iter.hasNext() and not monitor.isCancelled():
    sym = iter.next()
    if sym is not None:
        println(sym.getName())
        count += 1
println(str(count) + " symbols")
