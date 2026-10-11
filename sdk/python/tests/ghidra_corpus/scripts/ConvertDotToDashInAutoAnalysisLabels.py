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
# Ghidra/Features/Base/ghidra_scripts/ConvertDotToDashInAutoAnalysisLabels.java
# to Python 3, with the Ghidra API calls as they were.
##
# Converts the '.'s to '_'s in auto-analysis created CODE and FUNCTION labels (some case and switch statements)
# Use this script for updating pre3.2 files so that exported C code can compile
# Need to run the UpdateSymbolSourceScript first if the symbols have not been updated yet

from ghidra.app.script import GhidraScript
from ghidra.program.model.symbol import SourceType

st = currentProgram.getSymbolTable()
it = st.getDefinedSymbols()
while it.hasNext():
    s = it.next()
    name = s.getName()
    if s.getSource() == SourceType.ANALYSIS and (not name.startswith("u_")) and (not name.startswith("s_")):
        newName = name.replace('.', '_')
        s.setName(newName, SourceType.ANALYSIS)
