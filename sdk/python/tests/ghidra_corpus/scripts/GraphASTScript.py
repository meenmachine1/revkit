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
# Ghidra/Features/Decompiler/ghidra_scripts/GraphASTScript.java
# to Python 3, with the Ghidra API calls as they were.
##
# Decompile the function at the cursor, then build data-flow graph (AST)
# @category PCode

from ghidra.app.decompiler import DecompileOptions, DecompInterface, DecompileResults
from ghidra.app.plugin.core.decompile.actions import PCodeDfgGraphTask
from ghidra.app.script import GhidraScript
from ghidra.app.services import GraphDisplayBroker
from ghidra.framework.plugintool import PluginTool
from ghidra.program.model.listing import Function
from ghidra.program.model.pcode import HighFunction
from ghidra.util import Msg

DECOMPILE = "decompile"
NORMALIZE = "normalize"
PARAM_ID = "paramid"
REGISTER = "register"
FIRSTPASS = "firstpass"
JUMP_TABLE = "jumptable"

func = None
high = None


def createTask(graphDisplayBroker):
    return PCodeDfgGraphTask(state.getTool(), graphDisplayBroker, high)


def buildAST(style):
    global high
    options = DecompileOptions()
    ifc = DecompInterface()
    try:
        ifc.setOptions(options)
        if not ifc.openProgram(currentProgram):
            raise Exception("Decompiler: Unable to initialize: " + ifc.getLastMessage())
        ifc.setSimplificationStyle(style)
        res = ifc.decompileFunction(func, 30, None)
        high = res.getHighFunction()
    finally:
        ifc.dispose()


tool = state.getTool()
if tool is None:
    popup("Script is not running in GUI")
else:
    graphDisplayBroker = tool.getService(GraphDisplayBroker)
    if graphDisplayBroker is None:
        Msg.showError(None, tool.getToolFrame(), "GraphAST Error",
                      "No graph display providers found: Please add a graph display provider to your tool")
    else:
        func = getFunctionContaining(currentAddress)
        if func is None:
            Msg.showWarn(None, state.getTool().getToolFrame(), "GraphAST Error", "No Function at current location")
        else:
            style = askChoice("Select Simplification Style", "Select Simplification Style",
                              [DECOMPILE, FIRSTPASS, JUMP_TABLE, NORMALIZE, PARAM_ID, REGISTER], DECOMPILE)
            buildAST(style)
            astGraphTask = createTask(graphDisplayBroker)
            astGraphTask.monitoredRun(monitor)
