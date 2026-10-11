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
# docs/GhidraClass/AdvancedDevelopment/contrib/gadc/ghidra_scripts/Lab4Script.java
# to Python 3, with the Ghidra API calls as they were.
##
# Ask for an integer and print the current
# program's name that many times to the console
# @category GADC

import time

from ghidra.app.script import GhidraScript

n = askInt("How Many Times?", "N")
for i in range(n):
    if monitor.isCancelled():
        break
    println(str(i) + ". " + currentProgram.getName())
    time.sleep(1.0)  # Thread.sleep(1000)
