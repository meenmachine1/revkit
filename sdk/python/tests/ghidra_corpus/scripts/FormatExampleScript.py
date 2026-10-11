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
# Ghidra/Features/Base/ghidra_scripts/FormatExampleScript.java
# to Python 3, with the Ghidra API calls as they were.
##
# <html>An example using the <code><b>printf()</b></code> method of GhidraScript
# @category Examples

import time

from ghidra.app.script import GhidraScript

# Calendar.getInstance() -> the time in milliseconds since the epoch, which
# java.util.Formatter's %t conversions take as they take a Calendar.
calendar = int(time.time() * 1000)
printf("The %s jumped over the %s\n", "cow", "moon")
printf("The %s jumped over the %s %tT\n", "cow", "moon", int(time.time() * 1000))
printf("The %s jumped over the %s - timestamp: %tc\n", "cow", "moon", int(time.time() * 1000))
printf("The %s jumped over the %s at %tl:%<tM on %3$tA, %3$tB %3$te\n", "cow", "moon", int(time.time() * 1000))
printf("Padding: %03d\n", 1)
printf("Hex: 0x%x\n", 10)
printf("Left-justified: %-10d\n", 1)
printf("Right-justified: %10d\n", 1)
printf("String fill: '%10s'\n", "Fill")
printf("String fill, left justified: '%-10s'\n", "Fill")
