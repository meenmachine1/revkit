// analyzeHeadless post-script for scripts/ghidra-headless-timing.py: after
// auto-analysis, decompiles every function as tools/ghidra-export does
// (DecompileOptions.grabFromProgram, simplification style "decompile") and
// records how long that took.
//@category revkit

import java.io.FileWriter;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;

public class RevkitTimingPost extends GhidraScript {
	@Override
	public void run() throws Exception {
		String stats = getScriptArgs().length > 0 ? getScriptArgs()[0] : null;
		long start = System.currentTimeMillis();
		DecompileOptions options = new DecompileOptions();
		options.grabFromProgram(currentProgram);
		DecompInterface ifc = new DecompInterface();
		ifc.setOptions(options);
		ifc.toggleCCode(true);
		ifc.toggleSyntaxTree(true);
		ifc.setSimplificationStyle("decompile");
		if (!ifc.openProgram(currentProgram)) {
			throw new Exception("decompiler failed to open program: " + ifc.getLastMessage());
		}
		int functions = 0;
		int decompiled = 0;
		try {
			for (Function f : currentProgram.getListing().getFunctions(true)) {
				functions++;
				DecompileResults r = ifc.decompileFunction(f, 120, monitor);
				if (r != null && r.getDecompiledFunction() != null) {
					decompiled++;
				}
			}
		}
		finally {
			ifc.dispose();
		}
		long end = System.currentTimeMillis();
		if (stats != null) {
			try (FileWriter w = new FileWriter(stats, true)) {
				w.write(String.format(
					"{\"program\":\"%s\",\"decompile_start_ms\":%d,\"decompile_end_ms\":%d,\"functions\":%d,\"decompiled\":%d}%n",
					currentProgram.getExecutablePath(), start, end, functions, decompiled));
			}
		}
	}
}
