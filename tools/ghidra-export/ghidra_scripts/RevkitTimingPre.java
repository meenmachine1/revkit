// analyzeHeadless pre-script for scripts/ghidra-headless-timing.py: records
// when analysis starts and, like tools/ghidra-export, points the PDB analyzer
// at a .pdb beside a PE file.
//@category revkit

import java.io.File;
import java.io.FileWriter;

import ghidra.app.plugin.core.analysis.PdbUniversalAnalyzer;
import ghidra.app.script.GhidraScript;

public class RevkitTimingPre extends GhidraScript {
	@Override
	public void run() throws Exception {
		String stats = getScriptArgs().length > 0 ? getScriptArgs()[0] : null;
		String exe = currentProgram.getExecutablePath();
		if (exe != null) {
			exe = new File(exe).getCanonicalPath();  // the corpus file behind an import symlink
		}
		if (exe != null && exe.toLowerCase().endsWith(".exe")) {
			File pdb = new File(exe.substring(0, exe.length() - 4) + ".pdb");
			if (pdb.isFile()) {
				PdbUniversalAnalyzer.setPdbFileOption(currentProgram, pdb);
			}
		}
		if (stats != null) {
			try (FileWriter w = new FileWriter(stats, true)) {
				w.write(String.format("{\"program\":\"%s\",\"analysis_start_ms\":%d}%n", exe,
					System.currentTimeMillis()));
			}
		}
	}
}
