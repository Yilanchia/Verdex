// Verdex Ghidra headless decompiler. Run via:
//   analyzeHeadless <proj_dir> <proj> -import <bin> -postScript GhidraDecompile.java <out.json> [symbol]
// Read-only: Ghidra analyzes the target, never executes it. Emits JSON
// {backend, functions:[{name, ea, pseudocode|error}]}.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.util.task.ConsoleTaskMonitor;
import java.io.FileWriter;
import java.util.ArrayList;
import java.util.List;

public class GhidraDecompile extends GhidraScript {
    private static String esc(String s) {
        if (s == null) return "";
        StringBuilder b = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '\\': b.append("\\\\"); break;
                case '"': b.append("\\\""); break;
                case '\n': b.append("\\n"); break;
                case '\r': b.append("\\r"); break;
                case '\t': b.append("\\t"); break;
                default:
                    if (c < 0x20) b.append(String.format("\\u%04x", (int) c));
                    else b.append(c);
            }
        }
        return b.toString();
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String out = args.length > 0 ? args[0] : "ghidra_out.json";
        // Symbol filter comes via env var: analyzeHeadless arg forwarding past
        // the first postScript arg is unreliable across platforms/cmd.exe.
        String target = System.getenv("VERDEX_DECOMPILE_SYMBOL");
        if (target != null && target.isEmpty()) target = null;

        DecompInterface di = new DecompInterface();
        di.openProgram(currentProgram);
        ConsoleTaskMonitor monitor = new ConsoleTaskMonitor();

        List<String> items = new ArrayList<>();
        FunctionIterator funcs = currentProgram.getFunctionManager().getFunctions(true);
        for (Function f : funcs) {
            if (f.isExternal()) continue;
            String name = f.getName();
            if (target != null && !name.equals(target)) continue;
            String ea = "0x" + f.getEntryPoint().toString(false);
            StringBuilder item = new StringBuilder();
            item.append("{\"name\":\"").append(esc(name)).append("\",\"ea\":\"").append(esc(ea)).append("\",");
            try {
                DecompileResults res = di.decompileFunction(f, 60, monitor);
                if (res != null && res.decompileCompleted()) {
                    item.append("\"pseudocode\":\"").append(esc(res.getDecompiledFunction().getC())).append("\"}");
                } else {
                    item.append("\"error\":\"decompile not completed\"}");
                }
            } catch (Exception e) {
                item.append("\"error\":\"").append(esc(e.getMessage())).append("\"}");
            }
            items.add(item.toString());
        }

        StringBuilder json = new StringBuilder();
        json.append("{\"backend\":\"ghidra\",\"functions\":[");
        for (int i = 0; i < items.size(); i++) {
            if (i > 0) json.append(",");
            json.append(items.get(i));
        }
        json.append("]}");

        try (FileWriter w = new FileWriter(out)) {
            w.write(json.toString());
        }
    }
}
