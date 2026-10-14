import ghidra.app.script.GhidraScript;

public class DisableObjcMessageAnalyzer extends GhidraScript {
    @Override
    public void run() throws Exception {
        setAnalysisOption(
            currentProgram,
            "Objective-C Message Analyzer",
            "false"
        );

        setAnalysisOption(
            currentProgram,
            "Objective-C Type Metadata Analyzer",
            "false"
        );

        println("Disabled Objective-C Message Analyzer");
        println("Disabled Objective-C Type Metadata Analyzer");
    }
}
