import ghidra.app.script.GhidraScript;

/**
 * Runs before Ghidra auto-analysis. These Objective-C analyzers can be very
 * expensive on large stripped iOS application binaries. The remaining analysis
 * still discovers generic functions, instructions, strings and references.
 */
public class DisableObjcAnalyzers extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] options = {
            "Objective-C Message Analyzer",
            "Objective-C Type Metadata Analyzer"
        };
        for (String option : options) {
            try {
                setAnalysisOption(currentProgram, option, "false");
                println("Disabled pre-analysis option: " + option);
            } catch (Exception exception) {
                // Option names can vary slightly between Ghidra releases.
                // Keep the run going and preserve a diagnostic in headless output.
                println("Could not disable option '" + option + "': " + exception.getMessage());
            }
        }
    }
}
