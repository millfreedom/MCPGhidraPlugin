package ua.millfreedom.ghidra.javamcp.util;

import generic.jar.ResourceFile;
import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraScriptProvider;
import ghidra.app.script.GhidraState;
import ghidra.app.script.ScriptControls;
import ghidra.app.script.ScriptInfo;
import ghidra.framework.options.Options;
import ghidra.framework.model.Project;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class GhidraScriptRunner {

    private GhidraScriptRunner() {
    }

    public record Result(
        String requestedName,
        String resolvedName,
        String sourcePath,
        String runtime,
        String description,
        List<String> scriptArgs,
        Map<String, Map<String, String>> appliedProgramOptions,
        String stdout,
        String stderr
    ) {
    }

    public static Result runScript(
        PluginTool tool,
        Program program,
        String requestedName,
        List<String> scriptArgs,
        Map<String, Map<String, String>> programOptions
    ) throws Exception {
        ghidra.app.script.GhidraScriptUtil.acquireBundleHostReference();
        try {
            ResourceFile sourceFile = ghidra.app.script.GhidraScriptUtil.findScriptByName(requestedName);
            if (sourceFile == null || !sourceFile.exists()) {
                throw new IllegalArgumentException("Script not found: " + requestedName);
            }

            GhidraScriptProvider provider = ghidra.app.script.GhidraScriptUtil.getProvider(sourceFile);
            if (provider == null) {
                throw new IllegalArgumentException("Unsupported Ghidra script type: " + sourceFile.getName());
            }

            StringWriter stdoutBuffer = new StringWriter();
            StringWriter stderrBuffer = new StringWriter();
            PrintWriter stdoutWriter = new PrintWriter(stdoutBuffer, true);
            PrintWriter stderrWriter = new PrintWriter(stderrBuffer, true);

            GhidraScript script;
            try {
                script = provider.getScriptInstance(sourceFile, stdoutWriter);
                if (script == null) {
                    throw new IllegalStateException("Failed to load script: " + sourceFile.getName());
                }

                applyProgramOptions(program, sourceFile.getName(), programOptions);

                Project project = tool != null ? tool.getProject() : null;
                GhidraState state = new GhidraState(tool, project, program, null, null, null);
                ScriptControls controls = new ScriptControls(stdoutWriter, stderrWriter, TaskMonitor.DUMMY);
                script.setScriptArgs(scriptArgs.toArray(String[]::new));
                script.execute(state, controls);
            } catch (Exception e) {
                stdoutWriter.flush();
                stderrWriter.flush();
                throw new ScriptExecutionException(
                    requestedName,
                    sourceFile.getName(),
                    sourceFile.getAbsolutePath(),
                    stdoutBuffer.toString(),
                    stderrBuffer.toString(),
                    e
                );
            }

            stdoutWriter.flush();
            stderrWriter.flush();

            ScriptInfo info = ghidra.app.script.GhidraScriptUtil.newScriptInfo(sourceFile);
            return new Result(
                requestedName,
                sourceFile.getName(),
                sourceFile.getAbsolutePath(),
                provider.getRuntimeEnvironmentName(),
                info != null ? info.getDescription() : null,
                List.copyOf(scriptArgs),
                copyProgramOptions(programOptions),
                stdoutBuffer.toString(),
                stderrBuffer.toString()
            );
        } finally {
            ghidra.app.script.GhidraScriptUtil.releaseBundleHostReference();
        }
    }

    private static void applyProgramOptions(
        Program program,
        String scriptName,
        Map<String, Map<String, String>> programOptions
    ) throws TransactionHelper.TransactionException {
        if (programOptions == null || programOptions.isEmpty()) {
            return;
        }

        TransactionHelper.executeInTransaction(program, "Set script options for " + scriptName, () -> {
            for (Map.Entry<String, Map<String, String>> pageEntry : programOptions.entrySet()) {
                Options opts = program.getOptions(pageEntry.getKey());
                for (Map.Entry<String, String> optionEntry : pageEntry.getValue().entrySet()) {
                    opts.setString(optionEntry.getKey(), optionEntry.getValue());
                }
            }
            return Boolean.TRUE;
        });
    }

    private static Map<String, Map<String, String>> copyProgramOptions(Map<String, Map<String, String>> programOptions) {
        LinkedHashMap<String, Map<String, String>> copy = new LinkedHashMap<>();
        if (programOptions == null) {
            return copy;
        }

        for (Map.Entry<String, Map<String, String>> entry : programOptions.entrySet()) {
            copy.put(entry.getKey(), new LinkedHashMap<>(entry.getValue()));
        }
        return copy;
    }

    public static final class ScriptExecutionException extends Exception {

        private final String requestedName;
        private final String resolvedName;
        private final String sourcePath;
        private final String stdout;
        private final String stderr;

        public ScriptExecutionException(
            String requestedName,
            String resolvedName,
            String sourcePath,
            String stdout,
            String stderr,
            Throwable cause
        ) {
            super(cause != null ? cause.getMessage() : "Script execution failed", cause);
            this.requestedName = requestedName;
            this.resolvedName = resolvedName;
            this.sourcePath = sourcePath;
            this.stdout = stdout;
            this.stderr = stderr;
        }

        public String getRequestedName() {
            return requestedName;
        }

        public String getResolvedName() {
            return resolvedName;
        }

        public String getSourcePath() {
            return sourcePath;
        }

        public String getStdout() {
            return stdout;
        }

        public String getStderr() {
            return stderr;
        }
    }
}
