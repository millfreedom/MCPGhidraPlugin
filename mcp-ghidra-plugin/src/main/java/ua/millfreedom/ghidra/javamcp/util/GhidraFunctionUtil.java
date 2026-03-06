package ua.millfreedom.ghidra.javamcp.util;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

public final class GhidraFunctionUtil {

    private GhidraFunctionUtil() {
    }

    public static String decompileFunction(Function function, boolean showConstants, int timeoutSeconds) {
        if (function == null) {
            return null;
        }

        Program program = function.getProgram();
        DecompInterface decompiler = new DecompInterface();
        DecompileOptions options = new DecompileOptions();

        if (showConstants) {
            options.setEliminateUnreachable(true);
            options.grabFromProgram(program);
        }

        decompiler.setOptions(options);
        decompiler.openProgram(program);

        try {
            DecompileResults results = decompiler.decompileFunction(function, timeoutSeconds, TaskMonitor.DUMMY);
            if (results != null && results.decompileCompleted() && results.getDecompiledFunction() != null) {
                return results.getDecompiledFunction().getC();
            }
            return null;
        } catch (Exception e) {
            Msg.error(GhidraFunctionUtil.class, "Decompilation failed for function: " + function.getName(), e);
            return null;
        } finally {
            decompiler.dispose();
        }
    }

    public static boolean setFunctionSignature(Function function, String signatureStr) {
        return setFunctionSignature(function, signatureStr, null);
    }

    public static boolean setFunctionSignature(
        Function function,
        String signatureStr,
        String explicitCallingConvention
    ) {
        if (function == null || signatureStr == null || signatureStr.isBlank()) {
            return false;
        }

        Program program = function.getProgram();
        if (program == null) {
            return false;
        }

        try {
            ghidra.app.util.parser.FunctionSignatureParser parser =
                new ghidra.app.util.parser.FunctionSignatureParser(program.getDataTypeManager(), null);
            FunctionDefinitionDataType functionDef = parser.parse(function.getSignature(), signatureStr);
            if (functionDef == null) {
                return false;
            }

            String parsedCallingConvention = functionDef.getCallingConvention() != null
                ? functionDef.getCallingConvention().getName()
                : null;
            String callingConvention = explicitCallingConvention != null && !explicitCallingConvention.isBlank()
                ? explicitCallingConvention.trim()
                : parsedCallingConvention;
            if (callingConvention != null && !callingConvention.isBlank()) {
                if (!applyCallingConvention(function, callingConvention)) {
                    return false;
                }
            }

            SourceType sourceType = SourceType.USER_DEFINED;
            function.setReturnType(functionDef.getReturnType(), sourceType);

            while (function.getParameterCount() > 0) {
                function.removeParameter(0);
            }

            ParameterDefinition[] paramDefs = functionDef.getArguments();
            if (paramDefs != null) {
                for (ParameterDefinition paramDef : paramDefs) {
                    DataType dataType = paramDef.getDataType();
                    Parameter param = new ParameterImpl(paramDef.getName(), dataType, program);
                    function.addParameter(param, sourceType);
                }
            }

            return true;
        } catch (Exception e) {
            Msg.error(GhidraFunctionUtil.class, "Failed to set function signature", e);
            return false;
        }
    }

    public static boolean setFunctionCallingConvention(Function function, String callingConvention) {
        if (function == null || callingConvention == null || callingConvention.isBlank()) {
            return false;
        }
        return applyCallingConvention(function, callingConvention.trim());
    }

    private static boolean applyCallingConvention(Function function, String callingConvention) {
        try {
            function.setCallingConvention(callingConvention);
            return true;
        } catch (Exception e) {
            Msg.error(
                GhidraFunctionUtil.class,
                "Failed to set function calling convention: " + callingConvention,
                e
            );
            return false;
        }
    }
}
