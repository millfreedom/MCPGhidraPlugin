package ua.millfreedom.ghidra.javamcp.util;

import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

import javax.swing.SwingUtilities;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicReference;

public final class TransactionHelper {

    private static final long EDT_TIMEOUT_SECONDS = Long.getLong("ghidra.mcp.edt.timeout", 30L);
    private static final ExecutorService EDT_EXECUTOR = Executors.newCachedThreadPool();

    private TransactionHelper() {
    }

    @FunctionalInterface
    public interface GhidraSupplier<T> {
        T get() throws Exception;
    }

    public static <T> T executeInTransaction(Program program, String transactionName, GhidraSupplier<T> operation)
        throws TransactionException {
        if (program == null) {
            throw new IllegalArgumentException("Program cannot be null for transaction");
        }

        AtomicReference<T> result = new AtomicReference<>();
        AtomicReference<Exception> exception = new AtomicReference<>();

        Runnable edtTask = () -> {
            int txId = -1;
            boolean success = false;
            try {
                txId = program.startTransaction(transactionName);
                if (txId < 0) {
                    throw new TransactionException("Failed to start transaction: " + transactionName);
                }
                result.set(operation.get());
                success = true;
            } catch (Exception e) {
                exception.set(e);
                Msg.error(TransactionHelper.class, "Transaction failed: " + transactionName, e);
            } finally {
                if (txId >= 0) {
                    program.endTransaction(txId, success);
                }
            }
        };

        try {
            Future<?> future = EDT_EXECUTOR.submit(() -> {
                try {
                    SwingUtilities.invokeAndWait(edtTask);
                } catch (Exception e) {
                    exception.set(e);
                }
            });
            future.get(EDT_TIMEOUT_SECONDS, TimeUnit.SECONDS);
        } catch (TimeoutException e) {
            throw new TransactionException("EDT timeout after " + EDT_TIMEOUT_SECONDS + "s for: " + transactionName, e);
        } catch (Exception e) {
            if (exception.get() != null) {
                throw new TransactionException("Swing thread execution failed", exception.get());
            }
            throw new TransactionException("Swing thread execution failed", e);
        }

        if (exception.get() != null) {
            throw new TransactionException("Operation failed: " + exception.get().getMessage(), exception.get());
        }
        return result.get();
    }

    public static class TransactionException extends Exception {
        public TransactionException(String message) {
            super(message);
        }

        public TransactionException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
