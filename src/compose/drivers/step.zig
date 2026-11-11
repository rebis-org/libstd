const exception_prim = @import("../../common/primitive/exception.zig");
const sessions = @import("../sessions.zig");

const Exception = exception_prim.Exception;
const StepResult = sessions.StepResult;

pub fn framingFailed(result: *StepResult, consumed: usize, exception: Exception) StepResult {
    result.consumed = consumed;
    result.status = .failed;
    result.exception = exception;
    return result.*;
}

pub fn encodeFailed(result: *StepResult, exception: Exception) StepResult {
    result.status = .failed;
    result.exception = exception;
    return result.*;
}
