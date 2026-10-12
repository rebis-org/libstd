// Single shared failure type so primitives name errors without importing catalog or resources.
pub const Failure = error{
    InvalidCall,
    Unsupported,
    InsufficientCapacity,
    InvalidData,
    IntegrityFailure,
    IoFailure,
    ResourceLimit,
    InternalFailure,
};

// A std-backed arm's own errors fold onto the flat surface, so the boundary
// sees one error set whatever provider ran.
pub fn fromStd(failure: anyerror) Failure {
    return switch (failure) {
        error.OutOfMemory => error.InsufficientCapacity,
        else => error.InvalidData,
    };
}
