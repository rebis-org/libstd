// Single shared failure type so primitives name errors without importing catalog or resources.
pub const Failure = error{
    InvalidCall,
    Unsupported,
    InsufficientCapacity,
    InvalidData,
    IntegrityFailure,
    IoFailure,
    // The reader had no bytes ready at a suspension-safe boundary. Only the
    // resumable read path raises it; the classic readByte maps it back to
    // IoFailure so existing callers keep one flat failure surface.
    Starved,
    ResourceLimit,
    InternalFailure,
};
