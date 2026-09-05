// The ABI status vocabulary is the one shared failure type for the protocol,
// the resource runtime, and the primitive layer, so primitives do not import
// the catalog or the resource runtime just to name an error.
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
