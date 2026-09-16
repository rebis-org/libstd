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
