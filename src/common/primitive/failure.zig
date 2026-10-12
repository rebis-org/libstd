// Single shared failure type so primitives name errors without importing catalog or resources.
pub const Failure = error{
    CallFailure,
    UnsupportedFailure,
    CapacityFailure,
    DataFailure,
    IntegrityFailure,
    IoFailure,
    ResourceFailure,
    InternalFailure,
};

// Both an exhausted allocator and an exhausted output surface as capacity,
// never corrupt input: the caller retries with more workspace.
pub fn fromStd(failure: anyerror) Failure {
    return switch (failure) {
        error.OutOfMemory, error.WriteFailed => error.CapacityFailure,
        else => error.DataFailure,
    };
}
