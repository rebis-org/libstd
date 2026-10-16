// Single shared exception type so primitives name errors without importing catalog or resources.
pub const Exception = error{
    CallException,
    UnsupportedException,
    CapacityException,
    DataException,
    IntegrityException,
    IoException,
    ResourceException,
    InternalException,
};

// Both an exhausted allocator and an exhausted output surface as capacity,
// never corrupt input: the caller retries with more workspace.
pub fn fromStd(err: anyerror) Exception {
    return switch (err) {
        error.OutOfMemory, error.WriteFailed => error.CapacityException,
        else => error.DataException,
    };
}
