/// Service registry backed by the NDN namespace.
///
/// Services advertise under `/local/services/<name>/info` (capabilities)
/// and `/local/services/<name>/alive` (heartbeat with short FreshnessPeriod).
/// Discovery is a CanBePrefix Interest for `/local/services`.
pub struct ServiceRegistry;
