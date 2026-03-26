/// State Vector Sync implementation.
///
/// Each node maintains a state vector mapping node names to sequence numbers.
/// Nodes periodically publish their state vector as a named Interest;
/// peers that detect gaps express Interests for the missing Data.
pub struct SvsNode;
