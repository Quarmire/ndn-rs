use ndn_strategy::FibEntry;
use ndn_transport::AnyMap;

/// Populates cross-layer data in the strategy context extensions.
/// Implementations pull from their data source (RadioTable, GPS, battery, …)
/// and insert a DTO into the `AnyMap`. `StrategyStage` calls every enricher
/// before each strategy invocation.
///
/// # Adding a new data source
///
/// 1. Define a DTO in `ndn-strategy::cross_layer`.
/// 2. Implement `ContextEnricher` and call `extensions.insert(dto)`.
/// 3. Register via `EngineBuilder::context_enricher(...)`.
#[cfg_attr(not(feature = "experimental-instrument"), doc(hidden))]
pub trait ContextEnricher: Send + Sync + 'static {
    fn name(&self) -> &str;

    fn enrich(&self, fib_entry: Option<&FibEntry>, extensions: &mut AnyMap);
}
