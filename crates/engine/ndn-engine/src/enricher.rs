use ndn_strategy::FibEntry;
use ndn_transport::AnyMap;

/// Populates cross-layer data in the strategy context extensions.
///
/// Implementations pull from whatever data source they own (RadioTable,
/// FlowTable, GPS receiver, battery monitor, ...) and insert a DTO into
/// the `AnyMap`.  `StrategyStage` holds a `Vec<Arc<dyn ContextEnricher>>`
/// and calls each one before every strategy invocation.
///
/// # Adding a new data source
///
/// 1. Define a DTO struct (e.g. `LocationSnapshot`) in `ndn-strategy::cross_layer`.
/// 2. Implement `ContextEnricher` — read your data source, build the DTO,
///    call `extensions.insert(dto)`.
/// 3. Register via `EngineBuilder::context_enricher(Arc::new(YourEnricher { ... }))`.
///
/// No changes to `StrategyContext`, `StrategyStage`, or existing enrichers are needed.
pub trait ContextEnricher: Send + Sync + 'static {
    fn name(&self) -> &str;

    fn enrich(&self, fib_entry: Option<&FibEntry>, extensions: &mut AnyMap);
}
