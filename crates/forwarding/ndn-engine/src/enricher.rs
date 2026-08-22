use ndn_strategy::FibEntry;
use ndn_transport::AnyMap;

/// Populates open-ended cross-layer data in the strategy context extensions.
/// `StrategyStage` calls every enricher before each strategy invocation.
///
/// Note: for known cross-layer signals (RSSI, SNR, GPS, …) prefer the typed
/// signal subsystem — implement a `SignalSource` (the trait is in
/// `ndn-signals-core`; concrete sources live with their subsystems — radio
/// metrics in the `ndn-radio-drivers` repo, extension faces in `ndn-ext`) and
/// read `ctx.signals`. Enrichers are for experimental / one-off DTOs that
/// don't fit the [`ndn_signals_core`] taxonomy.
///
/// # Adding an experimental DTO
///
/// 1. Define a DTO type.
/// 2. Implement `ContextEnricher` and call `extensions.insert(dto)`.
/// 3. Register via `EngineBuilder::context_enricher(...)`; read it with
///    `ctx.extensions.get::<Dto>()` in your strategy/filter.
#[cfg_attr(not(feature = "experimental-instrument"), doc(hidden))]
pub trait ContextEnricher: Send + Sync + 'static {
    fn name(&self) -> &str;

    fn enrich(&self, fib_entry: Option<&FibEntry>, extensions: &mut AnyMap);
}
