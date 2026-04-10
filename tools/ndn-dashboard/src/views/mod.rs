pub mod config;
pub mod onboarding;
pub mod cs;
pub mod faces;
pub mod fleet;
pub mod logs;
pub mod overview;
pub mod radio;
pub mod routes;
pub mod security;
pub mod session;
pub mod strategy;
pub mod traffic;
pub mod tools;
pub mod modals;
pub mod dashboard_config;

/// Which panel is currently visible in the content area.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum View {
    Overview,
    Strategy,
    Logs,
    Session,
    Security,
    Fleet,
    Radio,
    Tools,
    DashboardConfig,
    RouterConfig,
}

impl View {
    pub fn label(self) -> &'static str {
        match self {
            View::Overview        => "Overview",
            View::Strategy        => "Strategy",
            View::Logs            => "Logs",
            View::Session         => "Session",
            View::Security        => "Security",
            View::Fleet           => "Fleet",
            View::Radio           => "Radio",
            View::Tools           => "Tools",
            View::DashboardConfig => "Dashboard Config",
            View::RouterConfig    => "Router Config",
        }
    }

    pub const NAV: &'static [View] = &[
        View::Overview,
        View::Strategy,
        View::Logs,
        View::Session,
        View::Security,
        View::Fleet,
        View::Radio,
        View::Tools,
    ];
}
