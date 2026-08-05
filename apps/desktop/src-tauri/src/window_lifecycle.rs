use serde::Deserialize;
use std::sync::atomic::{AtomicU8, Ordering};

const CLOSE_TO_TRAY: u8 = 0;
const QUIT_APPLICATION: u8 = 1;

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum CloseBehavior {
    Tray,
    Quit,
}

impl CloseBehavior {
    fn as_u8(self) -> u8 {
        match self {
            Self::Tray => CLOSE_TO_TRAY,
            Self::Quit => QUIT_APPLICATION,
        }
    }

    fn from_u8(value: u8) -> Self {
        match value {
            QUIT_APPLICATION => Self::Quit,
            _ => Self::Tray,
        }
    }
}

pub struct WindowLifecycleState {
    close_behavior: AtomicU8,
}

impl Default for WindowLifecycleState {
    fn default() -> Self {
        Self {
            close_behavior: AtomicU8::new(CLOSE_TO_TRAY),
        }
    }
}

impl WindowLifecycleState {
    pub fn set_close_behavior(&self, behavior: CloseBehavior) {
        self.close_behavior
            .store(behavior.as_u8(), Ordering::Release);
    }

    pub fn close_behavior(&self) -> CloseBehavior {
        CloseBehavior::from_u8(self.close_behavior.load(Ordering::Acquire))
    }
}

#[cfg(test)]
mod tests {
    use super::{CloseBehavior, WindowLifecycleState};

    #[test]
    fn close_to_tray_is_the_safe_default() {
        let state = WindowLifecycleState::default();

        assert_eq!(state.close_behavior(), CloseBehavior::Tray);
    }

    #[test]
    fn close_behavior_can_be_changed_to_quit() {
        let state = WindowLifecycleState::default();

        state.set_close_behavior(CloseBehavior::Quit);

        assert_eq!(state.close_behavior(), CloseBehavior::Quit);
    }

    #[test]
    fn close_behavior_can_be_changed_back_to_tray() {
        let state = WindowLifecycleState::default();
        state.set_close_behavior(CloseBehavior::Quit);

        state.set_close_behavior(CloseBehavior::Tray);

        assert_eq!(state.close_behavior(), CloseBehavior::Tray);
    }
}
