use std::fmt::Display;

use crate::output;

pub trait Warn {
    fn warn(self, msg: &str);
}

impl<T: Display> Warn for T {
    fn warn(self, msg: &str) {
        output::warning(format!("{}: {}", msg, self))
    }
}
