use chrono::{NaiveDateTime, Utc};

pub trait Clock {
    fn now(&self) -> NaiveDateTime;
}

pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> NaiveDateTime {
        Utc::now().naive_utc()
    }
}
