use std::collections::{HashMap, VecDeque};
use std::convert::TryInto;
use std::time::{Duration, Instant};

pub struct Limiter {
    limit: usize,
    period: Duration,
    inner: __Limiter,
}

impl Limiter {
    pub fn allow(&mut self) -> bool {
        self.inner.allow(self.limit, self.period)
    }

    pub fn allow_many(&mut self, count: usize) -> bool {
        self.inner.allow_many(self.limit, self.period, count)
    }
}

struct __Limiter {
    current: usize,
    last_update_time: Instant,
}

impl __Limiter {
    fn new() -> Self {
        Self {
            current: 0,
            last_update_time: Instant::now(),
        }
    }

    fn allow(&mut self, limit: usize, period: Duration) -> bool {
        self.allow_many(limit, period, 1)
    }

    fn allow_many(&mut self, limit: usize, period: Duration, count: usize) -> bool {
        let arrival_time = Instant::now();

        // The number of nanoseconds that can fit in a u128 is so obscene that we do not need to be
        // worried about overflow.
        let drips_since_last_update = arrival_time
            .duration_since(self.last_update_time)
            .as_nanos()
            / period.as_nanos();

        // The number of nanoseconds that can fit in a u64 is ~585 years. We don't support the
        // possibility that the time between calls to the limiter is this big.
        let update_time_delta = Duration::from_nanos(
            (period.as_nanos() * drips_since_last_update)
                .try_into()
                .unwrap(),
        );
        self.last_update_time += update_time_delta;

        // If the u128 does not fit an a usize, then we saturate it to the max value. In this case
        // we would want the current value to become zero, and since the current value is also a
        // usize, the saturating subtraction will have the desired effect.
        let drips_since_last_update = drips_since_last_update.try_into().unwrap_or(usize::MAX);
        self.current = self.current.saturating_sub(drips_since_last_update);

        // The state has now been updated to reflect the drips, so we can check to see if we have
        // the capacity to add the new arrivals.
        match self.current.checked_add(count) {
            None => false,
            Some(new_amount) => {
                if new_amount > limit {
                    false
                } else {
                    self.current += count;
                    true
                }
            }
        }
    }
}

pub struct BoundedUniformLimiterMap<K> {
    limit: usize,
    period: Duration,
    limiters: HashMap<K, __Limiter>,
    chronologically_ordered_keys: VecDeque<K>,
}

#[derive(Debug, Clone)]
pub struct Options {
    pub capacity: usize,
    pub limit: usize,
    pub period: Duration,
}

impl<K> BoundedUniformLimiterMap<K> {
    pub fn new(options: Options) -> Self {
        let Options {
            capacity,
            limit,
            period,
        } = options;
        let limiters = HashMap::with_capacity(capacity);
        let chronologically_ordered_keys = VecDeque::with_capacity(capacity);
        Self {
            limit,
            period,
            limiters,
            chronologically_ordered_keys,
        }
    }
}

impl<K> BoundedUniformLimiterMap<K>
where
    K: Eq + std::hash::Hash + Clone,
{
    pub fn allow(&mut self, key: K) -> bool {
        self.allow_many(key, 1)
    }

    pub fn allow_many(&mut self, key: K, count: usize) -> bool {
        match self.limiters.get_mut(&key) {
            None => {
                if self.chronologically_ordered_keys.len()
                    == self.chronologically_ordered_keys.capacity()
                {
                    let old_key = self.chronologically_ordered_keys.pop_front().unwrap();
                    self.limiters.remove(&old_key);
                }
                let mut limiter = __Limiter::new();
                let allow = limiter.allow_many(self.limit, self.period, count);
                self.limiters.insert(key.clone(), limiter);
                self.chronologically_ordered_keys.push_back(key);
                allow
            }
            Some(limiter) => limiter.allow_many(self.limit, self.period, count),
        }
    }
}
