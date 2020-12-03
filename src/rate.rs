use std::collections::{HashMap, VecDeque};
use std::convert::TryInto;
use std::time::{Duration, Instant};

pub struct Limiter {
    limit: usize,
    period: Duration,
    inner: __Limiter,
}

impl Limiter {
    pub fn new(limit: usize, period: Duration) -> Self {
        let inner = __Limiter::new();
        Self {
            limit,
            period,
            inner,
        }
    }

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

    // NOTE(ross): Using an implemntation based on a period in the context of a data bandwidth rate
    // limiter means that the highest rate this rate limiter can be configured to use is 1 Gb/s
    // (assuming a unit of a byte, it would be less if the unit was a bit). This is probably more
    // than what we would ever set it to for our use cases, but if it needs to go higher then we
    // will need to think about a frequency based implemntation, most likely using floats.
    fn allow_many(&mut self, limit: usize, period: Duration, count: usize) -> bool {
        let arrival_time = Instant::now();
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
    capacity: usize,
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
    /// NOTE: The given capacity will be used to construct the underlying data structures, but for
    /// the given APIs (specifically `std::collections::HashMap` and `std::collections::VecDeque`)
    /// the call to `with_capacity` has the possibility of generating more memory than what is
    /// needed for the requested capacity. It will however be ensured that the lengths of these
    /// data structures never exceeds the given capacity.
    pub fn new(options: Options) -> Self {
        let Options {
            capacity,
            limit,
            period,
        } = options;
        let limiters = HashMap::with_capacity(capacity);
        let chronologically_ordered_keys = VecDeque::with_capacity(capacity);
        Self {
            capacity,
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
                if self.chronologically_ordered_keys.len() == self.capacity {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limiter_rejects_too_many_cells() {
        let limit = 10;
        let period = Duration::from_secs(1000);
        let mut limiter = Limiter::new(limit, period);

        for _ in 0..limit {
            assert!(limiter.allow());
        }
        assert!(!limiter.allow());
    }

    #[test]
    fn limiter_drips_at_given_rate() {
        let limit = 10;
        let period = Duration::from_millis(1);
        let mut limiter = Limiter::new(limit, period);

        for _ in 0..limit {
            assert!(limiter.allow());
        }

        let drips = 5;
        std::thread::sleep(Duration::from_millis(drips));
        for _ in 0..drips {
            assert!(limiter.allow());
        }
        assert!(!limiter.allow());
    }

    #[test]
    fn bounded_uniform_limiter_maintains_capacity() {
        let capacity = 10;
        let options = Options {
            capacity,
            limit: 10,
            period: Duration::from_secs(1),
        };
        let mut limiter = BoundedUniformLimiterMap::new(options);
        let vec_cap = limiter.chronologically_ordered_keys.capacity();
        let map_cap = limiter.limiters.capacity();

        for i in 0..1000 {
            limiter.allow(i);
            assert_eq!(
                limiter.chronologically_ordered_keys.len(),
                limiter.limiters.len()
            );

            // The length is always bounded by the specified capacity.
            assert!(limiter.limiters.len() <= capacity);

            // The allocated memory for the `HashMap` and the `VecDeque` never changes; this
            // implies that new memory is never allocated for them.
            assert_eq!(limiter.chronologically_ordered_keys.capacity(), vec_cap);
            assert_eq!(limiter.limiters.capacity(), map_cap);
        }
    }
}
