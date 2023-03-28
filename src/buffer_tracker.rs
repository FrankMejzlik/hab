#[derive(Clone, Copy, Debug)]
struct Interval {
    start: usize,
    end: usize,
    last: bool,
}
#[derive(Debug, Clone)]
pub struct BufferTracker {
    received_intervals: Vec<Interval>,
}

impl BufferTracker {
    pub fn new() -> Self {
        Self {
            received_intervals: vec![],
        }
    }

    pub fn mark_received(&mut self, from_offset: usize, to_offset: usize, more: bool) -> bool {
        let mut new_interval = Interval {
            start: from_offset,
            end: to_offset,
            last: !more,
        };

        let mut new_receiverd_intervals = vec![];

        // If there are no intervals, add the new one
        if self.received_intervals.is_empty() {
            self.received_intervals.push(new_interval);
        }

        // If intervals do not overlap
        for interval in self.received_intervals.iter() {
            if interval.end < new_interval.start || interval.start > new_interval.end {
                new_receiverd_intervals.push(*interval);
            }
            // If they overlap, merge them
            else {
                new_interval.start = std::cmp::min(interval.start, new_interval.start);
                new_interval.end = std::cmp::max(interval.end, new_interval.end);
				new_interval.last = new_interval.last || interval.last;
            }
        }
        new_receiverd_intervals.push(new_interval);

        self.received_intervals = new_receiverd_intervals;

        if self.is_whole_received() {
            true
        } else {
            false
        }
    }

    fn is_whole_received(&self) -> bool {
        // There must be only one interval left
        if self.received_intervals.len() != 1 {
            return false;
        }

        let single_interval = self.received_intervals[0];

        // It must start from 0
        if single_interval.start != 0 {
            return false;
        }

        // And must also contain the last fragment
        return single_interval.last;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty() {
        let bt = BufferTracker::new();
        assert_eq!(bt.is_whole_received(), false);
    }

    #[test]
    fn test_single_fragment_buffer() {
        let mut bt = BufferTracker::new();
        assert_eq!(bt.mark_received(0, 1, false), true);
    }

    #[test]
    fn test_multiple_fragment_buffer_out_of_order_insert() {
        let mut bt = BufferTracker::new();
        assert_eq!(bt.mark_received(3, 4, true), false);
        assert_eq!(bt.mark_received(4, 5, false), false);
        assert_eq!(bt.mark_received(0, 1, true), false);
        assert_eq!(bt.mark_received(1, 2, true), false);
        assert_eq!(bt.mark_received(2, 3, true), true);
    }
}
