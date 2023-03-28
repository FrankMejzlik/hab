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

        // If intervals do not overlap
        for interval in self.received_intervals.iter() {
            if interval.end < new_interval.start || interval.start > new_interval.end {
                new_receiverd_intervals.push(*interval);
            }
            // If they overlap, merge them
            else {
                new_interval.start = std::cmp::min(interval.start, new_interval.start);
                new_interval.end = std::cmp::max(interval.end, new_interval.end);
                new_receiverd_intervals.push(new_interval);
            }
        }

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
    fn test_empty() {}

    #[test]
    fn test_single_fragment_buffer() {}

    #[test]
    fn test_multiple_fragment_buffer_out_of_order_insert() {}
}
