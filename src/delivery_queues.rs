use std::collections::BinaryHeap;
use std::collections::VecDeque;
use std::time::Duration;
use std::time::SystemTime;

use crate::common::MsgVerification;
use crate::common::SeqNum;
//---
//---
use crate::common::VerifyResult;
#[allow(unused_imports)]
use crate::{debug, error, info, trace, warn};

pub struct DeliveryQueuesParams {
    pub deadline: Duration,
}

pub struct DeliveryQueues {
    params: DeliveryQueuesParams,
	/// Min-heap holding the verified messages to be delivered.
    heap: BinaryHeap<VerifyResult>,
	/// Queue holding unverified messages to deliver (therse are not delivered in-order).
	unverified_queue: VecDeque<VerifyResult>,
    /// Next sequence number to deliver
    next_delivery_seq: SeqNum,
    /// A deadline for delivery of message that is being blocked by missing previos ones.
    next_delivery_deadline: std::time::SystemTime,
}

impl DeliveryQueues {
    pub fn new(params: DeliveryQueuesParams) -> Self {
        let heap = BinaryHeap::new();

        DeliveryQueues {
            params,
            heap,
			unverified_queue: VecDeque::new(),
            next_delivery_seq: 1,
            next_delivery_deadline: std::time::SystemTime::now(),
        }
    }
    pub fn dequeue(&mut self) -> Option<VerifyResult> {
		// The verified messages have the priority
        let top = self.heap.peek();
        if let Some(x) = top {
            // If this is the next message
            if x.metadata.seq == self.next_delivery_seq {
                // Deliver it right away
                self.next_delivery_seq += 1;
				self.next_delivery_deadline = SystemTime::now() +  self.params.deadline;
                debug!(tag: "receiver", "Delivering message {} in sequence.", x.metadata.seq);
                return self.heap.pop();
            }
            // If the next message is not the direct successor but the deadline has elapsed already
            else if SystemTime::now() >= self.next_delivery_deadline {
                // Set the next deadline
                self.next_delivery_deadline = SystemTime::now() +  self.params.deadline;
                // Set the seq
                self.next_delivery_seq = x.metadata.seq + 1;

                debug!(tag: "receiver", "Delivering message {} due to deadline.", x.metadata.seq);
                return self.heap.pop();
            }
        }

		// Deliver some low-prio messages
		self.unverified_queue.pop_front()
    }

    pub fn enqueue(&mut self, ver_res: VerifyResult) {
		match ver_res.verification {
			// Unverified messages are delivered as they come
			MsgVerification::Unverified => {
				self.unverified_queue.push_back(ver_res);
			},
			// Verified messages are delivered in-order
			_ => {
				// If the message is not yet obsolete
				if ver_res.metadata.seq >= self.next_delivery_seq {
					if self.heap.is_empty() {
						self.next_delivery_deadline = SystemTime::now() +  self.params.deadline;
					}
					self.heap.push(ver_res);
				}
			}
		}
        
    }
}
