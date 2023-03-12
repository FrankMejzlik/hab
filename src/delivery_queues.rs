use std::collections::VecDeque;
//---
//---
use crate::common::VerifyResult;

pub struct DeliveryQueues {
    delivered: VecDeque<VerifyResult>,
}

impl DeliveryQueues {
    pub fn new() -> Self {
        DeliveryQueues {
            delivered: VecDeque::new(),
        }
    }
    pub fn dequeue(&mut self) -> Option<VerifyResult> {
        self.delivered.pop_front()
    }

    pub fn enqueue(&mut self, ver_res: VerifyResult) {
        //
        //
        self.delivered.push_back(ver_res)
    }
}
