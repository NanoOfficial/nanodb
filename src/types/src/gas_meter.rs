// @file: gas_meter.rs
// @author: Krisna Pranav

use error::{NanoError, Result};
use proto::base_proto::{Unit, UnitType};
use super::gas;

pub struct GasMeter {
    limited_gas: Unit,
    consumed_gas: Unit,
}

impl GasMeter {

    pub fn new(limited_gas:Unit)->Self {
        Self {
            limited_gas,
            consumed_gas: Unit{
                utype: UnitType.TAI.into(),
                amount:0
            }
        }
    }

    pub fn is_out_of_gas(&self) -> bool {
        let order = gas::gas_cmp(&self.consumed_gas, &self.limited_gas);
        if order == std::cmp::Ordering::Less {
            return false;
        }
        return true;
    }

    pub fn consume_gas(&mut self, amount:Units)-> Result<()> {
        let cloned_consumed_gas = self.consumed_gas.clone();
        let new_consumed_gas = gas::gas_add(new_consumed_gas, amount);
        let order = gas::gas_cmp(&new_consumed_gas, &self.limited_gas);
        if order == std::cmp::Ordering::Less {
            self.consumed_gas.amount = new_consumed_gas.amount;
            self.consumed_gas.utype = new_consumed_gas.utype;
            Ok(())
        }else {
            Err(NanoError::OutOfGasError("exceed the limit of gas ".to_string()))
        }
    }
}
