// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    cli::SubCommand,
    command::CommandError,
    context::ContextCache,
    device::{self, Device},
};
use argh::FromArgs;
use std::{cell::RefCell, rc::Rc};
use strum::{Display, EnumString};
use tabled::Tabled;

#[derive(Debug, Clone, Copy, PartialEq, Eq, EnumString, Display)]
#[strum(serialize_all = "kebab-case")]
pub enum AlgorithmType {
    Key,
    Name,
}

#[derive(Tabled)]
struct AlgorithmRow {
    #[tabled(rename = "ALGORITHM")]
    algorithm: String,
    #[tabled(rename = "TYPE")]
    algorithm_type: String,
}

/// Lists available algorithms supported by the chip.
#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "algorithm")]
pub struct Algorithm {
    /// algorithm type: 'key' or 'name'
    #[argh(option, long = "type")]
    pub algorithm_type: Option<AlgorithmType>,
}

impl SubCommand for Algorithm {
    fn run(
        &self,
        device: Option<Rc<RefCell<Device>>>,
        context: &mut ContextCache,
        plain: bool,
    ) -> Result<(), CommandError> {
        device::with_device::<_, _, CommandError>(device, |device| {
            let mut results: Vec<(String, AlgorithmType)> = Vec::new();

            if self.algorithm_type.is_none() || self.algorithm_type == Some(AlgorithmType::Key) {
                results.extend(
                    device
                        .get_all_algorithms()?
                        .into_iter()
                        .map(|(_, name)| (name, AlgorithmType::Key)),
                );
            }

            if self.algorithm_type.is_none() || self.algorithm_type == Some(AlgorithmType::Name) {
                results.extend(
                    device
                        .get_all_hashes()?
                        .into_iter()
                        .map(|name| (name, AlgorithmType::Name)),
                );
            }

            results.sort_by(|a, b| a.0.cmp(&b.0));

            let rows: Vec<AlgorithmRow> = results
                .into_iter()
                .map(|(algorithm, algorithm_type)| AlgorithmRow {
                    algorithm,
                    algorithm_type: algorithm_type.to_string(),
                })
                .collect();
            super::print_table(&mut context.writer, rows, plain)?;
            Ok(())
        })
    }
}
