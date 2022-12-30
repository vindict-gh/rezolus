// Copyright 2022, Valentin BRICE <dev@vbrice.fr>.
// Licensed under the Apache License, Version 2.0
// http://www.apache.org/licenses/LICENSE-2.0

use crate::metrics::*;
use serde_derive::{Deserialize, Serialize};
use strum_macros::{EnumIter, EnumString, IntoStaticStr};

#[cfg(feature = "bpf")]
use crate::common::bpf::*;

#[derive(
    Clone,
    Copy,
    Debug,
    Deserialize,
    EnumIter,
    EnumString,
    Eq,
    IntoStaticStr,
    PartialEq,
    Hash,
    Serialize,
)]
#[serde(deny_unknown_fields, try_from = "&str", into = "&str")]
#[allow(clippy::enum_variant_names)]
pub enum ZVolStatistic {
    #[strum(serialize = "zvol/read/latency")]
    ReadLatency,
    #[strum(serialize = "zvol/write/latency")]
    WriteLatency,
}

impl ZVolStatistic {
    #[allow(dead_code)]
    pub fn bpf_table(self) -> Option<&'static str> {
        match self {
            Self::ReadLatency => Some("read"),
            Self::WriteLatency => Some("write"),
        }
    }

    #[cfg(feature = "bpf")]
    pub fn bpf_probes_required(self) -> Vec<Probe> {
        // define the unique probes below.
        let zpl_read_probe = Probe {
            name: "zvol_read".to_string(),
            handler: "trace_entry".to_string(),
            probe_type: ProbeType::Kernel,
            probe_location: ProbeLocation::Entry,
            binary_path: None,
            sub_system: None,
        };
        let zpl_write_probe = Probe {
            name: "zvol_write".to_string(),
            handler: "trace_entry".to_string(),
            probe_type: ProbeType::Kernel,
            probe_location: ProbeLocation::Entry,
            binary_path: None,
            sub_system: None,
        };
        let zpl_read_ret_probe = Probe {
            name: "zvol_read".to_string(),
            handler: "trace_read_return".to_string(),
            probe_type: ProbeType::Kernel,
            probe_location: ProbeLocation::Return,
            binary_path: None,
            sub_system: None,
        };
        let zpl_write_ret_probe = Probe {
            name: "zvol_write".to_string(),
            handler: "trace_write_return".to_string(),
            probe_type: ProbeType::Kernel,
            probe_location: ProbeLocation::Return,
            binary_path: None,
            sub_system: None,
        };
        // specify what probes are required for each telemetry.
        match self {
            Self::ReadLatency => vec![zpl_read_probe, zpl_read_ret_probe],
            Self::WriteLatency => vec![zpl_write_probe, zpl_write_ret_probe],
        }
    }
}

impl Statistic for ZVolStatistic {
    fn name(&self) -> &str {
        (*self).into()
    }

    fn source(&self) -> Source {
        Source::Distribution
    }
}
