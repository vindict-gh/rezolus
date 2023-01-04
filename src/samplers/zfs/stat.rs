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
pub enum ZfsStatistic {
    #[strum(serialize = "zfs/read/latency")]
    ReadLatency,
    #[strum(serialize = "zfs/write/latency")]
    WriteLatency,
    #[strum(serialize = "zfs/open/latency")]
    OpenLatency,
    #[strum(serialize = "zfs/fsync/latency")]
    FsyncLatency,
}

impl ZfsStatistic {
    #[allow(dead_code)]
    pub fn bpf_table(self) -> Option<&'static str> {
        match self {
            Self::ReadLatency => Some("read"),
            Self::WriteLatency => Some("write"),
            Self::OpenLatency => Some("open"),
            Self::FsyncLatency => Some("fsync"),
        }
    }

    #[cfg(feature = "bpf")]
    pub fn bpf_probes_required(self) -> Vec<Probe> {
        // FIXME: There may be a more Rust-ic way to do this
        let mut func_prefix: Option<&str> = None;
        let mut sym: Option<String> = symbol_lookup("zpl_iter_read");
        if !sym.is_none() {
            func_prefix = Some("zpl_iter");
        }

        sym = symbol_lookup("zpl_aio_read");
        if !sym.is_none() {
            func_prefix = Some("zpl_aio");
        }

        if func_prefix.is_none() {
            func_prefix = Some("zpl")
        }

        // Define the unique probes below.
        let zpl_read_probe = Probe {
            name: format!("{}_read", func_prefix.unwrap()).to_string(),
            handler: "trace_entry".to_string(),
            probe_type: ProbeType::Kernel,
            probe_location: ProbeLocation::Entry,
            binary_path: None,
            sub_system: None,
        };
        let zpl_write_probe = Probe {
            name: format!("{}_write", func_prefix.unwrap()).to_string(),
            handler: "trace_entry".to_string(),
            probe_type: ProbeType::Kernel,
            probe_location: ProbeLocation::Entry,
            binary_path: None,
            sub_system: None,
        };
        let zpl_open_probe = Probe {
            name: "zpl_open".to_string(),
            handler: "trace_entry".to_string(),
            probe_type: ProbeType::Kernel,
            probe_location: ProbeLocation::Entry,
            binary_path: None,
            sub_system: None,
        };
        let zpl_fsync_probe = Probe {
            name: "zpl_fsync".to_string(),
            handler: "trace_entry".to_string(),
            probe_type: ProbeType::Kernel,
            probe_location: ProbeLocation::Entry,
            binary_path: None,
            sub_system: None,
        };
        let zpl_read_ret_probe = Probe {
            name: format!("{}_read", func_prefix.unwrap()).to_string(),
            handler: "trace_read_return".to_string(),
            probe_type: ProbeType::Kernel,
            probe_location: ProbeLocation::Return,
            binary_path: None,
            sub_system: None,
        };
        let zpl_write_ret_probe = Probe {
            name: format!("{}_write", func_prefix.unwrap()).to_string(),
            handler: "trace_write_return".to_string(),
            probe_type: ProbeType::Kernel,
            probe_location: ProbeLocation::Return,
            binary_path: None,
            sub_system: None,
        };
        let zpl_open_ret_probe = Probe {
            name: "zpl_open".to_string(),
            handler: "trace_open_return".to_string(),
            probe_type: ProbeType::Kernel,
            probe_location: ProbeLocation::Return,
            binary_path: None,
            sub_system: None,
        };
        let zpl_fsync_ret_probe = Probe {
            name: "zpl_fsync".to_string(),
            handler: "trace_fsync_return".to_string(),
            probe_type: ProbeType::Kernel,
            probe_location: ProbeLocation::Return,
            binary_path: None,
            sub_system: None,
        };

        // specify what probes are required for each telemetry.
        match self {
            Self::ReadLatency => vec![zpl_read_probe, zpl_read_ret_probe],
            Self::WriteLatency => vec![zpl_write_probe, zpl_write_ret_probe],
            Self::OpenLatency => vec![zpl_open_probe, zpl_open_ret_probe],
            Self::FsyncLatency => vec![zpl_fsync_probe, zpl_fsync_ret_probe],
        }
    }
}

impl Statistic for ZfsStatistic {
    fn name(&self) -> &str {
        (*self).into()
    }

    fn source(&self) -> Source {
        Source::Distribution
    }
}
