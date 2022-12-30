// Copyright 2022 Valentin BRICE <dev@vbrice.fr>
// Licensed under the Apache License, Version 2.0
// http://www.apache.org/licenses/LICENSE-2.0

use serde_derive::Deserialize;
use strum::IntoEnumIterator;

use crate::config::SamplerConfig;

use super::stat::*;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ZfsConfig {
    #[serde(default)]
    bpf: bool,
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    interval: Option<usize>,
    #[serde(default = "crate::common::default_percentiles")]
    percentiles: Vec<f64>,
    #[serde(default = "default_statistics")]
    statistics: Vec<ZfsStatistic>,
}

impl Default for ZfsConfig {
    fn default() -> Self {
        Self {
            bpf: Default::default(),
            enabled: Default::default(),
            interval: Default::default(),
            percentiles: crate::common::default_percentiles(),
            statistics: default_statistics(),
        }
    }
}

fn default_statistics() -> Vec<ZfsStatistic> {
    ZfsStatistic::iter().collect()
}

impl SamplerConfig for ZfsConfig {
    type Statistic = ZfsConfig;

    fn bpf(&self) -> bool {
        self.bpf
    }

    fn enabled(&self) -> bool {
        self.enabled
    }

    fn interval(&self) -> Option<usize> {
        self.interval
    }

    fn percentiles(&self) -> &[f64] {
        &self.percentiles
    }

    fn statistics(&self) -> Vec<<Self as SamplerConfig>::Statistic> {
        let mut enabled = Vec::new();
        for statistic in self.statistics.iter() {
            if statistic.bpf_table().is_some() {
                if self.bpf() {
                    enabled.push(*statistic);
                }
            } else {
                enabled.push(*statistic);
            }
        }
        enabled
    }
}
