// Copyright 2022 Valentin BRICE <dev@vbrice.fr>
// Licensed under the Apache License, Version 2.0
// http://www.apache.org/licenses/LICENSE-2.0

#[cfg(feature = "bpf")]
use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;

use crate::common::bpf::*;
use crate::config::SamplerConfig;
use crate::samplers::Common;
use crate::Sampler;
use crate::*;

mod config;
mod stat;

pub use config::*;
pub use stat::*;

#[cfg(feature = "bpf")]
pub fn zvol_map_from_table(table: &mut bcc::table::Table)
    -> std::collections::HashMap<String, std::collections::HashMap<u64, u32>> {
    use std::collections::HashMap;

    let mut current = HashMap::new();

    trace!("transferring data to userspace");
    for (id, mut entry) in table.iter().enumerate() {
        let mut key = [0; 264];
        let mut ds_name = vec![0; 256];
        let mut slot_key = [0; 8];

        if key.len() != entry.key.len() {
            // log and skip processing if the key length is unexpected
            debug!(
                "unexpected length of the entry's key, entry id: {} key length: {} (expected {})",
                id,
                entry.key.len(),
                key.len() + ds_name.len()
            );
            continue;
        }
        key.copy_from_slice(&entry.key);

        ds_name.copy_from_slice(&entry.key[..256]);
        slot_key.copy_from_slice(&entry.key[256..]);

        let slot_key = u64::from_ne_bytes(slot_key);
        let nul_range_end = ds_name.iter().position(|&c| c == b'\0').unwrap_or(ds_name.len());
        let ds_name_res = String::from_utf8((&ds_name[0..nul_range_end]).to_vec());
        if !ds_name_res.is_ok() {
            debug!("invalid ds_name found");
            continue;
        }
        let ds_name_str = ds_name_res.unwrap();
        let mut value = [0; 8];
        if value.len() != entry.value.len() {
            // log and skip processing if the value length is unexpected
            debug!(
                "unexpected length of the entry's value, entry id: {} value length: {}",
                id,
                entry.value.len()
            );
            continue;
        }
        value.copy_from_slice(&entry.value);
        let value = u64::from_ne_bytes(value);

        debug!("Found for {} : index {} = count {}", ds_name_str, slot_key, value);

        if !current.contains_key(&ds_name_str) {
            let mut current_inner = HashMap::new();
            if let Some(slot_key) = key_to_value(slot_key as u64) {
                current_inner.insert(slot_key, value as u32);
            }
            current.insert(ds_name_str, current_inner);
        } else {
            if let Some(slot_key) = key_to_value(slot_key as u64) {
                let inner = current.get_mut(&ds_name_str).unwrap();
                inner.insert(slot_key, value as u32);
            }
        }
        
        // clear the source counter
        let _ = table.set(&mut entry.key, &mut [0_u8; 8]);
    }
    current
}

#[allow(dead_code)]
pub struct ZVol {
    bpf: Option<Arc<Mutex<BPF>>>,
    bpf_last: Arc<Mutex<Instant>>,
    common: Common,
    statistics: Vec<ZVolStatistic>,
}

#[async_trait]
impl Sampler for ZVol {
    type Statistic = ZVolStatistic;
    fn new(common: Common) -> Result<Self, anyhow::Error> {
        let fault_tolerant = common.config.general().fault_tolerant();
        let statistics = common.config().samplers().zvol().statistics();

        #[allow(unused_mut)]
        let mut sampler = Self {
            bpf: None,
            bpf_last: Arc::new(Mutex::new(Instant::now())),
            common,
            statistics,
        };

        if let Err(e) = sampler.initialize_bpf() {
            error!("failed to initialize bpf: {}", e);
            if !fault_tolerant {
                return Err(e);
            }
        }

        if sampler.sampler_config().enabled() {
            sampler.register();
        }

        Ok(sampler)
    }

    fn spawn(common: Common) {
        if common.config().samplers().zvol().enabled() {
            if let Ok(mut sampler) = Self::new(common.clone()) {
                common.runtime().spawn(async move {
                    loop {
                        let _ = sampler.sample().await;
                    }
                });
            } else if !common.config.fault_tolerant() {
                fatal!("failed to initialize zvol sampler");
            } else {
                error!("failed to initialize zvol sampler");
            }
        }
    }

    fn common(&self) -> &Common {
        &self.common
    }

    fn common_mut(&mut self) -> &mut Common {
        &mut self.common
    }

    fn sampler_config(&self) -> &dyn SamplerConfig<Statistic = Self::Statistic> {
        self.common.config().samplers().zvol()
    }

    async fn sample(&mut self) -> Result<(), std::io::Error> {
        if let Some(ref mut delay) = self.delay() {
            delay.tick().await;
        }

        if !self.sampler_config().enabled() {
            return Ok(());
        }

        debug!("sampling");

        // sample bpf
        #[cfg(feature = "bpf")]
        self.map_result(self.sample_bpf())?;

        Ok(())
    }
}

impl ZVol {
    // checks that bpf is enabled in config and one or more bpf stats enabled
    #[cfg(feature = "bpf")]
    fn bpf_enabled(&self) -> bool {
        if self.sampler_config().bpf() {
            for statistic in &self.statistics {
                if statistic.bpf_table().is_some() {
                    return true;
                }
            }
        }
        false
    }

    fn initialize_bpf(&mut self) -> Result<(), anyhow::Error> {
        #[cfg(feature = "bpf")]
        {
            if self.enabled() && self.bpf_enabled() {
                debug!("initializing bpf");

                // load the code and compile
                let code = include_str!("bpf.c");
                let code = code.replace(
                    "VALUE_TO_INDEX2_FUNC",
                    include_str!("../../common/value_to_index2.c"),
                );
                let mut bpf = bcc::BPF::new(&code)?;

                // collect the set of probes required from the statistics enabled.
                let mut probes = HashSet::new();
                for statistic in &self.statistics {
                    for probe in statistic.bpf_probes_required() {
                        probes.insert(probe);
                    }
                }

                // load + attach the kernel probes that are required to the bpf instance.
                for probe in probes {
                    if self.common.config.fault_tolerant() {
                        if let Err(e) = probe.try_attach_to_bpf(&mut bpf) {
                            warn!("skipping {} with error: {}", probe.name, e);
                        }
                    } else {
                        probe.try_attach_to_bpf(&mut bpf)?;
                    }
                }

                self.bpf = Some(Arc::new(Mutex::new(BPF { inner: bpf })));
            }
        }

        Ok(())
    }

    #[cfg(feature = "bpf")]
    fn register_zvolstatistic(&self, zvolstatistic: &ZVolCustomStatistic) {
        let zvol_reading = self.common().metrics().reading(zvolstatistic);
        if zvol_reading.is_err() {
            debug!("registering statistic {}", zvolstatistic.name());
            self.common()
                .metrics()
                .add_output(zvolstatistic, Output::Reading);
            let percentiles = self.sampler_config().percentiles();
            if !percentiles.is_empty() {
                if zvolstatistic.source() == Source::Distribution {
                    self.common().metrics().add_summary(
                        zvolstatistic,
                        Summary::heatmap(
                            1_000_000_000,
                            2,
                            Duration::from_secs(
                                self.common()
                                    .config()
                                    .general()
                                    .window()
                                    .try_into()
                                    .unwrap(),
                            ),
                            Duration::from_secs(1),
                        ),
                    );
                } else {
                    self.common()
                        .metrics()
                        .add_summary(zvolstatistic, Summary::stream(self.samples()));
                }
            }
            for percentile in percentiles {
                self.common()
                    .metrics()
                    .add_output(zvolstatistic, Output::Percentile(*percentile));
            }
        }
    }

    #[cfg(feature = "bpf")]
    fn sample_bpf(&self) -> Result<(), std::io::Error> {
        if self.bpf_last.lock().unwrap().elapsed()
            >= Duration::from_secs(self.general_config().window() as u64)
        {
            if let Some(ref bpf) = self.bpf {
                let bpf = bpf.lock().unwrap();
                let time = Instant::now();
                for statistic in self.statistics.iter().filter(|s| s.bpf_table().is_some()) {
                    if let Ok(mut table) = (*bpf).inner.table(statistic.bpf_table().unwrap()) {
                        for (zvol_name, inner_map) in zvol_map_from_table(&mut table) {
                            // in order to stay in current rezolus workflow and automation
                            // we need to modify statistic so that the name() function
                            // return the zvol_name prefixed with the statistic actual name
                            let custom_statistic = ZVolCustomStatistic {
                                full_name: format!("{}/{}", statistic.name(), zvol_name),
                            };

                            // we need to register the statistics on the fly,
                            // this is because we generate per zvol statistics
                            self.register_zvolstatistic(&custom_statistic);

                            for (&value, &count) in &inner_map {
                                debug!("Got for {}: {} for {} micsecs", custom_statistic.name(), count, value);
                                if count > 0 {
                                    let _ = self.metrics().record_bucket(
                                        &custom_statistic,
                                        time,
                                        value * crate::MICROSECOND,
                                        count,
                                    );
                                }
                            }
                        }
                    }
                }
            }
            *self.bpf_last.lock().unwrap() = Instant::now();
        }
        Ok(())
    }
}
