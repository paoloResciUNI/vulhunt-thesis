use std::collections::BTreeSet;
use std::hash::Hash;
use std::ops::{Add, Deref};
use std::sync::Arc;
use std::path::{Path, PathBuf};
use fugue::ir::disassembly::Opcode::New;
use goblin::pe::PE;

use ahash::AHashMap;
use compact_str::ToCompactString;
use fugue::ir::Address;
// use fugue::sleigh::CodeBlock;
use serde::{Deserialize, Serialize};
use ustr::{Ustr, UstrSet};
use yaxpeax_arm::armv7::ConditionCode::LO;

use crate::analyses::strings::StringsXRefDB;
use crate::cfg::block::BlockInfo;
use crate::cfg::icfg;
use crate::cfg::insn::InsnInfo;
use crate::cfg::non_returning::{
    NonReturningFunctions, NonReturningPropagator, PropagatedNonReturning,
};
use crate::cio::Arg;
// use crate::eval::Configuration;
use crate::inject::ExternalFunction;
use crate::ir::Insn;
use crate::kb::block::{CodeBlock, CodeBlockId, EmptyCodeBlock};
use crate::kb::function::Function;
use crate::kb::id::Identifiable;
use crate::kb::{ustr, uuid, Lazy, Uuid};



use crate::bias_core::loader::pe::IMPORT_FUNCS;  // importing the <address - name> vector

use crate::loader::{self, LoadedBinary};
use crate::loader::pe::LoadedPE;
use crate::prelude::FunctionId;
use crate::project::analysis::{Analysis, AnalysisError, AnalysisInfo, AnalysisSchedule};
use crate::region::Region;
use crate::{PELoader, Project, ProjectConfig};


#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct TestAnalysis {}

impl TestAnalysis {
    pub fn new() -> Self {
        Self::default()
    }
}

impl AnalysisInfo for TestAnalysis {
    const NAME: &'static str = "Test analysis";
    const UUID: Uuid = uuid("C0139FE1-4B18-4724-BA01-4ADA868B6B84");
    const DEPENDENCIES: &'static [AnalysisSchedule] = &[];
}

impl Analysis for TestAnalysis {
    fn id(&self) -> &Uuid {
        &Self::UUID
    }

    fn dependencies(&self) -> &[AnalysisSchedule] {
        Self::DEPENDENCIES
    }

    fn analyse(&mut self, project: &mut Project) -> Result<(), AnalysisError> {
        println!("Test analysis");  
   
        let imported = IMPORT_FUNCS.get().unwrap();

        let mut new_address: u64 =  0x8000000000;
        for (_address, _name) in  imported {
            let func_name: Ustr = _name.as_str().into();
            let import_address = Address::from_value(new_address as u64);
            let function = project.functions_mut().get_point_mut(import_address).unwrap();
            function.update_name(func_name);
            // project
            //     .memory_mut()
            //     .write_value(_address, new_address as u64)
            //     .unwrap();
            new_address += 3;
        }
        

    Ok(())
}
}



        // let mut i:u64 = 0;
        // for (address, name) in  {
        //     let mut off = i*3;
        //     i+=1;
        //     let mut fake_ker = 0x8000000000+off;
        //     let import_address = Address::from_value(fake_ker as u64);
        //     let function = project.functions_mut().get_point_mut(import_address).unwrap();
        //     function.update_name(name);

        //     project
        //         .memory_mut()
        //         .write_value(address, fake_ker)
        //         .unwrap();
        // }

        // let import_address_2 = Address::from_value(0x8000000003 as u64);
        // let function_2 = project.functions_mut().get_point_mut(import_address_2).unwrap();
        // function_2.update_name("IofCompleteRequest");
        // let import_address_3 = Address::from_value(0x8000000006 as u64);
        // let function_3 = project.functions_mut().get_point_mut(import_address_3).unwrap();
        // function_3.update_name("RtlInitUnicodeString");
        // project
        //     .memory_mut()
        //     .write_value(Address::from_value(0x140002010 as u64), 0x8000000003 as u64)
        //     .unwrap();
        // project.memory_mut()
        //     .write_value(Address::from_value(0x140002000 as u64), 0x8000000006 as u64)
        //     .unwrap();