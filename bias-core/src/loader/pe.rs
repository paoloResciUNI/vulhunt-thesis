use std::borrow::Cow;
use std::fs::File;
use std::path::{Path, PathBuf};

use fugue::bytes::Endian;
use fugue::ir::error::Error as LanguageDBError;
use fugue::ir::{Address, IntoAddress, LanguageDB};
use goblin::mach::segment::Section;
use goblin::pe::header::{COFF_MACHINE_X86, COFF_MACHINE_X86_64};
use goblin::pe::section_table::{IMAGE_SCN_CNT_CODE, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_WRITE};
use goblin::pe::utils::PESectionTable;
use goblin::pe::PE;
use memmap2::Mmap;
use thiserror::Error;

use super::{
    LoadedBinary, Loader, LoaderBlock, LoaderBytes, LoaderContainer, LoaderFunction, LoaderImport,
    LoaderRegion,
};
use crate::eval::Configuration;
use crate::{Project, ProjectConfig};
use crate::analyses::strings::StringsXRefDB;
use crate::arch::x86::X86;
use crate::cfg::{ICFG, ICFGBuilder};
use crate::eval::traits::VarOps;
use crate::lifter::{Lifter, LifterBuilder, LifterBuilderError};

use std::sync::OnceLock;

pub static IMPORT_FUNCS: OnceLock<Vec<(Address, String)>> = OnceLock::new();
const IMPORT_STUB_BASE: u64 = 0x8000000000;
const IMPORT_STUB_SIZE: u64 = 3;

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    LoaderFormat(#[from] goblin::error::Error),
    #[error(transparent)]
    LoaderIO(#[from] std::io::Error),
    #[error(transparent)]
    LanguageDB(#[from] LanguageDBError),
    #[error(transparent)]
    LifterBuilder(#[from] LifterBuilderError),
    #[error("unsupported architecture {0:x}")]
    UnsupportedArchitecture(u16),
    #[error("unsupported lifter convention: {0}")]
    UnsupportedConvention(Cow<'static, str>),
}

pub struct PELoader<'a> {
    ldb: Cow<'a, LanguageDB>,
    bytes: Option<Mmap>,
    convention: Cow<'static, str>,
}

impl<'a> PELoader<'a> {
    pub fn new(ldb: impl Into<Cow<'a, LanguageDB>>) -> Self {
        Self {
            ldb: ldb.into(),
            bytes: None,
            convention: "windows".into(), // TODO: change to windows?
        }
    }

    pub fn new_with<P>(language_dir: P) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        let ldb = Cow::Owned(LanguageDB::from_directory_with(language_dir, true)?);
        Ok(Self::new(ldb))
    }

    #[inline]
    pub fn load_bytes<'b>(&self, bytes: &'b [u8]) -> Result<(Lifter, LoadedPE<'b>), Error> {
        self.load_bytes_with(bytes, None)
    }

    #[inline]
    pub fn load_bytes_with<'b>(
        &self,
        bytes: &'b [u8],
        path: impl Into<Option<PathBuf>>,
    ) -> Result<(Lifter, LoadedPE<'b>), Error> {
        let pe = PE::parse(&bytes).map_err(Error::LoaderFormat)?;
        let arch = pe.header.coff_header.machine;
        // let import_funcs: OnceLock<Vec<(Address, String)>> = OnceLock::new();

        let (arch_info, processor, bits) = match arch {
            COFF_MACHINE_X86_64 => (X86::new(true), "x86", 64),
            COFF_MACHINE_X86 => (X86::new(false), "x86", 32),
            _ => return Err(Error::UnsupportedArchitecture(arch)),
        };

        let builder = self
            .ldb
            .lookup(processor, Endian::Little, bits, "default")
            .ok_or_else(|| Error::UnsupportedArchitecture(arch))?;

        let translator = LifterBuilder::build_or_cached(&builder)?;

        let convention = translator
            .compiler_conventions()
            .get(&*self.convention)
            .cloned()
            .or_else(|| translator.compiler_conventions().get("default").cloned())
            .ok_or_else(|| Error::UnsupportedConvention(self.convention.clone()))?;

        let lifter = Lifter::new_with(translator, convention, arch_info);

        let image_base = Address::from(pe.image_base as u64);

        Ok((
            lifter,
            LoadedPE {
                pe,
                image_base,
                path: path.into(),
                raw: bytes,
                import_funcs: OnceLock::new(),
            },
        ))
    }

    pub fn with_convention<C>(mut self, convention: C) -> Self
    where
        C: Into<Cow<'static, str>>,
    {
        self.convention = convention.into();
        self
    }
}

impl<'a> Loader for &'a mut PELoader<'_> {
    type Error = Error;
    type Loaded = LoadedPE<'a>;

    fn load_file<P>(self, path: P) -> Result<(Lifter, Self::Loaded), Self::Error>
    where
        P: AsRef<Path>,
    {
        println!("DEBUG: Loading PE file from {}\n", path.as_ref().display());

        let path = path.as_ref();
        let f = File::open(path).map_err(Error::LoaderIO)?;
        self.bytes = Some(unsafe { Mmap::map(&f) }.map_err(Error::LoaderIO)?);

        let bytes = self.bytes.as_ref().unwrap();

        self.load_bytes_with(bytes, path.to_owned())
    }
}

pub struct LoadedPE<'a> {
    pe: PE<'a>,
    image_base: Address,
    path: Option<PathBuf>,
    raw: &'a [u8],
    import_funcs: OnceLock<Vec<(Address, String)>>,
}

impl<'a> LoadedPE<'a> {
    pub fn pe(&self) -> &PE<'a> {
        &self.pe
    }

    pub fn bytes(&self) -> &[u8] {
        &self.raw
    }

    pub fn path(&self) -> Option<&PathBuf> {
        self.path.as_ref()
    }
}

impl<'a> LoadedBinary for LoadedPE<'a> {
    fn for_each_region<'b, F>(&'b self, mut f: F)
    where
        F: FnMut(&LoaderRegion<'b>),
    {

        
        // Taking all the imports from the .idata section with goblin parser
        let mut import_address: Vec<(Address, String)> = self
            .pe
            .imports
            .iter()
            .map(|import| (self.image_base + import.offset, import.name.to_string()))
            .collect();
        // for import in self.pe.imports.iter() {
            //     import_address.push((self.image_base+import.offset, import.name.to_string()));
        // }
        import_address.sort();
        import_address.dedup();

        // The same thing as before but in the LoadedPE structure
        self.import_funcs.set(import_address.clone()).ok();
        
        for section in self.pe.sections.iter() {
            if section.virtual_size() == 0 {
                continue;
            }

            let rstart = section.pointer_to_raw_data() as usize;
            let rsize = section.size_of_raw_data() as usize;
            
            let rend = match rstart.checked_add(rsize) {
                None => {
                    tracing::debug!("PointerToRawData + SizeOfRawData overflows");
                    continue;
                }
                Some(rend) => rend as usize,
            };

            if rend as usize > self.raw.len() {
                tracing::debug!("PointerToRawData + SizeOfRawData is out of bounds");
                continue;
            }

            let vstart = self.image_base + section.virtual_address() as usize;
            let vsize = section.virtual_size() as usize;
            let vend = vstart + vsize;

            let vbounds = if vend <= vstart {
                tracing::debug!("VirtualAddress + VirtualSize overflows");
                continue;
            } else {
                vstart..vend
            };
            
            if rsize > vsize {
                tracing::debug!("raw section size > virtual size");
            }
            
            let mut lrgn = LoaderRegion::default();
            
            lrgn.name = section.name().ok().map(Cow::Borrowed);
            lrgn.code =
            (section.characteristics() & (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE)) != 0;
            lrgn.read_only = (section.characteristics() & IMAGE_SCN_MEM_WRITE) == 0;
            lrgn.bounds = vbounds.clone();
            lrgn.endian = Endian::Little;
            
            // TODO: relocations!

            lrgn.bytes = if rsize < vsize {
                tracing::trace!("raw section size < virtual size; padding with zeros");
                let mut bytes = Vec::with_capacity(vsize);
                
                bytes.extend_from_slice(&self.raw[rstart..rend]);
                bytes.resize(vsize, 0u8);
                
                lrgn.uninitialised = Some((vstart + rsize)..(vstart + vsize));
                
                Cow::Owned(bytes)
            } else {
                let vrend = rstart + rsize.min(vsize);
                Cow::Borrowed(&self.raw[rstart..vrend])
            };


            if self.pe.header.coff_header.machine == COFF_MACHINE_X86_64 {
                for (index, (iat_address, name)) in import_address.iter().enumerate() {
                
                    if !lrgn.bounds.contains(iat_address) {
                        continue;
                    }
                
                    let offset = usize::from(*iat_address - lrgn.bounds.start);
                
                    let fake_address =
                        IMPORT_STUB_BASE + (index as u64 * IMPORT_STUB_SIZE);
                
                    let fake_address_bytes = fake_address.to_le_bytes();
                
                    let region_bytes = lrgn.bytes.to_mut();
                
                    let Some(end) = offset.checked_add(fake_address_bytes.len()) else {
                        tracing::warn!(
                            "IAT offset overflow for import {} at {}",
                            name,
                            iat_address
                        );
                        continue;
                    };
                
                    if end > region_bytes.len() {
                        tracing::warn!(
                            "IAT entry for import {} at {} is outside region {}",
                            name,
                            iat_address,
                            lrgn.name.as_deref().unwrap_or("extern")
                        );
                        continue;
                    }
                
                    region_bytes[offset..end]
                        .copy_from_slice(&fake_address_bytes);
                
                    println!(
                        "Patched IAT: {} at {} -> {:#x}",
                        name,
                        iat_address,
                        fake_address
                    );
                }
            }           
            
            f(&lrgn)
        }



        let kernel_base = Address::from_value(IMPORT_STUB_BASE);
        // Let's just simulate our beloved kernel region

        let mut bytes = Vec::new();

        println!(
            "Numero di funzioni importate, {}",
            self.import_funcs.get().unwrap().len()
        );
        for (address, name) in self.import_funcs.get().unwrap() {
            println!("Nome funzione: {}\nAddress funzione: {}\n", name, address);
            bytes.extend_from_slice((0x31c0_u16).to_be_bytes().as_ref()); // XOR EAX, EAX
            bytes.extend_from_slice((0xc3_u8).to_be_bytes().as_ref()); // RET
        }

        IMPORT_FUNCS
            .set(self.import_funcs.get().unwrap().clone())
            .unwrap(); // exorting the <address - name> vector

        let mut lrgn = LoaderRegion::default();
        lrgn.name = Some(Cow::Borrowed("extern"));
        lrgn.code = true;
        lrgn.read_only = true;
        lrgn.bounds = kernel_base..(kernel_base + (bytes.len() as u64));
        lrgn.endian = Endian::Little;
        lrgn.bytes = Cow::Owned(bytes);

        println!(
            "Creating fake region for kernel imports of size {}!",
            (lrgn.bounds.end - lrgn.bounds.start)
        );



        f(&lrgn);
    }

    fn for_each_block<F>(&self, _f: F)
    where
        F: FnMut(&LoaderBlock),
    {
    }

    fn for_each_function<'b, F>(&'b self, mut f: F)
    where
        F: FnMut(&LoaderFunction<'b>),
    {
        f(&LoaderFunction {
            entry: self.entry_point().unwrap(),
            name: None,
            ..Default::default()
        });

        self.for_each_import(|import| {
            if let Some(entry) = import.address {
                f(&LoaderFunction {
                    entry,
                    name: Some(Cow::Owned(format!("{}", import.name))),
                    ..Default::default()
                });
            }
        });

        if let Some(import_address) = IMPORT_FUNCS.get() {
            let kernel_base = Address::from_value(IMPORT_STUB_BASE);
            let mut current_addr = kernel_base;

            for (_address, name) in import_address {
                f(&LoaderFunction {
                    entry: current_addr,
                    name: Some(Cow::Borrowed(name.as_str())),
                    ..Default::default()
                });
                current_addr = current_addr + 3usize;
            }
        }
    }

    fn for_each_import<'b, F>(&'b self, mut f: F)
    where
        F: FnMut(&LoaderImport<'b>),
    {
        // println!("DEBUG: checking if the for is triggered, number of possible iterations: {}\n", self.pe.imports.len());
        self.pe.imports.iter().for_each(|import| {
            // println!("DEBUG: I think we're iterating throught some imported functions, like {}\n", (import.name));
            f(&LoaderImport {
                name: Cow::Borrowed(import.name.as_ref()),
                address: Some(Address::from(
                    (import.offset as u64).wrapping_add(self.pe.image_base as u64),
                )),
                source: Some(import.dll.into()),
                ..Default::default()
            })
        });
    }

    fn bytes<'b>(&'b self) -> LoaderBytes<'b> {
        LoaderBytes::Borrowed(self.raw)
    }

    fn container<'b>(&'b self) -> LoaderContainer<'b> {
        let mut t = LoaderContainer::new(self.pe());
        t.set_attr(LoaderBytes::Borrowed(self.raw));
        t
    }

    fn entry_point(&self) -> Option<Address> {
        Some(Address::from(self.pe.entry as u64) + self.image_base)
    }
}
