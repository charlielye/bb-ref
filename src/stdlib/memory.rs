//! Runtime-indexed arrays (bb `stdlib::rom_table` / `ram_table`). The builder-side array is created
//! lazily on the first access so that tables that are never read cost nothing.

use super::field::{Ctx, FieldT};
use crate::circuit::Builder;

fn as_witness_index(b: &mut Builder, f: &FieldT) -> u32 {
    if f.is_constant() {
        b.put_constant_variable(f.get_value())
    } else {
        f.get_witness_index()
    }
}

pub struct RomTable {
    ctx: Ctx,
    entries: Vec<FieldT>,
    rom_id: Option<usize>,
}

impl RomTable {
    pub fn new(ctx: &Ctx, entries: Vec<FieldT>) -> Self {
        Self {
            ctx: ctx.clone(),
            entries,
            rom_id: None,
        }
    }
    fn initialize(&mut self) -> usize {
        if let Some(id) = self.rom_id {
            return id;
        }
        let witnesses: Vec<u32> = self
            .entries
            .iter()
            .map(|e| as_witness_index(&mut self.ctx.borrow_mut(), e))
            .collect();
        let mut b = self.ctx.borrow_mut();
        let id = b.create_rom_array(self.entries.len());
        for (i, w) in witnesses.into_iter().enumerate() {
            b.set_rom_element(id, i, w);
        }
        self.rom_id = Some(id);
        id
    }
    pub fn read(&mut self, index: &FieldT) -> FieldT {
        let i = Builder::low_u64(&index.get_value()) as usize;
        assert!(i < self.entries.len(), "ROM access out of bounds");
        let id = self.initialize();
        if index.is_constant() {
            return self.entries[i].clone();
        }
        let w = index.get_witness_index();
        let out = self.ctx.borrow_mut().read_rom_array(id, w);
        FieldT::from_witness_index(&self.ctx, out)
    }
}

pub struct RamTable {
    ctx: Ctx,
    entries: Vec<FieldT>,
    ram_id: Option<usize>,
}

impl RamTable {
    pub fn new(ctx: &Ctx, entries: Vec<FieldT>) -> Self {
        Self {
            ctx: ctx.clone(),
            entries,
            ram_id: None,
        }
    }
    fn initialize(&mut self) -> usize {
        if let Some(id) = self.ram_id {
            return id;
        }
        let id = self.ctx.borrow_mut().create_ram_array(self.entries.len());
        for i in 0..self.entries.len() {
            let w = as_witness_index(&mut self.ctx.borrow_mut(), &self.entries[i]);
            self.ctx.borrow_mut().init_ram_element(id, i, w);
        }
        self.ram_id = Some(id);
        id
    }
    pub fn read(&mut self, index: &FieldT) -> FieldT {
        assert!(
            (Builder::low_u64(&index.get_value()) as usize) < self.entries.len(),
            "RAM access out of bounds"
        );
        let id = self.initialize();
        let w = as_witness_index(&mut self.ctx.borrow_mut(), index);
        let out = self.ctx.borrow_mut().read_ram_array(id, w);
        FieldT::from_witness_index(&self.ctx, out)
    }
    pub fn write(&mut self, index: &FieldT, value: &FieldT) {
        assert!(
            (Builder::low_u64(&index.get_value()) as usize) < self.entries.len(),
            "RAM access out of bounds"
        );
        let id = self.initialize();
        let iw = as_witness_index(&mut self.ctx.borrow_mut(), index);
        let vw = as_witness_index(&mut self.ctx.borrow_mut(), value);
        self.ctx.borrow_mut().write_ram_array(id, iw, vw);
    }
}
