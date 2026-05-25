struct Bar(u32);

impl Bar {
    fn foo(&mut self) {
        self.0 += 1
    }
}

fn main() {
    let x = 1;
    let y = &x;

    format!("{y}")
}
