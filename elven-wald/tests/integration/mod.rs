mod simple_asm;

use std::{
    ffi::{OsStr, OsString},
    fmt::Display,
    path::PathBuf,
    process::Command,
};

pub fn run(mut cmd: Command) {
    let out = cmd.output().expect("failed to spawn command");
    if !out.status.success() {
        panic!(
            "FAILED to run {}: {}",
            cmd.get_program().to_str().unwrap(),
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

macro_rules! elven_wald {
    ($ctx:expr; $($args:expr),*) => {{
        let ctx = &$ctx;
        let output = ctx.file_ref("elven-wald-output");
        let mut cmd = std::process::Command::new("../target/debug/elven-wald");
        cmd.arg("-o");
        cmd.arg(&output);
        $( cmd.arg($args); )*
        $crate::integration::run(cmd);
        output
    }};
}
pub(crate) use elven_wald;

pub struct Ctx {
    _tempdir: tempfile::TempDir,
    path: PathBuf,
}

pub struct File(PathBuf);

impl Display for File {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0.to_str().unwrap())
    }
}

impl From<File> for OsString {
    fn from(value: File) -> Self {
        value.0.into_os_string()
    }
}

impl AsRef<OsStr> for File {
    fn as_ref(&self) -> &OsStr {
        self.0.as_os_str()
    }
}

pub fn ctx() -> Ctx {
    let tempdir = tempfile::tempdir().expect("failed to create tempdir");
    let path = tempdir.path().to_owned();
    Ctx {
        _tempdir: tempdir,
        path,
    }
}

impl Ctx {
    #[allow(dead_code)]
    pub fn write_to_path(mut self, path: &str) -> Self {
        self.path = path.into();
        self
    }

    pub fn file_ref(&self, filename: &str) -> File {
        File(self.path.join(filename))
    }

    pub fn file(&self, filename: &str, content: &str) -> File {
        let out = self.path.join(filename);
        std::fs::write(&out, content).expect("failed to write file");
        File(out)
    }

    pub fn nasm(&self, filename: &str, content: &str) -> File {
        let input = self.file(&format!("{filename}.asm"), content);
        let out = self.path.join(filename);
        let mut cmd = Command::new("nasm");
        cmd.args(["-felf64", "-o"]);
        cmd.arg(&out);
        cmd.arg(input);
        run(cmd);
        File(out)
    }
}
