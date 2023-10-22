//! CLI option parsing.
//!
//! See [man ld](https://man7.org/linux/man-pages/man1/ld.1.html).
//!
//! ld opts are very whack and weird, so we use no CLI parsing framework
//! or library because they'd probably do it wrong!
//!
//! Bless the linker writers of the past for the mess they have constructed.

use std::path::PathBuf;

use anyhow::bail;

#[derive(Debug)]
pub struct InputFile {
    pub name: PathBuf,
}

struct Opt {
    short: Option<char>,
    long: &'static str,
    takes_value: Option<fn(&mut Opts, value: String)>,
    set: fn(&mut Opts),
}

macro_rules! define_opts {
    ($(
        $field:ident: $long:literal $(, $short:literal)? $(, $value:ident)? ;
    )*) => {
        #[derive(Debug, Default)]
        pub struct Opts {
            $(
                pub $field: Option<String>,
            )*
        }

        const OPTS: &[Opt] = &[
            $(
                Opt {
                    short: short_opt!($($short)?),
                    long: $long,
                    takes_value: takes_value!($field, $($value)?),
                    set: set!($field, $($value)?)
                },
            )*
        ];
    };
}

macro_rules! short_opt {
    () => {
        None
    };
    ($opt:tt) => {
        Some($opt)
    };
}

macro_rules! takes_value {
    ($field:ident, ) => {
        None
    };
    ($field:ident, $opt:tt) => {
        Some(|opts, value| opts.$field = Some(value))
    };
}

macro_rules! set {
    ($field:ident, ) => {
        |opts| opts.$field = true;
    };
    ($field:ident, $opt:tt) => {
        |_| {
            unreachable!(
                "set called on option taking a value: {}",
                stringify!($field)
            )
        }
    };
}

define_opts! {
    entry: "entry", 'e', String;
    output: "output", 'o', String;
}

pub fn parse(mut args: impl Iterator<Item = String>) -> anyhow::Result<(Opts, Vec<InputFile>)> {
    let mut opts = Opts::default();
    let mut files = Vec::new();
    let mut require_value: Option<fn(_, _)> = None;

    while let Some(arg) = args.next() {
        if arg.starts_with("@") {
            bail!("@file parsing syntax is not implemented yet.");
        } else if let Some(apply_value) = require_value {
            apply_value(&mut opts, arg);
            require_value = None;
        } else if arg.starts_with("-") {
            let Some(first_c) = arg.chars().nth(1) else {
                bail!("option starting with - requires a value. stdin/stdout are not supported");
            };

            // We first need to check for long opts, as -entry should be parsed as --entry and not -e ntry.
            // Accept both double -- and single -.
            let long_start = if first_c == '-' { 2 } else { 1 };
            let long_end = arg.chars().position(|c| c == '=').unwrap_or(arg.len());
            let long_flag_name = &arg[long_start..long_end];
            if let Some(long) = OPTS
                .iter()
                // Important: any long options starting with -o MUST NOT be parsed as the long options if starting
                // with a single dash. Just -o. No other flag.
                .find(|o| {
                    let skip_because_of_o = long_flag_name.starts_with("o") && first_c != '-';
                    !skip_because_of_o && o.long == long_flag_name
                })
            {
                if let Some(takes_value) = long.takes_value {
                    if long_end != arg.len() {
                        let value = &arg[(long_end + 1)..];
                        takes_value(&mut opts, value.to_owned());
                    } else {
                        require_value = Some(takes_value);
                    }
                } else if long_end != arg.len() {
                    bail!("long option {arg} does not take a value");
                } else {
                    (long.set)(&mut opts);
                }
                // We successfully parsed this as a long option, great. Move on.
                continue;
            }

            // No long option. Try short opts instead.
            if let Some(short) = OPTS.iter().find(|o| o.short == Some(first_c)) {
                if let Some(takes_value) = short.takes_value {
                    if long_flag_name.len() > 1 {
                        let value = &long_flag_name[1..];
                        takes_value(&mut opts, value.to_owned());
                    } else {
                        require_value = Some(takes_value);
                    }
                } else if arg.len() > 2 {
                    bail!("short option {arg} does not take a value");
                } else {
                    (short.set)(&mut opts);
                }
                // It's a short option!
                continue;
            }

            // No options exist :(
            bail!("unrecognized option: {arg}");
        } else {
            files.push(InputFile { name: arg.into() });
        }
    }

    if require_value.is_some() {
        bail!("last option required a value but none was supplied");
    }

    Ok((opts, files))
}

#[cfg(test)]
mod tests {
    use super::{InputFile, Opts};

    fn parse(cmd: impl AsRef<[&'static str]>) -> anyhow::Result<(Opts, Vec<InputFile>)> {
        super::parse(cmd.as_ref().into_iter().map(|&s| s.to_owned()))
    }

    #[test]
    fn value_has_dashes() {
        let cmd = ["--output", "--meow"];
        let (opts, files) = parse(cmd).unwrap();
        assert_eq!(opts.output, Some("--meow".to_owned()));
        assert!(files.is_empty());
    }

    #[test]
    fn short_value_direct() {
        let cmd = ["-estart"];
        let (opts, _) = parse(cmd).unwrap();
        assert_eq!(opts.entry, Some("start".to_owned()));
    }

    #[test]
    fn short_value_2() {
        let cmd = ["-e", "start"];
        let (opts, _) = parse(cmd).unwrap();
        assert_eq!(opts.entry, Some("start".to_owned()));
    }

    #[test]
    fn single_dash_long_value_eq() {
        let cmd = ["-entry=start"];
        let (opts, _) = parse(cmd).unwrap();
        assert_eq!(opts.entry, Some("start".to_owned()));
    }

    #[test]
    fn single_dash_long_value_2() {
        let cmd = ["-entry", "start"];
        let (opts, _) = parse(cmd).unwrap();
        assert_eq!(opts.entry, Some("start".to_owned()));
    }

    #[test]
    fn long_value_eq() {
        let cmd = ["--entry=start"];
        let (opts, _) = parse(cmd).unwrap();
        assert_eq!(opts.entry, Some("start".to_owned()));
    }

    #[test]
    fn long_value_2() {
        let cmd = ["--entry", "start"];
        let (opts, _) = parse(cmd).unwrap();
        assert_eq!(opts.entry, Some("start".to_owned()));
    }

    #[test]
    fn bad_option() {
        let cmd = ["--meow"];
        parse(cmd).unwrap_err();
    }

    #[test]
    fn no_value_supplied_end() {
        let cmd = ["-e"];
        parse(cmd).unwrap_err();
    }
}
