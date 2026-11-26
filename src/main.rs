//! Top-level main code for `pwninit`

use std::io::{self, Write};

use pwninit::opts::Opts;

use clap::{CommandFactory, Parser};

fn report_output_error(err: io::Error) {
    if err.kind() != io::ErrorKind::BrokenPipe {
        let _ = writeln!(io::stderr().lock(), "error writing command output: {err}");
    }
}

fn main() {
    let opts = Opts::parse().with_resolved_command();
    pwninit::output::configure(opts.quiet, opts.verbose, opts.json);

    if let Err(message) = opts.validate() {
        if opts.json {
            if let Err(err) = pwninit::output::error(message) {
                report_output_error(err);
            }
            std::process::exit(2);
        }
        Opts::command()
            .error(clap::error::ErrorKind::InvalidValue, message)
            .exit();
    }

    match pwninit::run_with_summary(opts) {
        Ok(summary) => {
            let success = summary.success();
            if let Err(err) = pwninit::output::render_summary(&summary) {
                report_output_error(err);
                std::process::exit(1);
            }
            if !success {
                std::process::exit(1);
            }
        }
        Err(err) => {
            if let Err(err) = pwninit::output::error(err.to_string()) {
                report_output_error(err);
            }
            std::process::exit(1);
        }
    }
}
