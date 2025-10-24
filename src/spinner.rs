// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

//! Displays a spinner in the terminal.

use clap::builder::styling::Style as AnsiStyle;
use std::io::{self, IsTerminal, Write};

/// A spinner for indicating ongoing progress in the terminal.
pub(crate) struct Spinner {
    chars: [char; 10],
    index: usize,
    message: &'static str,
    started: bool,
    enabled: bool,
}

impl Spinner {
    /// Creates a new spinner.
    #[must_use]
    pub fn new(message: &'static str) -> Self {
        Self {
            chars: ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'],
            index: 0,
            message,
            started: false,
            enabled: io::stderr().is_terminal(),
        }
    }

    /// Displays the first frame of the spinner if enabled, and hides the
    /// cursor.
    fn start(&mut self) {
        if self.enabled && !self.started {
            let mut stderr = io::stderr();
            let _ = write!(stderr, "\x1B[?25l");
            let _ = stderr.flush();
            self.started = true;
            self.tick_internal();
        }
    }

    /// Updates the spinner animation by a frame. Does an implicit `start()` if
    /// the spinner is not yet started.
    pub fn tick(&mut self) {
        if !self.enabled {
            return;
        }
        if self.started {
            self.index += 1;
            self.tick_internal();
        } else {
            self.start();
        }
    }

    fn tick_internal(&self) {
        if !self.enabled || !self.started {
            return;
        }
        let mut stderr = io::stderr();
        let green = AnsiStyle::new().bold();
        let spinner_char = self.chars[self.index % self.chars.len()];
        let _ = write!(stderr, "\r{green}{spinner_char}{green:#} {}", self.message);
        let _ = stderr.flush();
    }

    /// Removes the spinner from the screen and shows the cursor.
    pub fn finish(&self) {
        if self.enabled && self.started {
            let mut stderr = io::stderr();
            let len_to_clear = 1 + 1 + self.message.len();
            let _ = write!(stderr, "\r{:len$}\r\x1B[?25h", " ", len = len_to_clear);
            let _ = stderr.flush();
        }
    }
}

impl Drop for Spinner {
    fn drop(&mut self) {
        self.finish();
    }
}
