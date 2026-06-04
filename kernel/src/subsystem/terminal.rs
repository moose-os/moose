use crate::driver::vga::{Rgb, Vga};

const THREE_BIT_PALETTE: [Rgb; 8] = [
    Rgb::new(1, 1, 1),       // Black
    Rgb::new(222, 56, 42),   // Red
    Rgb::new(57, 181, 74),   // Green
    Rgb::new(255, 199, 6),   // Yellow
    Rgb::new(0, 111, 184),   // Blue
    Rgb::new(118, 38, 113),  // Magenta
    Rgb::new(44, 181, 233),  // Cyan
    Rgb::new(204, 204, 204), // White
];

const THREE_BIT_BRIGHT_PALETTE: [Rgb; 8] = [
    Rgb::new(85, 85, 85),    // Bright black (gray)
    Rgb::new(255, 85, 85),   // Bright red
    Rgb::new(85, 255, 85),   // Bright green
    Rgb::new(255, 255, 85),  // Bright yellow
    Rgb::new(85, 85, 255),   // Bright blue
    Rgb::new(255, 85, 255),  // Bright magenta
    Rgb::new(85, 255, 255),  // Bright cyan
    Rgb::new(255, 255, 255), // Bright white
];

pub struct Terminal {
    vga: Vga,
    current_max_width: u64,
    x: u64,
    y: u64,

    foreground_color: Rgb,
    background_color: Rgb,
}

impl Terminal {
    pub fn new(vga: Vga) -> Self {
        Self {
            vga,
            current_max_width: 0,
            x: 0,
            y: 0,
            foreground_color: Rgb::new(190, 190, 190),
            background_color: Rgb::new(0, 0, 0),
        }
    }

    pub fn print_str(&mut self, string: &str) {
        const WIDTH: u64 = 8;
        const HEIGHT: u64 = 16;

        let mut in_ansi_sequence = false;
        let mut in_control_sequence = false;
        let mut sequence_buffer = [' '; 16];
        let mut sequence_buffer_idx = 0;

        for character in string.chars() {
            if character == '\x1b' {
                in_ansi_sequence = true;

                continue;
            }

            if in_ansi_sequence {
                if character == '[' {
                    in_control_sequence = true;

                    continue;
                }

                if in_control_sequence {
                    if character != 'm' {
                        sequence_buffer[sequence_buffer_idx] = character;
                        sequence_buffer_idx += 1;

                        continue;
                    } else {
                        in_ansi_sequence = false;
                        in_control_sequence = false;

                        if sequence_buffer == [' '; 16] {
                            continue;
                        }

                        let mut sequence = [0u8; 6];
                        let mut sequence_idx = 0;

                        for character in &sequence_buffer[..sequence_buffer_idx] {
                            if character.is_ascii_whitespace() {
                                break;
                            }

                            if character.is_ascii_digit() {
                                sequence[sequence_idx] *= 10;
                                sequence[sequence_idx] += *character as u8 - b'0';
                            }

                            if *character == ';' {
                                sequence_idx += 1;
                            }
                        }

                        if sequence_buffer_idx != 0 {
                            match sequence[0] {
                                // 4 bit

                                // 3 bit foreground color
                                code @ 30..=37 => {
                                    self.foreground_color = THREE_BIT_PALETTE[(code - 30) as usize];
                                }
                                // 3 bit background color
                                code @ 40..=47 => {
                                    self.background_color = THREE_BIT_PALETTE[(code - 40) as usize];
                                }
                                // 3 bit bright foreground color
                                code @ 90..=97 => {
                                    self.foreground_color =
                                        THREE_BIT_BRIGHT_PALETTE[(code - 90) as usize];
                                }
                                // 3 bit bright background color
                                code @ 100..=107 => {
                                    self.background_color =
                                        THREE_BIT_BRIGHT_PALETTE[(code - 100) as usize];
                                }

                                // 8 bit

                                // foreground color
                                38 if sequence[1] == 5 => match sequence[2] {
                                    code @ 0..=7 => {
                                        self.foreground_color =
                                            THREE_BIT_PALETTE[(code - 30) as usize];
                                    }
                                    code @ 8..=15 => {
                                        self.foreground_color =
                                            THREE_BIT_BRIGHT_PALETTE[(code - 90) as usize];
                                    }
                                    code @ 16..=231 => {
                                        let idx = code - 16;
                                        let r = (idx / 36) * 51;
                                        let g = ((idx % 36) / 6) * 51;
                                        let b = (idx % 6) * 51;

                                        self.foreground_color = Rgb::new(r, g, b);
                                    }
                                    code @ 232..=255 => {
                                        let gray = (code - 232) * 10 + 8;

                                        self.foreground_color = Rgb::new(gray, gray, gray);
                                    }
                                },
                                // background color
                                48 if sequence[1] == 5 => match sequence[2] {
                                    code @ 0..=7 => {
                                        self.background_color =
                                            THREE_BIT_PALETTE[(code - 30) as usize];
                                    }
                                    code @ 8..=15 => {
                                        self.background_color =
                                            THREE_BIT_BRIGHT_PALETTE[(code - 90) as usize];
                                    }
                                    code @ 16..=231 => {
                                        let idx = code - 16;
                                        let r = (idx / 36) * 51;
                                        let g = ((idx % 36) / 6) * 51;
                                        let b = (idx % 6) * 51;

                                        self.background_color = Rgb::new(r, g, b);
                                    }
                                    code @ 232..=255 => {
                                        let gray = (code - 232) * 10 + 8;

                                        self.background_color = Rgb::new(gray, gray, gray);
                                    }
                                },

                                // 24 bit

                                // foreground color
                                38 if sequence[1] == 2 => {
                                    self.foreground_color =
                                        Rgb::new(sequence[2], sequence[3], sequence[4]);
                                }
                                // background color
                                48 if sequence[1] == 2 => {
                                    self.background_color =
                                        Rgb::new(sequence[2], sequence[3], sequence[4]);
                                }

                                _ => {}
                            }
                        }

                        sequence_buffer = [' '; 16];
                        sequence_buffer_idx = 0;

                        continue;
                    }
                }
            }

            if character.is_ascii_control() && !character.is_whitespace() && character != '\n' {
                continue;
            }

            if character == '\n' {
                self.x = 0;
                self.y += HEIGHT;

                if (self.y + HEIGHT) >= self.vga.height() {
                    self.x = 0;
                    self.y -= HEIGHT;

                    self.vga.copy(
                        (0, HEIGHT),
                        (0, 0),
                        self.current_max_width,
                        self.vga.height() - HEIGHT,
                    );

                    self.vga.fill_rectangle(
                        self.x,
                        self.y,
                        self.current_max_width,
                        HEIGHT,
                        self.background_color,
                    );
                }

                continue;
            }

            if character.is_ascii_graphic() {
                self.vga.draw_character(
                    self.x,
                    self.y,
                    1,
                    character,
                    self.foreground_color,
                    self.background_color,
                );
            } else if !character.is_whitespace() {
                self.vga.draw_character(
                    self.x,
                    self.y,
                    1,
                    '.',
                    self.foreground_color,
                    self.background_color,
                );
            }

            self.x += WIDTH;

            if self.x > self.current_max_width {
                self.current_max_width = self.x;
            }

            if (self.x + WIDTH) > self.vga.width() {
                self.x = 0;
                self.y += HEIGHT;

                if (self.y + HEIGHT) >= self.vga.height() {
                    self.x = 0;
                    self.y -= HEIGHT;

                    self.vga.copy(
                        (0, HEIGHT),
                        (0, 0),
                        self.current_max_width,
                        self.vga.height() - HEIGHT,
                    );

                    self.vga.fill_rectangle(
                        self.x,
                        self.y,
                        self.vga.width(),
                        HEIGHT,
                        self.background_color,
                    );
                }
            }
        }
    }
}

impl core::fmt::Write for Terminal {
    fn write_str(&mut self, string: &str) -> core::fmt::Result {
        self.print_str(string);

        Ok(())
    }
}
