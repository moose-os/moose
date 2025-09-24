use core::ptr;

use crate::font::DEFAULT_ASCII_FONT;
use limine::framebuffer::Framebuffer;

const BITS_PER_PIXEL: u64 = 32;
const BYTES_PER_PIXEL: u64 = BITS_PER_PIXEL / 8;

pub struct Vga {
    framebuffer: Framebuffer<'static>,
}

impl Vga {
    pub fn new(framebuffer: Framebuffer<'static>) -> Self {
        // TODO: Research whether BPP does in practice have other values than 32 and if so,
        //       lift this restriction
        assert_eq!(framebuffer.bpp(), 32);

        assert_eq!(framebuffer.red_mask_shift(), 16);
        assert_eq!(framebuffer.green_mask_shift(), 8);
        assert_eq!(framebuffer.blue_mask_shift(), 0);

        Self { framebuffer }
    }

    #[inline(always)]
    pub fn put_pixel(&mut self, x: u64, y: u64, color: Rgb) {
        assert!(x < self.framebuffer.width());
        assert!(y < self.framebuffer.height());

        let pixel_offset = ((y * self.framebuffer.pitch()) + (x * BYTES_PER_PIXEL)) as isize;
        let current_pixel = unsafe { self.framebuffer.addr().offset(pixel_offset) } as *mut u32;

        unsafe { ptr::write_volatile(current_pixel, color.0) };
    }

    pub fn put_pixels(&mut self, x: u64, y: u64, colors: &[Rgb]) {
        let width = self.framebuffer.width();
        let height = self.framebuffer.height();

        assert!(x < width);
        assert!(y < height);

        let mut i = 0;

        let mut current_x = x;
        let mut current_y = y;

        while i < colors.len() {
            if current_x >= width {
                current_x = 0;
                current_y += 1;

                assert!(current_y < height);
            }

            let pixel_offset = ((y * self.framebuffer.pitch()) + (x * BYTES_PER_PIXEL)) as isize;
            let current_pixel = unsafe { self.framebuffer.addr().offset(pixel_offset) } as *mut u32;

            let color = colors[i];

            unsafe { ptr::write_volatile(current_pixel, color.0) };

            i += 1;
            current_x += 1;
        }
    }

    pub fn fill_rectangle(&mut self, x: u64, y: u64, width: u64, height: u64, color: Rgb) {
        let framebuffer_width = self.framebuffer.width();
        let framebuffer_height = self.framebuffer.height();

        assert!(x < framebuffer_width);
        assert!(y < framebuffer_height);
        assert!((x + width) <= framebuffer_width);
        assert!((y + height) <= framebuffer_height);

        let address = self.framebuffer.addr();
        let pitch = self.framebuffer.pitch();

        for current_y in y..y + height {
            let packed_colors = ((color.0 as u128) << 96)
                | ((color.0 as u128) << 64)
                | ((color.0 as u128) << 32)
                | color.0 as u128;

            for current_x in (x..(x + width) - ((x + width) % 4)).step_by(4) {
                let pixel_offset = ((pitch * current_y) + (current_x * BYTES_PER_PIXEL)) as isize;
                let current_pixel = unsafe { address.offset(pixel_offset) } as *mut u128;

                unsafe { ptr::write_volatile(current_pixel, packed_colors) };
            }

            for current_x in (x + width) - ((x + width) % 4)..x + width {
                let pixel_offset = ((pitch * current_y) + (current_x * BYTES_PER_PIXEL)) as isize;
                let current_pixel = unsafe { address.offset(pixel_offset) } as *mut u32;

                unsafe { ptr::write_volatile(current_pixel, color.0) };
            }
        }
    }

    pub fn fill_row(&mut self, x: u64, y: u64, width: u64, color: Rgb) {
        self.fill_rectangle(x, y, width, 1, color);
    }

    pub fn draw_character(
        &mut self,
        x: u64,
        y: u64,
        scale: u64,
        character: char,
        foreground_color: Rgb,
        background_color: Rgb,
    ) {
        let framebuffer_width = self.framebuffer.width();
        let framebuffer_height = self.framebuffer.height();

        assert!((x + 8 * scale) <= framebuffer_width);
        assert!((y + 16 * scale) <= framebuffer_height);

        assert!(character.is_ascii_graphic());

        self.fill_rectangle(x, y, 8 * scale, 16 * scale, background_color);

        let glyph = &DEFAULT_ASCII_FONT[character as usize];

        if scale == 1 {
            for current_y_offset in 0..16 {
                let glyph_row = glyph[current_y_offset as usize];

                if glyph_row == 0 {
                    continue;
                }

                if glyph_row == 0b11111111 {
                    self.fill_row(x, y + current_y_offset, 8, foreground_color);

                    continue;
                }

                for current_x_offset in 0..8 {
                    if (glyph_row >> (7 - (current_x_offset as usize)) & 1) == 1 {
                        self.put_pixel(
                            x + current_x_offset,
                            y + current_y_offset,
                            foreground_color,
                        );
                    }
                }
            }
        } else {
            for current_y_offset in 0..16 * scale {
                let glyph_row = glyph[(current_y_offset / scale) as usize] as usize;

                if glyph_row == 0 {
                    continue;
                }

                if glyph_row == 0xFF {
                    self.fill_row(x, y + current_y_offset, 8 * scale, foreground_color);

                    continue;
                }

                for current_x_offset in 0..8 * scale {
                    if (glyph_row >> (7 - ((current_x_offset / scale) as usize)) & 1) == 1 {
                        self.put_pixel(
                            x + current_x_offset,
                            y + current_y_offset,
                            foreground_color,
                        );
                    }
                }
            }
        }
    }

    pub fn copy(&mut self, from: (u64, u64), to: (u64, u64), width: u64, height: u64) {
        let framebuffer_width = self.width();
        let framebuffer_height = self.height();

        assert!(from.0 < framebuffer_width);
        assert!(from.1 < framebuffer_height);
        assert!(to.0 < framebuffer_width);
        assert!(to.1 < framebuffer_height);

        if width == 0 {
            return;
        }

        assert!(from.0 + width <= framebuffer_width);
        assert!(to.0 + width <= framebuffer_width);

        if height == 0 {
            return;
        }

        assert!(from.1 + height <= framebuffer_height);
        assert!(to.1 + height <= framebuffer_height);

        if from == to {
            return;
        }

        if from.0 > to.0 {
            todo!();
        }

        if from.1 < to.1 {
            todo!();
        }

        let pitch = self.framebuffer.pitch();
        let address = self.framebuffer.addr();

        for y in 0..height {
            let source_y = from.1 + y;
            let destination_y = to.1 + y;

            for x in (0..width - (width % 4)).step_by(4) {
                let source_x = from.0 + x;
                let destination_x = to.0 + x;

                let source_pixel_offset = ((source_y * pitch) + (source_x * 4)) as isize;
                let source_pixel = unsafe { address.offset(source_pixel_offset) } as *mut u128;

                let destination_pixel_offset =
                    ((destination_y * pitch) + (destination_x * 4)) as isize;
                let destination_pixel =
                    unsafe { address.offset(destination_pixel_offset) } as *mut u128;

                unsafe { ptr::write_volatile(destination_pixel, ptr::read_volatile(source_pixel)) };
            }

            for x in (width - (width % 4))..width {
                let source_x = from.0 + x;
                let destination_x = to.0 + x;

                let source_pixel_offset = ((source_y * pitch) + (source_x * 4)) as isize;
                let source_pixel = unsafe { address.offset(source_pixel_offset) } as *mut u32;

                let destination_pixel_offset =
                    ((destination_y * pitch) + (destination_x * 4)) as isize;
                let destination_pixel =
                    unsafe { address.offset(destination_pixel_offset) } as *mut u32;

                unsafe { ptr::write_volatile(destination_pixel, ptr::read_volatile(source_pixel)) };
            }
        }
    }

    #[inline(always)]
    pub fn width(&self) -> u64 {
        self.framebuffer.width()
    }

    #[inline(always)]
    pub fn height(&self) -> u64 {
        self.framebuffer.height()
    }
}

// Safety: This is safe only if Vga has exclusive access to the framebuffer.
unsafe impl Send for Vga {}

#[derive(Clone, Copy)]
pub struct Rgb(u32);

impl Rgb {
    pub const fn new(r: u8, g: u8, b: u8) -> Self {
        Self((r as u32) << 16 | (g as u32) << 8 | b as u32)
    }
}
