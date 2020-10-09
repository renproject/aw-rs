use core::{
    pin::Pin,
    task::{Context, Poll},
};
use std::io::{self, ErrorKind, Read, Write};
use std::sync::mpsc::{self, Receiver, Sender};
use tokio::io::{AsyncRead, AsyncWrite};

pub struct ChannelRW {
    reader: Receiver<Vec<u8>>,
    writer: Sender<Vec<u8>>,
}

impl ChannelRW {
    pub fn new_pair() -> (Self, Self) {
        let (w1, r1) = mpsc::channel();
        let (w2, r2) = mpsc::channel();
        (
            Self {
                reader: r1,
                writer: w2,
            },
            Self {
                reader: r2,
                writer: w1,
            },
        )
    }
}

impl Read for ChannelRW {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let data = self
            .reader
            .recv()
            .map_err(|e| io::Error::new(ErrorKind::BrokenPipe, e))?;
        let n = std::cmp::min(data.len(), buf.len());
        buf[..n].copy_from_slice(&data[..n]);
        Ok(n)
    }
}

impl Write for ChannelRW {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = buf.len();
        let mut data = Vec::with_capacity(n);
        data.extend_from_slice(&buf);
        self.writer
            .send(data)
            .map_err(|e| io::Error::new(ErrorKind::BrokenPipe, e))?;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl AsyncRead for ChannelRW {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context,
        buf: &mut [u8],
    ) -> Poll<tokio::io::Result<usize>> {
        println!("reading");
        self.read(buf).into()
    }
}

impl AsyncWrite for ChannelRW {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context,
        buf: &[u8],
    ) -> Poll<Result<usize, tokio::io::Error>> {
        self.write(buf).into()
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        _cx: &mut Context,
    ) -> Poll<Result<(), tokio::io::Error>> {
        self.flush().into()
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), tokio::io::Error>> {
        self.poll_flush(cx)
    }
}

pub struct ChunkedRW<RW> {
    max_chunk_size: usize,
    rw: RW,
}

impl<RW> ChunkedRW<RW> {
    pub fn new(rw: RW, max_chunk_size: usize) -> Self {
        Self { max_chunk_size, rw }
    }
}

impl<RW> Read for ChunkedRW<RW>
where
    RW: Read,
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.rw.read(buf)
    }
}

impl<RW> Write for ChunkedRW<RW>
where
    RW: Write,
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = buf.len();
        let mut to_write = n;
        let mut written = 0;
        while to_write != 0 {
            let mut chunk_size = (rand::random::<usize>() % self.max_chunk_size) + 1;
            if chunk_size > to_write {
                chunk_size = to_write;
            }
            self.rw.write_all(&buf[written..written + chunk_size])?;
            to_write -= chunk_size;
            written += chunk_size;
        }
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.rw.flush()
    }
}

impl<RW> AsyncRead for ChunkedRW<RW>
where
    RW: Read + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context,
        buf: &mut [u8],
    ) -> Poll<tokio::io::Result<usize>> {
        self.read(buf).into()
    }
}

impl<RW> AsyncWrite for ChunkedRW<RW>
where
    RW: Write + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context,
        buf: &[u8],
    ) -> Poll<Result<usize, tokio::io::Error>> {
        self.write(buf).into()
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        _cx: &mut Context,
    ) -> Poll<Result<(), tokio::io::Error>> {
        self.flush().into()
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), tokio::io::Error>> {
        self.poll_flush(cx)
    }
}
