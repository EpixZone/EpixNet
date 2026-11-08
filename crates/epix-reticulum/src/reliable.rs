//! Bounded, acknowledged byte streams over the Reticulum Channel protocol.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex as StdMutex};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use reticulum::channel::{Channel, Message, MessageStatus};
use reticulum::destination::link::{Link, LinkId};
use reticulum::error::RnsError;
use reticulum::transport::Transport;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{broadcast, mpsc, Mutex};
use tokio::task::JoinHandle;

const PAYLOAD: usize = 400;
const QUEUE: usize = 4;
const DELIVERY_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Clone)]
enum StreamMessage {
    Data(Vec<u8>),
    Finish,
}

impl Message for StreamMessage {
    fn unpack(bytes: &[u8], message_type: u16) -> Result<Self, RnsError> {
        match message_type {
            0x0e01 if !bytes.is_empty() && bytes.len() <= PAYLOAD => Ok(Self::Data(bytes.to_vec())),
            0x0e02 if bytes.is_empty() => Ok(Self::Finish),
            _ => Err(RnsError::ChannelError),
        }
    }

    fn pack(&self) -> Vec<u8> {
        match self {
            Self::Data(bytes) => bytes.clone(),
            Self::Finish => Vec::new(),
        }
    }

    fn message_type(&self) -> u16 {
        match self {
            Self::Data(_) => 0x0e01,
            Self::Finish => 0x0e02,
        }
    }
}

struct WriteMessage {
    sequence: u64,
    message: StreamMessage,
}

#[derive(Default)]
struct Progress {
    delivered: u64,
    error: Option<&'static str>,
    waiter: Option<Waker>,
}

impl Progress {
    fn wake(&mut self) {
        if let Some(waiter) = self.waiter.take() {
            waiter.wake();
        }
    }

    fn fail(&mut self, error: &'static str) {
        self.error.get_or_insert(error);
        self.wake();
    }
}

type Reserve = Pin<
    Box<
        dyn Future<Output = Result<mpsc::OwnedPermit<WriteMessage>, mpsc::error::SendError<()>>>
            + Send,
    >,
>;

pub(crate) struct ReliableStream {
    incoming: mpsc::Receiver<Vec<u8>>,
    outgoing: mpsc::Sender<WriteMessage>,
    reserve: Option<Reserve>,
    progress: Arc<StdMutex<Progress>>,
    written: u64,
    finishing: bool,
    read_buf: Vec<u8>,
    read_pos: usize,
    tasks: Vec<JoinHandle<()>>,
    transport: Arc<Mutex<Transport>>,
    link: Arc<Mutex<Link>>,
}

fn broken(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, message)
}

impl ReliableStream {
    pub(crate) async fn wrap(
        transport: Arc<Mutex<Transport>>,
        link: Arc<Mutex<Link>>,
        _link_id: LinkId,
    ) -> io::Result<Self> {
        let (channel, incoming) = Channel::<StreamMessage>::new(link.clone(), &transport)
            .await
            .map_err(|_| broken("mesh channel already bound or unavailable"))?;
        let channel = Arc::new(channel);
        let (in_tx, in_rx) = mpsc::channel(QUEUE);
        let (out_tx, out_rx) = mpsc::channel(QUEUE);
        let progress = Arc::new(StdMutex::new(Progress::default()));
        let writer = spawn_writer(
            channel.clone(),
            out_rx,
            progress.clone(),
            transport.clone(),
            link.clone(),
        );
        let reader = spawn_reader(
            channel,
            incoming,
            in_tx,
            progress.clone(),
            transport.clone(),
            link.clone(),
        );
        Ok(Self {
            incoming: in_rx,
            outgoing: out_tx,
            reserve: None,
            progress,
            written: 0,
            finishing: false,
            read_buf: Vec::new(),
            read_pos: 0,
            tasks: vec![writer, reader],
            transport,
            link,
        })
    }

    fn poll_permit(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<mpsc::OwnedPermit<WriteMessage>>> {
        if let Some(error) = self.progress.lock().unwrap().error {
            return Poll::Ready(Err(broken(error)));
        }
        let reserve = self
            .reserve
            .get_or_insert_with(|| Box::pin(self.outgoing.clone().reserve_owned()));
        match reserve.as_mut().poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                self.reserve = None;
                Poll::Ready(result.map_err(|_| broken("mesh sender closed")))
            }
        }
    }

    fn queue(&mut self, permit: mpsc::OwnedPermit<WriteMessage>, message: StreamMessage) {
        self.written += 1;
        permit.send(WriteMessage {
            sequence: self.written,
            message,
        });
    }

    fn poll_delivered(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut progress = self.progress.lock().unwrap();
        if let Some(error) = progress.error {
            Poll::Ready(Err(broken(error)))
        } else if progress.delivered >= self.written {
            Poll::Ready(Ok(()))
        } else {
            progress.waiter = Some(cx.waker().clone());
            Poll::Pending
        }
    }
}

impl AsyncRead for ReliableStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if buffer.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if let Some(error) = this.progress.lock().unwrap().error {
            return Poll::Ready(Err(broken(error)));
        }
        if this.read_pos == this.read_buf.len() {
            match this.incoming.poll_recv(cx) {
                Poll::Ready(Some(bytes)) => {
                    this.read_buf = bytes;
                    this.read_pos = 0;
                }
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => return Poll::Pending,
            }
        }
        let count = buffer.remaining().min(this.read_buf.len() - this.read_pos);
        buffer.put_slice(&this.read_buf[this.read_pos..this.read_pos + count]);
        this.read_pos += count;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for ReliableStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.finishing {
            return Poll::Ready(Err(broken("mesh write side is closed")));
        }
        if bytes.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let permit = std::task::ready!(this.poll_permit(cx))?;
        let count = bytes.len().min(PAYLOAD);
        this.queue(permit, StreamMessage::Data(bytes[..count].to_vec()));
        Poll::Ready(Ok(count))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_delivered(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.finishing {
            let permit = std::task::ready!(this.poll_permit(cx))?;
            this.queue(permit, StreamMessage::Finish);
            this.finishing = true;
        }
        this.poll_delivered(cx)
    }
}

async fn deliver(
    channel: &Channel<StreamMessage>,
    message: &StreamMessage,
) -> Result<(), &'static str> {
    let hash = channel
        .send(message)
        .await
        .map_err(|_| "mesh channel cannot send")?;
    let delivered = tokio::time::timeout(DELIVERY_TIMEOUT, async {
        loop {
            if matches!(
                channel.message_status(&hash).await,
                MessageStatus::Delivered
            ) {
                channel.forget_delivered(&hash).await;
                return Ok(());
            }
            if channel.is_closed().await {
                return Err("mesh channel closed before acknowledgment");
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    delivered.unwrap_or(Err("mesh delivery timed out"))
}

fn spawn_writer(
    channel: Arc<Channel<StreamMessage>>,
    mut outgoing: mpsc::Receiver<WriteMessage>,
    progress: Arc<StdMutex<Progress>>,
    transport: Arc<Mutex<Transport>>,
    link: Arc<Mutex<Link>>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(message) = outgoing.recv().await {
            if let Err(error) = deliver(&channel, &message.message).await {
                progress.lock().unwrap().fail(error);
                close_link(&transport, &link).await;
                return;
            }
            let mut progress = progress.lock().unwrap();
            progress.delivered = message.sequence;
            progress.wake();
        }
    })
}

fn spawn_reader(
    channel: Arc<Channel<StreamMessage>>,
    mut incoming: broadcast::Receiver<StreamMessage>,
    output: mpsc::Sender<Vec<u8>>,
    progress: Arc<StdMutex<Progress>>,
    transport: Arc<Mutex<Transport>>,
    link: Arc<Mutex<Link>>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let result = read_messages(&channel, &mut incoming, output).await;
        if let Err(error) = result {
            progress.lock().unwrap().fail(error);
            close_link(&transport, &link).await;
        }
    })
}

async fn read_messages(
    channel: &Channel<StreamMessage>,
    incoming: &mut broadcast::Receiver<StreamMessage>,
    output: mpsc::Sender<Vec<u8>>,
) -> Result<(), &'static str> {
    loop {
        tokio::select! {
            message = incoming.recv() => match message {
                Ok(StreamMessage::Data(bytes)) => output.send(bytes).await.map_err(|_| "mesh reader dropped")?,
                Ok(StreamMessage::Finish) => return Ok(()),
                Err(_) => return Err("mesh receive stream closed or lagged"),
            },
            _ = tokio::time::sleep(Duration::from_millis(100)) => {
                if channel.is_closed().await { return Err("mesh channel closed without end of stream"); }
            }
        }
    }
}

async fn close_link(transport: &Arc<Mutex<Transport>>, link: &Arc<Mutex<Link>>) {
    let id = *link.lock().await.id();
    let _ = transport.lock().await.link_close(id).await;
}

impl Drop for ReliableStream {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
        let transport = self.transport.clone();
        let link = self.link.clone();
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                let _ = tokio::time::timeout(Duration::from_secs(5), close_link(&transport, &link))
                    .await;
            });
        }
    }
}

#[cfg(test)]
#[path = "tests/reliable_startup.rs"]
mod startup_tests;
