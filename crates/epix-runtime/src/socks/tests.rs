use super::{SocksControl, SocksRoute, MAX_CONNECTIONS};
use std::{io, sync::Arc, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Notify;

struct Echo(u8);

#[async_trait::async_trait]
impl SocksRoute for Echo {
    async fn serve(&self, mut stream: TcpStream) -> io::Result<()> {
        stream.write_all(&[self.0]).await?;
        loop {
            let byte = stream.read_u8().await?;
            stream.write_all(&[byte]).await?;
        }
    }
}

async fn connect(port: u16) -> TcpStream {
    TcpStream::connect(("127.0.0.1", port)).await.unwrap()
}

async fn read(stream: &mut TcpStream) -> io::Result<u8> {
    tokio::time::timeout(Duration::from_secs(2), stream.read_u8())
        .await
        .unwrap()
}

#[tokio::test]
async fn unavailable_route_rejects_without_releasing_the_listener() {
    let (control, task) = SocksControl::bind(0, Arc::new(Notify::new())).unwrap();
    let port = control.port();
    for _ in 0..3 {
        let mut stream = connect(port).await;
        assert!(read(&mut stream).await.is_err());
    }
    assert!(std::net::TcpListener::bind(("127.0.0.1", port)).is_err());
    drop(control);
    tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap();
    assert!(std::net::TcpListener::bind(("127.0.0.1", port)).is_ok());
}

#[tokio::test]
async fn recovery_cancels_old_connections_and_keeps_the_same_owned_port() {
    let (control, task) = SocksControl::bind(0, Arc::new(Notify::new())).unwrap();
    let port = control.port();
    control.route.send_replace(Some(Arc::new(Echo(1))));
    let mut original = connect(port).await;
    assert_eq!(read(&mut original).await.unwrap(), 1);
    control.disable();
    assert!(read(&mut original).await.is_err());
    assert!(read(&mut connect(port).await).await.is_err());
    assert!(std::net::TcpListener::bind(("127.0.0.1", port)).is_err());
    control.route.send_replace(Some(Arc::new(Echo(2))));
    let mut recovered = connect(port).await;
    assert_eq!(read(&mut recovered).await.unwrap(), 2);
    recovered.write_all(&[99]).await.unwrap();
    assert_eq!(read(&mut recovered).await.unwrap(), 99);
    drop(control);
    tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap();
    assert!(read(&mut recovered).await.is_err());
}

#[tokio::test]
async fn stalled_connections_are_bounded_and_shutdown_cancels_them() {
    let stop = Arc::new(Notify::new());
    let (control, task) = SocksControl::bind(0, stop.clone()).unwrap();
    control.route.send_replace(Some(Arc::new(Echo(1))));
    let mut held = Vec::new();
    for _ in 0..MAX_CONNECTIONS {
        let mut stream = connect(control.port()).await;
        assert_eq!(read(&mut stream).await.unwrap(), 1);
        held.push(stream);
    }
    let mut overflow = connect(control.port()).await;
    assert!(read(&mut overflow).await.is_err());
    stop.notify_one();
    tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap();
    for mut stream in held {
        assert!(read(&mut stream).await.is_err());
    }
}

#[tokio::test]
async fn stopping_before_the_accept_task_first_runs_is_not_lost() {
    let (control, task) = SocksControl::bind(0, Arc::new(Notify::new())).unwrap();
    let port = control.port();
    control.stop();
    tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap();
    assert!(std::net::TcpListener::bind(("127.0.0.1", port)).is_ok());
}
