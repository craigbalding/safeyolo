//! Hold an operator SUB in transit while the real broker handles the handshake.
use std::{io, time::Duration};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    task::JoinHandle,
};

pub(crate) struct SubscriptionRelay {
    pub(crate) port: u16,
    held: oneshot::Receiver<()>,
    release: Option<oneshot::Sender<()>>,
    task: JoinHandle<()>,
}

impl Drop for SubscriptionRelay {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl SubscriptionRelay {
    pub(crate) async fn start(broker_port: u16) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (held, receiver) = oneshot::channel();
        let (release, resume) = oneshot::channel();
        let task = tokio::spawn(async move {
            let (client, _) = listener.accept().await.unwrap();
            let broker = TcpStream::connect(("127.0.0.1", broker_port))
                .await
                .unwrap();
            let (client_read, mut client_write) = client.into_split();
            let (mut broker_read, mut broker_write) = broker.into_split();
            let forward = async {
                let mut reader = BufReader::new(client_read);
                loop {
                    let mut line = Vec::new();
                    if reader.read_until(b'\n', &mut line).await? == 0 {
                        return Ok::<(), io::Error>(());
                    }
                    if line.starts_with(b"SUB safeyolo.operator.events ") {
                        let _ = held.send(());
                        let _ = resume.await;
                        broker_write.write_all(&line).await?;
                        tokio::io::copy(&mut reader, &mut broker_write).await?;
                        return Ok(());
                    }
                    broker_write.write_all(&line).await?;
                }
            };
            // Closing either endpoint during fixture cleanup may return an error.
            let _ = tokio::try_join!(
                forward,
                tokio::io::copy(&mut broker_read, &mut client_write)
            );
        });
        Self {
            port,
            held: receiver,
            release: Some(release),
            task,
        }
    }

    pub(crate) async fn wait_for_sub(&mut self) {
        tokio::time::timeout(Duration::from_secs(3), &mut self.held)
            .await
            .expect("consumer did not send its event SUB")
            .expect("relay closed before holding SUB");
    }

    pub(crate) fn release(&mut self) {
        self.release.take().unwrap().send(()).unwrap();
    }
}
