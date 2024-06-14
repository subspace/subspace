use async_trait::async_trait;
use futures::prelude::*;
use libp2p::swarm::StreamProtocol;
use std::io;

/// A request-response codec using that sends bytes without extra encoding.
#[derive(Debug, Default, Copy, Clone)]
pub struct NoCodec {}

#[async_trait]
impl libp2p::request_response::Codec for NoCodec {
    type Protocol = StreamProtocol;
    type Request = Vec<u8>;
    type Response = Vec<u8>;

    async fn read_request<T>(&mut self, _: &Self::Protocol, io: &mut T) -> io::Result<Vec<u8>>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut vec = Vec::new();

        let len = io.take(1).read_to_end(&mut vec).await?;

        vec.truncate(len);

        Ok(vec)
    }

    async fn read_response<T>(&mut self, _: &Self::Protocol, io: &mut T) -> io::Result<Vec<u8>>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut vec = Vec::new();

        let len = io.take(1).read_to_end(&mut vec).await?;

        vec.truncate(len);

        Ok(vec)
    }

    async fn write_request<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        request: Vec<u8>,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        io.write_all(&request).await
    }

    async fn write_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        response: Vec<u8>,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        io.write_all(&response).await
    }
}
