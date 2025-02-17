use rand::rng;
use rand::prelude::IndexedRandom;
use base64::engine::general_purpose;
use base64::Engine as _;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use bytes::{Bytes, Buf};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Empty, Full};
use hyper::{Request, Response, Method};
use hyper::body::Incoming;
use reqwest::{Client, Proxy, Url};
use tokio::io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tokio;

const BASIC_AUTH_CREDS: &str = "user:pass";

async fn tunnel<A, B>(
    client: &mut A,
    proxy: &mut B,
    target: &str,
)
where
    A: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    B: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    match copy_bidirectional(client, proxy).await {
        Ok((from_client, from_proxy)) => {
            println!(
                "Tunnel closed for {}: {} bytes from client, {} bytes from proxy",
                target, from_client, from_proxy
            );
        }
        Err(e) => eprintln!("Tunnel error for {}: {}", target, e),
    }
}

async fn proxy_forward(
    req: Request<Incoming>,
    proxy_pool: Arc<Mutex<Vec<String>>>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    // Handle CONNECT requests for HTTPS tunneling.
    if req.method() == Method::CONNECT {
        let target = req
            .uri()
            .authority()
            .map(|a| a.to_string())
            .unwrap_or_default();
        println!("[*] CONNECT request for target: {}", target);

        // Immediately respond 200 OK with a "Connection: close" header.
        let response = Response::builder()
            .status(200)
            .header("Connection", "close")
            .body(
                Empty::<Bytes>::new()
                    .map_err(|e: Infallible| -> hyper::Error { match e {} })
                    .boxed(),
            )
            .unwrap();

        tokio::spawn(async move {
            match hyper::upgrade::on(req).await {
                Ok(upgraded) => {
                    println!("Connection upgraded for target: {}", target);
                    let mut client_io = TokioIo::new(upgraded);

                    // Randomly select a proxy.
                    let proxy_url = {
                        let proxies = proxy_pool.lock().unwrap();
                        proxies.choose(&mut rng()).unwrap().clone()
                    };
                    let parsed_proxy = Url::parse(&proxy_url).expect("Invalid proxy URL");
                    let proxy_host = parsed_proxy.host_str().expect("Proxy missing host");
                    let proxy_port = parsed_proxy.port().unwrap_or(80);
                    let proxy_addr = format!("{}:{}", proxy_host, proxy_port);
                    println!("[*] Using proxy: {}", proxy_addr);

                    // Build basic auth header value.
                    let credentials = BASIC_AUTH_CREDS;
                    let encoded = general_purpose::STANDARD.encode(credentials);

                    let connect_cmd = format!(
                        "CONNECT {} HTTP/1.1\r\nHost: {}\r\nProxy-Authorization: Basic {}\r\nConnection: close\r\n\r\n",
                        target, target, encoded
                    );

                    match tokio::net::TcpStream::connect(proxy_addr).await {
                        Ok(mut proxy_stream) => {
                            if let Err(e) = proxy_stream.write_all(connect_cmd.as_bytes()).await {
                                eprintln!("Error sending CONNECT command: {}", e);
                                return;
                            }
                            let mut buf = [0u8; 1024];
                            match proxy_stream.read(&mut buf).await {
                                Ok(n) => {
                                    let resp_str = String::from_utf8_lossy(&buf[..n]);
                                    if !resp_str.starts_with("HTTP/1.1 200") && !resp_str.starts_with("HTTP/1.0 200") {
                                        eprintln!("Proxy CONNECT failed: {}", resp_str);
                                        return;
                                    }
                                }
                                Err(e) => {
                                    eprintln!("Error reading proxy response: {}", e);
                                    return;
                                }
                            }
                            tunnel(&mut client_io, &mut proxy_stream, &target).await;
                        }
                        Err(e) => {
                            eprintln!("Error connecting to proxy: {}", e);
                        }
                    }
                }
                Err(e) => eprintln!("Upgrade error: {}", e),
            }
        });
        return Ok(response);
    }

    // For non-CONNECT requests:
    let raw_url = req.uri().to_string();
    let url = if raw_url.contains("://") {
        raw_url
    } else {
        format!("https://{}", raw_url)
    };
    println!("[*] Shuttling {}", url);

    let method = req.method().clone();
    let headers = req.headers().clone();

    // Fully buffer the incoming body.
    let full_body = match req.into_body().collect().await {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Error collecting request body: {}", e);
            return Ok(Response::builder()
                .status(502)
                .header("Connection", "close")
                .body(
                    Empty::<Bytes>::new()
                        .map_err(|e: Infallible| -> hyper::Error { match e {} })
                        .boxed(),
                )
                .unwrap());
        }
    };
    let mut aggregated = full_body.aggregate();
    let mut vec = Vec::with_capacity(aggregated.remaining());
    while aggregated.has_remaining() {
        let chunk = aggregated.chunk();
        vec.extend_from_slice(chunk);
        aggregated.advance(chunk.len());
    }
    let body_bytes = Bytes::from(vec);

    // Randomly select a proxy.
    let proxy_url = {
        let proxies = proxy_pool.lock().unwrap();
        proxies.choose(&mut rng()).unwrap().clone()
    };

    // Build a reqwest client using the selected proxy.
    let client = match Client::builder()
        .danger_accept_invalid_certs(true)
        .proxy(Proxy::all(&proxy_url).unwrap().basic_auth("blackh4t", "ywHBjeWr"))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error building reqwest client: {}", e);
            return Ok(Response::builder()
                .status(502)
                .header("Connection", "close")
                .body(
                    Empty::<Bytes>::new()
                        .map_err(|e: Infallible| -> hyper::Error { match e {} })
                        .boxed(),
                )
                .unwrap());
        }
    };

    // Build a reqwest request that mirrors the incoming one.
    let mut req_builder = client.request(method, &url);
    for (key, value) in headers.iter() {
        req_builder = req_builder.header(key, value);
    }
    if !body_bytes.is_empty() {
        req_builder = req_builder.body(body_bytes);
    }

    let response = match req_builder.send().await {
        Ok(resp) => resp,
        Err(e) => {
            eprintln!("Error forwarding request: {}", e);
            return Ok(Response::builder()
                .status(502)
                .header("Connection", "close")
                .body(
                    Empty::<Bytes>::new()
                        .map_err(|e: Infallible| -> hyper::Error { match e {} })
                        .boxed(),
                )
                .unwrap());
        }
    };

    let status = response.status();
    let resp_headers = response.headers().clone();
    let resp_bytes = match response.bytes().await {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Error reading response body: {}", e);
            return Ok(Response::builder()
                .status(502)
                .header("Connection", "close")
                .body(
                    Empty::<Bytes>::new()
                        .map_err(|e: Infallible| -> hyper::Error { match e {} })
                        .boxed(),
                )
                .unwrap());
        }
    };

    let mut response_builder = Response::builder().status(status);
    for (key, value) in resp_headers.iter() {
        response_builder = response_builder.header(key, value);
    }
    // Force connection closure.
    response_builder = response_builder.header("Connection", "close");

    let resp = response_builder
        .body(
            Full::new(resp_bytes)
                .map_err(|e: Infallible| -> hyper::Error { match e {} })
                .boxed(),
        )
        .unwrap();
    Ok(resp)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Define your list of proxies (using "http://" since your proxies are HTTP).
    let proxies = vec![
        "http://1.2.3.4:8080".to_string(),
        "https://8.9.10.11:8080".to_string(),
    ];
    let proxy_pool = Arc::new(Mutex::new(proxies));

    // Bind a TcpListener on localhost:8081.
    let addr = SocketAddr::from(([127, 0, 0, 1], 8081));
    let listener = TcpListener::bind(addr).await?;
    println!("Proxy rotator (HTTP/1.1) running at http://{}", addr);

    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);
        let proxy_pool = Arc::clone(&proxy_pool);
        tokio::spawn(async move {
            let service = service_fn(move |req: Request<Incoming>| {
                let proxy_pool = Arc::clone(&proxy_pool);
                proxy_forward(req, proxy_pool)
            });
            if let Err(err) = http1::Builder::new()
                .serve_connection(io, service)
                .with_upgrades()
                .await
            {
                eprintln!("Error serving connection: {:?}", err);
            }
        });
    }
}
