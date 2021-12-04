use std::sync::Arc;
use std::time::Duration;

use super::{
    discovery::Discovery,
    overlay_service::{Node, OverlayRequest, OverlayService, RequestDirection},
    types::{
        Accept, ByteList, Content, FindContent, FindNodes, Message, Nodes, Offer, Ping, Pong,
        ProtocolId, Request, Response,
    },
    Enr, U256,
};
use crate::locks::RwLoggingExt;

use crate::utp::utp::{ConnectionKey, UtpListener};
use crate::utp::utp_types::{UtpAccept, UtpMessage, UtpMessageId, UtpStreamState};
use discv5::{
    enr::NodeId,
    kbucket::{Filter, KBucketsTable},
    TalkRequest,
};
use futures::channel::oneshot;
use rocksdb::DB;
use ssz::Encode;
use tokio::sync::{mpsc::UnboundedSender, RwLock};
use tracing::{debug, warn};

pub use super::overlay_service::OverlayRequestError;

/// Configuration parameters for the overlay network.
#[derive(Clone)]
pub struct OverlayConfig {
    pub bucket_pending_timeout: Duration,
    pub max_incoming_per_bucket: usize,
    pub table_filter: Option<Box<dyn Filter<Node>>>,
    pub bucket_filter: Option<Box<dyn Filter<Node>>>,
}

impl Default for OverlayConfig {
    fn default() -> Self {
        Self {
            bucket_pending_timeout: Duration::from_secs(60),
            max_incoming_per_bucket: 16,
            table_filter: None,
            bucket_filter: None,
        }
    }
}

/// Overlay protocol is a layer on top of discv5 that handles all requests from the overlay networks
/// (state, history etc.) and dispatch them to the discv5 protocol TalkReq. Each network should
/// implement the overlay protocol and the overlay protocol is where we can encapsulate the logic for
/// handling common network requests/responses.
#[derive(Clone)]
pub struct OverlayProtocol {
    /// Reference to the underlying discv5 protocol
    pub discovery: Arc<Discovery>,
    // Reference to the database instance
    pub db: Arc<DB>,
    /// The data radius of the local node.
    pub data_radius: Arc<U256>,
    /// The overlay routing table of the local node.
    kbuckets: Arc<RwLock<KBucketsTable<NodeId, Node>>>,
    /// The subnetwork protocol of the overlay.
    protocol: ProtocolId,
    /// A sender to send requests to the OverlayService.
    request_tx: UnboundedSender<OverlayRequest>,
    utp_listener: Arc<RwLock<UtpListener>>,
}

impl OverlayProtocol {
    pub async fn new(
        config: OverlayConfig,
        discovery: Arc<Discovery>,
        utp_listener: Arc<RwLock<UtpListener>>,
        db: Arc<DB>,
        data_radius: U256,
        protocol: ProtocolId,
    ) -> Self {
        let kbuckets = Arc::new(RwLock::new(KBucketsTable::new(
            discovery.local_enr().node_id().into(),
            config.bucket_pending_timeout,
            config.max_incoming_per_bucket,
            config.table_filter,
            config.bucket_filter,
        )));

        let data_radius = Arc::new(data_radius);
        let request_tx = OverlayService::spawn(
            Arc::clone(&discovery),
            Arc::clone(&db),
            Arc::clone(&kbuckets),
            Arc::clone(&data_radius),
            protocol.clone(),
        )
        .await
        .unwrap();

        Self {
            discovery,
            data_radius,
            kbuckets,
            db,
            protocol,
            request_tx,
            utp_listener,
        }
    }

    /// Returns the subnetwork protocol of the overlay protocol.
    pub fn protocol(&self) -> &ProtocolId {
        &self.protocol
    }

    pub async fn local_enr(&self) -> Enr {
        self.discovery.discv5.local_enr()
    }

    /// Returns the data radius of the local node.
    pub async fn data_radius(&self) -> U256 {
        *self.data_radius
    }

    /// Processes a single Discovery v5 TALKREQ message.
    pub async fn process_one_request(
        &self,
        talk_request: &TalkRequest,
    ) -> Result<Response, OverlayRequestError> {
        let request = match Message::from_bytes(talk_request.body()) {
            Ok(Message::Request(request)) => request,
            Ok(_) => return Err(OverlayRequestError::InvalidRequest),
            Err(_) => return Err(OverlayRequestError::DecodeError),
        };
        let direction = RequestDirection::Incoming {
            source: *talk_request.node_id(),
        };

        // Send the request and wait on the response.
        self.send_overlay_request(request, direction).await
    }

    /// Returns a vector of all ENR node IDs of nodes currently contained in the routing table.
    pub async fn table_entries_id(&self) -> Vec<NodeId> {
        self.kbuckets
            .write_with_warn()
            .await
            .iter()
            .map(|entry| *entry.node.key.preimage())
            .collect()
    }

    /// Returns a vector of all the ENRs of nodes currently contained in the routing table.
    pub async fn table_entries_enr(&self) -> Vec<Enr> {
        self.kbuckets
            .write_with_warn()
            .await
            .iter()
            .map(|entry| entry.node.value.enr().clone())
            .collect()
    }

    /// Sends a `Ping` request to `enr`.
    pub async fn send_ping(&self, enr: Enr) -> Result<Pong, OverlayRequestError> {
        // Construct the request.
        let enr_seq = self.discovery.local_enr().seq();
        let data_radius = self.data_radius().await;
        let custom_payload = ByteList::from(data_radius.as_ssz_bytes());
        let request = Ping {
            enr_seq,
            custom_payload,
        };

        let node_id = enr.node_id();
        let direction = RequestDirection::Outgoing { destination: enr };

        // Send the request and wait on the response.
        debug!("Sending {} dest={}", request, node_id);
        match self
            .send_overlay_request(Request::Ping(request), direction)
            .await
        {
            Ok(Response::Pong(pong)) => Ok(pong),
            Ok(_) => Err(OverlayRequestError::InvalidResponse),
            Err(error) => Err(error),
        }
    }

    /// Sends a `FindNodes` request to `enr`.
    pub async fn send_find_nodes(
        &self,
        enr: Enr,
        distances: Vec<u16>,
    ) -> Result<Nodes, OverlayRequestError> {
        // Construct the request.
        let request = FindNodes { distances };
        let direction = RequestDirection::Outgoing { destination: enr };

        // Send the request and wait on the response.
        match self
            .send_overlay_request(Request::FindNodes(request), direction)
            .await
        {
            Ok(Response::Nodes(nodes)) => Ok(nodes),
            Ok(_) => Err(OverlayRequestError::InvalidResponse),
            Err(error) => Err(error),
        }
    }

    /// Sends a `FindContent` request for `content_key` to `enr`.
    pub async fn send_find_content(
        &self,
        enr: Enr,
        content_key: Vec<u8>,
    ) -> Result<Content, OverlayRequestError> {
        // Construct the request.
        let request = FindContent { content_key };
        let direction = RequestDirection::Outgoing { destination: enr };

        // Send the request and wait on the response.
        match self
            .send_overlay_request(Request::FindContent(request), direction)
            .await
        {
            Ok(Response::Content(found_content)) => Ok(found_content),
            Ok(_) => Err(OverlayRequestError::InvalidResponse),
            Err(error) => Err(error),
        }
    }
    /// offer is sent in order to store content to k nodes with radii that contain content-id
    /// offer is also sent to nodes after FindContent (POKE)
    pub async fn send_offer(
        &self,
        content_keys: Vec<Vec<u8>>,
        enr: Enr,
    ) -> Result<Accept, OverlayRequestError> {
        // Construct the request.
        let request = Offer {
            content_keys: content_keys.clone(),
        };
        let direction = RequestDirection::Outgoing {
            destination: enr.clone(),
        };

        // Send the request and wait on the response.
        match self
            .send_overlay_request(Request::Offer(request), direction)
            .await
        {
            Ok(Response::Accept(accept)) => Ok(self
                .process_accept_response(accept, enr, content_keys)
                .await),
            Ok(_) => Err(OverlayRequestError::InvalidResponse),
            Err(error) => Err(error),
        }
    }

    pub async fn process_accept_response(
        &self,
        response: Accept,
        enr: Enr,
        content_keys_offered: Vec<Vec<u8>>,
    ) -> Accept {
        let connection_id = response.connection_id.clone();

        let (tx, mut rx) = mpsc::unbounded_channel::<UtpStreamState>();

        // Add connection_id we will be receiving to the listening list and the
        // response number. The connection_id is + 1 because that is their id
        self.utp_listener
            .write_with_warn()
            .await
            .listening
            .insert(connection_id.clone() + 1, UtpMessageId::OfferAcceptStream);

        self.utp_listener
            .write_with_warn()
            .await
            .connect(connection_id.clone(), enr.node_id(), tx)
            .await;

        // Return to acceptor: the content key and corresponding data
        let mut content_items: Vec<(Vec<u8>, Vec<u8>)> = vec![];

        for (i, key) in response
            .content_keys
            .clone()
            .iter()
            .zip(content_keys_offered.iter())
        {
            if i == true {
                match self.db.get(key.clone()) {
                    Ok(content) => match content {
                        Some(content) => content_items.push((key.clone(), content)),
                        None => {}
                    },
                    // should return some error if content not found
                    Err(_) => {}
                }
            }
        }

        let content_message = UtpAccept {
            message: content_items,
        };

        let utp_listener = self.utp_listener.clone();
        tokio::spawn(async move {
            while let Some(state) = rx.recv().await {
                if state == UtpStreamState::Connected {
                    if let Some(conn) = utp_listener
                        .write_with_warn()
                        .await
                        .utp_connections
                        .get_mut(&ConnectionKey {
                            node_id: enr.node_id(),
                            conn_id_recv: connection_id,
                        })
                    {
                        // send the content to the acceptor over a uTP stream
                        conn.write(&UtpMessage::new(content_message.as_ssz_bytes()).encode()[..])
                            .await;
                    }
                } else if state == UtpStreamState::Finished {
                    if let Some(conn) = utp_listener
                        .write_with_warn()
                        .await
                        .utp_connections
                        .get_mut(&ConnectionKey {
                            node_id: enr.node_id(),
                            conn_id_recv: connection_id,
                        })
                    {
                        conn.send_finalize().await;
                        return;
                    }
                }
            }
        });
        response
    }

    /// Sends a request through the overlay service.
    async fn send_overlay_request(
        &self,
        request: Request,
        direction: RequestDirection,
    ) -> Result<Response, OverlayRequestError> {
        let (tx, rx) = oneshot::channel();
        let overlay_request = OverlayRequest {
            request,
            direction,
            responder: Some(tx),
        };
        if let Err(error) = self.request_tx.send(overlay_request) {
            warn!(
                "Failure sending request over {:?} service channel",
                self.protocol
            );
            return Err(OverlayRequestError::ChannelFailure(error.to_string()));
        }

        // Wait on the response.
        match rx.await {
            Ok(result) => result,
            Err(error) => Err(OverlayRequestError::ChannelFailure(error.to_string())),
        }
    }
}
