use super::*;

fn active_pair(destination: &SingleInputDestination) -> (Link, Link) {
    let (events, _) = broadcast::channel(16);
    let mut caller = Link::new(destination.desc, events.clone());
    let request = caller.request();
    let mut receiver = Link::new_from_request(
        &request,
        destination.sign_key().clone(),
        destination.desc,
        events,
    )
    .unwrap();
    assert!(matches!(
        caller.handle_packet(&receiver.prove(), true),
        LinkHandleResult::Activated
    ));
    (caller, receiver)
}

#[tokio::test]
async fn forged_announces_do_not_allocate_remote_state() {
    let transport = TransportConfig::default().build();
    let handler = transport.get_handler();
    for index in 0u64..2048 {
        let mut packet = Packet::default();
        packet.header.packet_type = PacketType::Announce;
        let mut hash = [0; 16];
        hash[..8].copy_from_slice(&index.to_be_bytes());
        packet.destination = AddressHash::new(hash);
        handle_announce(&packet, handler.lock().await, AddressHash::new([1; 16])).await;
    }
    let handler = handler.lock().await;
    assert_eq!(
        handler.announce_limits.len(),
        0,
        "forged identities must not allocate rate-limit entries"
    );
    assert!(handler.single_out_destinations.is_empty());
    assert_eq!(handler.path_table.len(), 0);
}

#[tokio::test]
async fn signed_announces_have_bounded_remote_metadata() {
    let transport = TransportConfig::default().build();
    let handler = transport.get_handler();
    let identity = PrivateIdentity::new_from_rand(OsRng);
    let protected =
        SingleInputDestination::new(identity.clone(), DestinationName::new("epix", "protected"));
    let packet = protected.announce(OsRng, None).unwrap();
    handle_announce(&packet, handler.lock().await, AddressHash::new([1; 16])).await;
    let (caller, receiver) = active_pair(&protected);
    let retained = Arc::new(Mutex::new(caller));
    handler
        .lock()
        .await
        .out_links
        .insert(protected.desc.address_hash, retained.clone());
    for index in 0..1050 {
        let destination = SingleInputDestination::new(
            identity.clone(),
            DestinationName::new("epix", &format!("bounded-{index}")),
        );
        let packet = destination.announce(OsRng, None).unwrap();
        handle_announce(&packet, handler.lock().await, AddressHash::new([1; 16])).await;
    }
    let mut handler = handler.lock().await;
    assert!(
        handler.single_out_destinations.len() <= 1024,
        "remote descriptors cannot grow with each new signed identity"
    );
    assert!(handler.announce_limits.len() <= 1024);
    assert!(handler.path_table.len() <= 1024);
    assert!(handler
        .single_out_destinations
        .contains_key(&protected.desc.address_hash));
    assert!(handler
        .path_table
        .get(&protected.desc.address_hash)
        .is_some());
    let packet = retained
        .lock()
        .await
        .data_packet(b"active link survives cache pressure")
        .unwrap();
    let mut plaintext = [0; crate::packet::PACKET_MDU];
    assert_eq!(
        receiver
            .decrypt(packet.data.as_slice(), &mut plaintext)
            .unwrap(),
        b"active link survives cache pressure"
    );
    let expired = time::Instant::now() + REMOTE_DESTINATION_TTL + Duration::from_secs(1);
    handler.prune_remote_destinations(expired).await;
    assert_eq!(
        handler.single_out_destinations.len(),
        1,
        "live destination stays pinned past TTL"
    );
    handler.out_links.clear();
    handler.prune_remote_destinations(expired).await;
    assert!(handler.single_out_destinations.is_empty());
    assert_eq!(handler.path_table.len(), 0);
    assert_eq!(handler.announce_limits.len(), 0);
    assert!(!handler
        .announce_table
        .contains_destination(&protected.desc.address_hash));
}

#[tokio::test]
async fn incoming_link_admission_reclaims_closed_slots_without_evicting_active_links() {
    let transport = TransportConfig::default().build();
    let destination = SingleInputDestination::new(
        PrivateIdentity::new_from_rand(OsRng),
        DestinationName::new("epix", "bounded-link"),
    );
    let (active, receiver) = active_pair(&destination);
    let id = *active.id();
    let active = Arc::new(Mutex::new(active));
    let handler = transport.get_handler();
    let mut handler = handler.lock().await;
    handler.in_links.insert(id, active.clone());
    let (events, _) = broadcast::channel(16);
    let mut closed_id = None;
    for index in 0..MAX_LOGICAL_LINKS - 1 {
        let mut bytes = [0; 16];
        bytes[..8].copy_from_slice(&(index as u64).to_be_bytes());
        let key = AddressHash::new(bytes);
        handler.in_links.insert(
            key,
            Arc::new(Mutex::new(Link::new(destination.desc, events.clone()))),
        );
        closed_id = Some(key);
    }
    let new_id = AddressHash::new([255; 16]);
    assert!(!handler.admit_incoming_link(&new_id).await);
    assert!(
        handler.admit_incoming_link(&id).await,
        "existing link is never evicted"
    );
    handler.in_links[&closed_id.unwrap()].lock().await.close();
    assert!(handler.admit_incoming_link(&new_id).await);
    assert_eq!(handler.in_links.len(), MAX_LOGICAL_LINKS - 1);
    assert!(Arc::ptr_eq(&handler.in_links[&id], &active));
    let packet = active
        .lock()
        .await
        .data_packet(b"retained authenticated link")
        .unwrap();
    assert_eq!(
        receiver
            .decrypt(packet.data.as_slice(), &mut [0; crate::packet::PACKET_MDU])
            .unwrap(),
        b"retained authenticated link"
    );
}

#[tokio::test]
async fn empty_keepalive_on_unknown_link_is_ignored_without_panicking() {
    let transport = TransportConfig::default().build();
    let handler = transport.get_handler();
    let mut packet = Packet::default();
    packet.header.destination_type = DestinationType::Link;
    packet.context = PacketContext::KeepAlive;
    handle_data(&packet, handler.lock().await).await;
    assert!(handler.lock().await.in_links.is_empty());
}

#[tokio::test]
async fn invalid_encrypted_rtt_does_not_panic_or_change_link_timing() {
    let destination = SingleInputDestination::new(
        PrivateIdentity::new_from_rand(OsRng),
        DestinationName::new("epix", "rtt"),
    );
    let (caller, mut receiver) = active_pair(&destination);
    for rtt in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, -1.0, f64::MAX] {
        let mut data = Vec::new();
        rmp::encode::write_f64(&mut data, rtt).unwrap();
        let mut packet = caller.data_packet(&data).unwrap();
        packet.context = PacketContext::LinkRTT;
        let previous = *receiver.rtt();
        receiver.handle_packet(&packet, false);
        assert_eq!(*receiver.rtt(), previous);
    }
    let mut data = Vec::new();
    rmp::encode::write_f64(&mut data, 0.125).unwrap();
    let mut packet = caller.data_packet(&data).unwrap();
    packet.context = PacketContext::LinkRTT;
    receiver.handle_packet(&packet, false);
    assert_eq!(*receiver.rtt(), Duration::from_millis(125));
    assert_eq!(receiver.status(), LinkStatus::Active);
}

#[tokio::test]
async fn signed_announcement_cannot_claim_another_destination() {
    let destination = SingleInputDestination::new(
        PrivateIdentity::new_from_rand(OsRng),
        DestinationName::new("epix", "address-binding"),
    );
    let mut packet = destination.announce(OsRng, Some(b"fixture")).unwrap();
    let (validated, app) = DestinationAnnounce::validate(&packet).unwrap();
    assert_eq!(validated.desc.address_hash, destination.desc.address_hash);
    assert_eq!(app, b"fixture");
    // Sign the substituted address with the attacker's real key. This is not
    // merely an invalid signature: identity/name must bind the claimed address.
    packet.destination = AddressHash::new([99; 16]);
    let signature_offset = 2 * crate::identity::PUBLIC_KEY_LENGTH
        + crate::destination::NAME_HASH_LENGTH
        + crate::destination::RAND_HASH_LENGTH;
    let data = packet.data.as_slice();
    let mut signed = packet.destination.as_slice().to_vec();
    signed.extend_from_slice(&data[..signature_offset]);
    signed.extend_from_slice(&data[signature_offset + 64..]);
    let signature = destination.identity.sign(&signed).to_bytes();
    let mut forged = data.to_vec();
    forged[signature_offset..signature_offset + 64].copy_from_slice(&signature);
    packet.data = PacketDataBuffer::new_from_slice(&forged);
    assert!(DestinationAnnounce::validate(&packet).is_err());
    let transport = TransportConfig::default().build();
    let handler = transport.get_handler();
    handle_announce(&packet, handler.lock().await, AddressHash::new([1; 16])).await;
    let handler = handler.lock().await;
    assert_eq!(handler.announce_limits.len(), 0);
    assert!(handler.single_out_destinations.is_empty());
    assert_eq!(handler.path_table.len(), 0);
}

#[tokio::test]
async fn cyclic_path_request_keeps_tag_and_stops_after_one_visit_per_node() {
    let mut nodes = Vec::new();
    let mut outputs = Vec::new();
    for _ in 0..3 {
        let transport = TransportConfig::default().build();
        let output = transport.iface_manager().lock().await.new_channel(16);
        nodes.push(transport);
        outputs.push(output);
    }
    let mut requests = PathRequests::new("origin", None);
    let tag = vec![42; 16];
    let mut packet = requests.generate(&AddressHash::new([7; 16]), Some(tag.clone()));
    for visit in 0..3 {
        let handler = nodes[visit].get_handler();
        handle_path_request(
            &packet,
            &mut handler.lock().await,
            AddressHash::new([255; 16]),
        )
        .await;
        packet = outputs[visit]
            .tx_channel
            .try_recv()
            .expect("one relay per new request")
            .packet;
        let mut observer = PathRequests::new("observer", None);
        assert_eq!(
            observer.decode(packet.data.as_slice()).unwrap().tag_bytes,
            tag
        );
        assert_eq!(packet.header.hops, (visit + 1) as u8);
    }
    let handler = nodes[0].get_handler();
    handle_path_request(
        &packet,
        &mut handler.lock().await,
        AddressHash::new([255; 16]),
    )
    .await;
    assert!(
        outputs[0].tx_channel.try_recv().is_err(),
        "cycle must terminate at the previously visited node"
    );
    for node in nodes {
        node.shutdown();
    }
}
