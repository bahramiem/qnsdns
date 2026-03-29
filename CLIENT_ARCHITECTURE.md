# DNS Tunnel VPN: Client Architecture

The `dnstun-client` is like a secret postal service. It takes your internet mail (TCP packets), breaks them into tiny pieces, hides them in a bunch of different envelopes (DNS queries), and sends them all at once through different post offices (DNS resolvers).

## 🚀 1. The Life of a Packet (Step-by-Step)

Imagine you open a website. Here is exactly how one packet travels:

1.  **Intercept**: Your browser sends a packet to the SOCKS5 proxy on your computer.
2.  **Chop**: The client chops the packet into tiny pieces (Symbols) of about 110 bytes.
3.  **Label**: A 20-byte **Header** is stuck to each piece. This header tells the server which "mailbox" (Session ID) the piece belongs to and which number it is in the "pile" (Sequence Number).
4.  **Hide**: The binary piece is turned into text using **Base32** (like converting a photo into code).
5.  **Address**: The text is put into a domain name, like `A.B.C.D.tun.com`.
6.  **Blast**: The client sends 10 different pieces to 10 different DNS servers simultaneously (Multipath).
7.  **Reply**: The DNS server replies with a **TXT** message. The client opens it, decodes it, and puts the result back together to show you the website.

---

## 🎨 2. Visualizing the Headers (Bit-by-Bit)

Every piece of data starts with a "Label" (Header). Here is what it looks like inside:

### Upstream Data Header (`chunk_header_t` - 20 Bytes)
This header is attached to every piece you **UPLOADS**.

```text
[ Session ID (8 bits) ] -> Tells the server who you are (0-255).
[ Flags (8 bits) ]      -> [E][C][F][P] [0][0][0][0]
                           |  |  |  |
                           |  |  |  +-- Poll: "Checking for mail"
                           |  |  +----- FEC: "Repairable puzzle"
                           |  +-------- Compressed: "Zstd-zipped"
                           +----------- Encrypted: "Secret"
[ Seq (16 bits) ]       -> The # of this piece (0-65535).
[ Info (32 bits) ]      -> Total pieces and error correction settings.
[ OTI (96 bits) ]       -> Deep technical stuff for rebuilding broken puzzles.
```

### Handshake Header (`handshake_packet_t` - 5 Bytes)
Sent only once when you first connect.

```text
[ Ver (8 bits) ]        -> Version 1.
[ Up MTU (16 bits) ]    -> How big the envelopes can be for upload.
[ Down MTU (16 bits) ]  -> How big the envelopes can be for download.
```

---

## 🧩 3. The 10-Envelope Trick (Scatter-Gather)

Normally, you send mail one by one. If one post office is slow, your mail is delayed.
We use **Multipath**:
- We send piece #1 to Google's DNS (`8.8.8.8`).
- **Concurrent BLAST**: We don't wait for #1 to finish before sending #2.
- **Winner Takes All**: The client dynamically shifts more traffic to the "Winning" (fastest) resolvers.

---

## 🛠️ 4. Forward Error Correction (The Puzzle Logic)

Imagine you send a 10-piece puzzle. If 1 piece gets lost in the mail, you can't see the picture.
With **FEC (Forward Error Correction)**:
1.  We send the 10 pieces of the puzzle.
2.  We send 5 "Repair Pieces" (Extra symbols).
3.  Even if 5 random pieces are lost, the server can use the remaining 10 to perfectly rebuild the original picture.
**It's like having a puzzle that heals itself!**

---

## 🏎️ 5. Driving a Car (AIMD Congestion Control)

How do we decide how fast to send pieces? We use a method called **AIMD**:
- **Speed Up (Additive Increase)**: Every time we get a reply back successfully, we drive slightly faster (+1).
- **Hard Brake (Multiplicative Decrease)**: The moment we lose one piece, we slam the brakes and cut our speed in **HALF** (-50%).
This ensures we go as fast as possible without crashing the network.

---

## 🤝 6. The First Meeting (Handshake Flow)

Before data flows, the client and server must "shake hands":
1.  **Client**: "Hi, I'm Version 1. My envelopes can hold 110 bytes. Can you reply with 220 bytes?"
2.  **Server**: "Got it. I'll remember your settings for this session."
3.  **Client**: Starts sending the actual website request.

---

## 💬 7. SOCKS5 Status Codes (Simple Guide)

Sometimes things go wrong. The client will tell you why:
- `0x00`: **Success!** You are connected.
- `0x01`: **General Fail.** The server is confused.
- `0x04`: **Host Unreachable.** The website you want is down.
- `0x05`: **Connection Refused.** The website blocked our tunnel.

---

## 📥 8. How We Get Data Back (The POLL)

DNS servers aren't allowed to call YOU. You must call THEM.
To get data back (Downstream):
1.  Your client sends a "Checking for mail" query (POLL).
2.  The server checks if it has anything for your `Session ID`.
3.  If it does, it hides the website data in the **TXT** record reply.
4.  If not, it sends an empty reply.
**It's like constantly checking your mailbox instead of waiting for a delivery truck.**

---

## ⌨️ 9. The Remote Control (TUI Keys)

- `1`: **Stats Panel**: See your speed (KB/s).
- `2`: **Resolver Pool**: See which DNS servers are slow (High RTT).
- `3`: **Settings**: Toggle encryption or jitter on the fly.
- `m`: **Change Domain**: Quickly switch tunnel domains.
