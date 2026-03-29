# DNS Tunnel VPN: Server Architecture

The `dnstun-server` is like a switchboard operator. It receives millions of tiny "Where is my mail?" requests (DNS queries), strips off the envelopes, and connects them to the internet.

## 🔄 1. The Reverse Journey (Step-by-Step)

When you send a packet, this is exactly what the server does with it:

1.  **Catch**: It listens on UDP port 53. Every time a DNS request arrives, it catches it.
2.  **Unwrap**: It looks at the domain, e.g., `A.B.C.D.tun.com`.
3.  **Clean**: It strips off the `tun.com` part.
4.  **Rebuild**: It takes `A. B. C. D.` and glues them back together into binary using **Base32**.
5.  **Identify**: It looks at the 20-byte **Header**. It sees who the user is (`Session ID`).
6.  **Forward**: It opens a TCP connection to the website you want (e.g., `google.com`) and writes the data to it.
7.  **Reply**: Any data that comes back from `google.com` is hidden in the **TXT** message reply.

---

## 🎨 2. Visualizing the Response Header (Bit-by-Bit)

Every message the server sends BACK to you has a small 4-byte "Label" attached to it.

```text
[ Session ID (8 bits) ] -> Tells your client which tab/app this is for (0-255).
[ Flags (8 bits) ]      -> [E][S][0][0] [0][0][0][0]
                           |  |
                           |  +--- Has Seq: "Includes a page number"
                           +------ Encoding: "Base64 or Hex"
[ Seq (16 bits) ]       -> The page number (0-65535).
```

---

## 🏗️ 3. QNAME Normalization (The "Cleaning" Stage)

DNS is like reading a long address. We need to find the heart of the message.
Imagine the user sends: `A.B.C.D.tun.com`
1.  **Identify Suffix**: The server knows its domain is `tun.com`.
2.  **Strip labels**: It removes `tun.com`. Now it has `A. B. C. D.`.
3.  **Merge**: It removes the dots. Now it has `ABCD`.
4.  **Decode**: It turns `ABCD` from text into binary.

**If the message is too small (under 20 bytes), the server ignores it; it's probably just a regular DNS request, not us!**

---

## 🗃️ 4. Session ID Mapping (Telling Users Apart)

The server might have 1,000 users at once. To tell them apart, it uses **Session IDs**:
- **8-bit ID**: This is a number from 0 to 255.
- **Mapping**: Each ID is linked to a specific "Internet Socket" (`uv_tcp_t`).
- **Isolation**: Data in `Session 5` is NEVER mixed with `Session 10`. It's like having 256 independent separate phone lines for each user.

---

## 🤝 5. Swarm Discovery (Finding Good Post Offices)

If your local post office (DNS server) is closed or slow, the server helps you find a better one!
1.  **Listen**: Whenever someone connects, the server records their IP.
2.  **Test**: If that IP works well, it adds it to the **Swarm**.
3.  **Sync**: If a user sends a "SYNC" signal, the server sends back a list of 10-20 "Verified Good" DNS servers.
4.  **Result**: The client adds these to its list and gets faster internet!

---

## 🧩 6. Rebuilding Broken Puzzles (FEC Reassembly)

If some pieces of your puzzle get lost in the mail, the server saves the ones it HAS.
- **Buffer**: It stores incoming pieces in a temporary "Waiting Room" (`burst_symbols`).
- **Reassemble**: Once it has enough pieces (even if some are the "Repair Pieces"), it calls the **RaptorQ** library.
- **Result**: The lib reconstructed the data perfectly, and the server sends it to the internet!
**It's like a jigsaw puzzle that fixes itself as soon as you have more than 70% of the pieces.**

---

## 🛠️ 7. Error Handling (SOCKS5 Status Mapping)

When the server fails to connect to the internet, it tells the client:
1.  **ECONNREFUSED** (The website blocked us) -> Sends status code `0x05`.
2.  **ETIMEDOUT** (The website is slow) -> Sends status code `0x04`.
3.  **EAI_NONAME** (The website domain doesn't exist) -> Sends status code `0x04`.

**This ensures the user's browser shows a proper "Cannot Connect" error instead of just hanging forever.**
