# et-kotlin

Pure Kotlin implementation of the client-side [Eternal Terminal](https://eternalterminal.dev) (ET) protocol for Android and JVM.

ET is a remote shell that automatically reconnects without interrupting the session. It survives IP roaming, laptop sleep, and other connection loss events. This library implements the encrypted TCP transport — SSH bootstrapping and terminal emulation are the caller's responsibility.

## What it does

- **XSalsa20-Poly1305 encryption** — compatible with libsodium's `crypto_secretbox` (via Bouncy Castle, no native dependencies)
- **ET wire protocol** — handshake (ConnectRequest/ConnectResponse), encrypted data framing, terminal buffer and resize packets
- **Hand-coded protobuf** — no protobuf compiler or runtime dependency; the small subset of ET proto messages is encoded/decoded directly
- **Coroutine-based I/O** — non-blocking read/write loops using Kotlin coroutines
- **Keepalive** — automatically responds to server heartbeat packets

## What it doesn't do

- SSH bootstrapping (exec `etterminal` on the remote host to get session credentials)
- Terminal emulation (feed the output bytes into your terminal library)
- Session recovery on reconnect (TODO — currently only new sessions are supported)
- Server implementation

## Usage

```kotlin
// 1. Bootstrap via SSH (your SSH library)
//    Run: echo '<id>/<passkey>_xterm-256color' | etterminal
//    Parse stdout for: IDPASSKEY:<16-char-id>/<32-char-passkey>
val clientId = "abcdefghijklmnop"  // 16 chars from etterminal
val passkey  = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef"  // 32 chars from etterminal

// 2. Create transport
val transport = EtTransport(
    serverHost = "192.168.1.100",
    port = 2022,
    clientId = clientId,
    passkey = passkey,
    onOutput = { data, offset, length ->
        // Feed to terminal emulator
        emulator.write(data, offset, length)
    },
    onDisconnect = { clean ->
        println("Disconnected (clean=$clean)")
    },
    logger = StdEtLogger,  // or implement EtLogger
)

// 3. Start (connects TCP, handshakes, enters read loop)
transport.start(coroutineScope)

// 4. Send keyboard input
transport.sendInput("ls -la\n".toByteArray())

// 5. Handle terminal resize
transport.resize(cols = 120, rows = 40)

// 6. Clean up
transport.close()
```

## SSH Bootstrap

ET authenticates by piggybacking on SSH. The client SSHs to the server and pipes credentials to `etterminal`:

```
ssh user@host "echo 'XXXrandomid12345/randompasskey32charslong1234567_xterm-256color' | etterminal"
```

`etterminal` registers the session with the running `etserver` daemon and prints:

```
IDPASSKEY:<16-char-id>/<32-char-passkey>
```

The `XXX` prefix on the proposed ID signals a new client — the server regenerates both ID and passkey. Parse the `IDPASSKEY:` line from stdout to get the actual credentials.

## Architecture

```
EtTransport
├── EtCrypto (XSalsa20-Poly1305)
│   ├── Writer: nonce MSB = 0 (client → server)
│   └── Reader: nonce MSB = 1 (server → client)
└── EtProtocol (wire format)
    ├── Handshake: 8-byte LE length + protobuf
    └── Data: 4-byte BE length + [enc][header][payload]
```

## Protocol Details

| Phase | Format | Encryption |
|-------|--------|------------|
| ConnectRequest/Response | 8-byte LE length + protobuf | None |
| InitialPayload/Response | 4-byte BE length + packet | XSalsa20-Poly1305 |
| Terminal data | 4-byte BE length + packet | XSalsa20-Poly1305 |
| Keepalive | 4-byte BE length + packet | XSalsa20-Poly1305 |

Packet format: `[1 byte encrypted flag][1 byte header][encrypted payload with 16-byte MAC]`

Header values: `0` = keepalive, `1` = terminal buffer, `2` = terminal info, `252` = initial response, `253` = initial payload.

## Building

```bash
./gradlew build
./gradlew test
```

## Integration with Gradle

As a composite build (for app development):

```kotlin
// settings.gradle.kts
includeBuild("et-kotlin") {
    dependencySubstitution {
        substitute(module("sh.haven:et-transport")).using(project(":"))
    }
}
```

Then depend on it:

```kotlin
// build.gradle.kts
dependencies {
    implementation("sh.haven:et-transport:0.1.0")
}
```

## License

GPLv3. Protocol implementation based on [Eternal Terminal](https://github.com/MisterTea/EternalTerminal) by Jason Gauci.

Extracted from [Haven](https://github.com/GlassOnTin/Haven), an Android SSH client.
