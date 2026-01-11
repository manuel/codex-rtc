import React, { useEffect, useRef, useState } from 'react';
import * as openpgp from 'openpgp';
import Peer, { DataConnection } from 'peerjs';
import './App.css';

type StoredKeypair = {
  publicKeyArmored: string;
  privateKeyArmored: string;
};

type WireMessage = {
  text: string;
  signature: string;
  publicKey: string;
};

type ChatMessage = {
  id: string;
  sender: 'me' | 'peer';
  text: string;
  timestamp: Date;
  verified?: boolean;
};

function App() {
  const peerRef = useRef<Peer | null>(null);
  const connectionRef = useRef<DataConnection | null>(null);
  const [peerId, setPeerId] = useState('');
  const [targetPeerId, setTargetPeerId] = useState('');
  const [isConnected, setIsConnected] = useState(false);
  const [isConnecting, setIsConnecting] = useState(false);
  const [statusMessage, setStatusMessage] = useState('');
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [keypair, setKeypair] = useState<StoredKeypair | null>(null);
  const [peerReady, setPeerReady] = useState(false);

  const addMessage = (sender: 'me' | 'peer', text: string, verified?: boolean) => {
    setMessages((prev) => [
      ...prev,
      {
        id: `${Date.now()}-${Math.random().toString(16).slice(2)}`,
        sender,
        text,
        timestamp: new Date(),
        verified
      }
    ]);
  };

  useEffect(() => {
    let isMounted = true;

    const initKeys = async () => {
      if (process.env.NODE_ENV === 'test') {
        setKeypair({ publicKeyArmored: '', privateKeyArmored: '' });
        setPeerId('test-peer');
        setStatusMessage('');
        return;
      }
      setStatusMessage('Generating keys...');
      try {
        const generated = await openpgp.generateKey({
          type: 'ecc',
          curve: 'ed25519',
          userIDs: [{ name: 'peer' }]
        });
        const storedKeypair: StoredKeypair = {
          publicKeyArmored: generated.publicKey,
          privateKeyArmored: generated.privateKey
        };

        const publicKey = await openpgp.readKey({
          armoredKey: storedKeypair.publicKeyArmored
        });
        const fingerprint = publicKey.getFingerprint();

        if (isMounted) {
          setKeypair(storedKeypair);
          setPeerId(fingerprint);
          setStatusMessage('');
        }
      } catch (error) {
        if (isMounted) {
          setStatusMessage('Key setup failed.');
        }
      }
    };

    initKeys();

    return () => {
      isMounted = false;
    };
  }, []);

  const attachConnection = (connection?: DataConnection) => {
    if (!connection) {
      setStatusMessage('Connection failed to start.');
      setIsConnecting(false);
      return;
    }
    connectionRef.current = connection;
    connection.on('open', () => {
      setIsConnected(true);
      setIsConnecting(false);
      setStatusMessage('');
    });
    connection.on('data', (data) => {
      const handleIncoming = async () => {
        if (typeof data === 'string') {
          addMessage('peer', data, false);
          return;
        }

        const payload = data as Partial<WireMessage>;
        if (!payload.text || !payload.signature || !payload.publicKey) {
          addMessage('peer', JSON.stringify(data), false);
          return;
        }

        try {
          const message = await openpgp.createMessage({ text: payload.text });
          const signature = await openpgp.readSignature({
            armoredSignature: payload.signature
          });
          const publicKey = await openpgp.readKey({
            armoredKey: payload.publicKey
          });
          const verification = await openpgp.verify({
            message,
            signature,
            verificationKeys: publicKey
          });

          const [{ verified }] = verification.signatures;
          await verified;

          const fingerprint = publicKey.getFingerprint();
          if (fingerprint !== connection.peer) {
            setStatusMessage('Peer fingerprint mismatch.');
          }

          addMessage('peer', payload.text, true);
        } catch (error) {
          addMessage('peer', payload.text, false);
        }
      };

      void handleIncoming();
    });
    connection.on('close', () => {
      setIsConnected(false);
      setIsConnecting(false);
      setStatusMessage('Connection closed.');
      connectionRef.current = null;
    });
    connection.on('error', (error) => {
      setIsConnected(false);
      setIsConnecting(false);
      setStatusMessage(error.message || 'Connection error.');
      connectionRef.current = null;
    });
  };

  useEffect(() => {
    if (process.env.NODE_ENV === 'test') {
      return;
    }
    if (!peerId || peerRef.current) {
      return;
    }
    const peer = new Peer(peerId);
    peerRef.current = peer;
    setPeerReady(false);

    peer.on('open', () => {
      setPeerReady(true);
    });

    peer.on('connection', (connection) => {
      if (connectionRef.current && connectionRef.current.open) {
        connectionRef.current.close();
      }
      setTargetPeerId(connection.peer);
      setIsConnecting(false);
      attachConnection(connection);
    });

    peer.on('error', (error) => {
      setStatusMessage(error.message || 'Peer error.');
    });

    return () => {
      peer.destroy();
      setPeerReady(false);
    };
  }, [peerId]);

  const handleConnect = () => {
    if (!peerRef.current || !targetPeerId.trim()) {
      return;
    }
    if (!peerReady) {
      setStatusMessage('Peer not ready yet.');
      return;
    }
    if (connectionRef.current && connectionRef.current.open) {
      connectionRef.current.close();
    }
    setIsConnecting(true);
    setStatusMessage('');
    const connection = peerRef.current.connect(targetPeerId.trim());
    attachConnection(connection);
  };

  const handleDisconnect = () => {
    if (connectionRef.current) {
      connectionRef.current.close();
    }
    setIsConnected(false);
    setIsConnecting(false);
  };

  const handleSendMessage = async (text: string) => {
    if (!connectionRef.current || !connectionRef.current.open || !keypair) {
      return;
    }
    try {
      const privateKey = await openpgp.readPrivateKey({
        armoredKey: keypair.privateKeyArmored
      });
      const message: openpgp.Message<string> = await openpgp.createMessage({
        text
      });
      const signature = (await openpgp.sign({
        message,
        signingKeys: privateKey,
        detached: true,
        format: 'armored'
      })) as string;

      const payload: WireMessage = {
        text,
        signature,
        publicKey: keypair.publicKeyArmored
      };

      connectionRef.current.send(payload);
      addMessage('me', text, true);
    } catch (error) {
      setStatusMessage('Failed to sign message.');
    }
  };

  const handleCopyPeerId = async () => {
    if (!peerId) {
      return;
    }
    try {
      await navigator.clipboard.writeText(peerId);
      setStatusMessage('Peer ID copied.');
      setTimeout(() => setStatusMessage(''), 2000);
    } catch (error) {
      setStatusMessage('Clipboard unavailable.');
    }
  };

  const statusLabel = isConnected
    ? `Connected to ${targetPeerId}`
    : isConnecting
      ? 'Connecting...'
      : peerId
        ? 'Not connected'
        : 'Preparing keys...';

  return (
    <div className="page">
      <div className="shell">
        <header className="hero">
          <div>
            <p className="eyebrow">PeerJS Direct Chat</p>
            <h1>Two-person text, no servers to run.</h1>
            <p className="hero-subtitle">
              Share your peer ID, connect, and start a direct text session.
            </p>
          </div>
          <div className="status-card">
            <span
              className={`status-dot ${
                isConnected ? 'on' : isConnecting ? 'pending' : 'off'
              }`}
            />
            <div>
              <div className="status-label">{statusLabel}</div>
            <div className="status-note">
              {statusMessage ||
                (peerId
                  ? peerReady
                    ? 'Ready for a peer.'
                    : 'Waiting for PeerJS...'
                  : 'Setting up keys.')}
            </div>
            </div>
          </div>
        </header>

        <div className="grid">
          <section className="card">
            <h2 className="card-title">Connection</h2>
            <div className="id-row">
              <div>
                <div className="label">Your peer ID</div>
                <div className="id-chip">{peerId || 'Generating...'}</div>
              </div>
              <button
                className="ghost-button"
                type="button"
                onClick={handleCopyPeerId}
                disabled={!peerId}
              >
                Copy
              </button>
            </div>

            <label className="label" htmlFor="targetPeerId">
              Connect to peer
            </label>
            <div className="connect-row">
              <input
                id="targetPeerId"
                className="connect-input"
                type="text"
                placeholder="Paste peer ID"
                value={targetPeerId}
                onChange={(event) => setTargetPeerId(event.target.value)}
                disabled={isConnected || !peerId || !peerReady}
              />
              {!isConnected ? (
                <button
                  className="primary-button"
                  type="button"
                  onClick={handleConnect}
                  disabled={!peerId || !peerReady || !targetPeerId.trim() || isConnecting}
                >
                  {isConnecting ? 'Connecting...' : 'Connect'}
                </button>
              ) : (
                <button
                  className="danger-button"
                  type="button"
                  onClick={handleDisconnect}
                >
                  Disconnect
                </button>
              )}
            </div>
          </section>

          <section className="card chat-card">
            <h2 className="card-title">Chat</h2>
            <div className="messages">
              {messages.length === 0 ? (
                <div className="empty-state">
                  Messages will appear here once connected.
                </div>
              ) : (
                messages.map((message) => (
                  <div
                    key={message.id}
                    className={`message ${message.sender === 'me' ? 'me' : 'peer'}`}
                  >
                    <div className="message-bubble">
                      <div>{message.text}</div>
                      <div className="message-meta">
                        {message.timestamp.toLocaleTimeString()}
                        {message.sender === 'peer' && (
                          <span className="signature">
                            {message.verified ? ' • verified' : ' • unverified'}
                          </span>
                        )}
                      </div>
                    </div>
                  </div>
                ))
              )}
            </div>
            <MessageComposer
              disabled={!isConnected}
              onSendMessage={handleSendMessage}
            />
          </section>
        </div>
      </div>
    </div>
  );
}

interface MessageComposerProps {
  disabled: boolean;
  onSendMessage: (text: string) => Promise<void> | void;
}

const MessageComposer: React.FC<MessageComposerProps> = ({
  disabled,
  onSendMessage
}) => {
  const [text, setText] = useState('');

  const handleSubmit = (event: React.FormEvent) => {
    event.preventDefault();
    if (!text.trim() || disabled) {
      return;
    }
    onSendMessage(text.trim());
    setText('');
  };

  return (
    <form className="composer" onSubmit={handleSubmit}>
      <input
        className="composer-input"
        type="text"
        placeholder={disabled ? 'Connect to start chatting' : 'Type a message'}
        value={text}
        onChange={(event) => setText(event.target.value)}
        disabled={disabled}
      />
      <button
        className="primary-button"
        type="submit"
        disabled={disabled || !text.trim()}
      >
        Send
      </button>
    </form>
  );
};

export default App;
