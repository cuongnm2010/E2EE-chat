package client;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.whispersystems.libsignal.IdentityKey;
import org.whispersystems.libsignal.SessionBuilder;
import org.whispersystems.libsignal.SessionCipher;
import org.whispersystems.libsignal.SignalProtocolAddress;
import org.whispersystems.libsignal.ecc.Curve;
import org.whispersystems.libsignal.ecc.ECKeyPair;
import org.whispersystems.libsignal.ecc.ECPublicKey;
import org.whispersystems.libsignal.protocol.CiphertextMessage;
import org.whispersystems.libsignal.protocol.PreKeySignalMessage;
import org.whispersystems.libsignal.protocol.SignalMessage;
import org.whispersystems.libsignal.state.PreKeyBundle;
import org.whispersystems.libsignal.state.PreKeyRecord;
import org.whispersystems.libsignal.state.SignedPreKeyRecord;
import org.whispersystems.libsignal.util.KeyHelper;

import signal.SignalStoring;

public class Client implements Runnable {
    private BufferedReader in;
    private PrintWriter out;
    private Socket socket;
    private String username;

    private SignalStoring signalStore = new SignalStoring();
    private Map<String, SessionCipher> sessionCiphers = new HashMap<>();
    @Override
    public void run() {
        try {
            socket = new Socket("localhost", 3200);
            in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            out = new PrintWriter(socket.getOutputStream(), true );
            InputHandler handler = new InputHandler(this);

            Thread t = new Thread(handler);
            t.start();

            // String comingMsg;
            handleCommunicationFromServer();
        } catch (IOException e) {
            shutdown();
        }
    }

    private void handleCommunicationFromServer() {
        boolean keepScanning = true;
        while (keepScanning) {
            try {
                String serverMsg = in.readLine();
                if (serverMsg == null) {
                    keepScanning = false;
                    continue;
                }

                if (serverMsg.startsWith("PREKEYREQ")) {
                    sendPreKeyBundle(serverMsg);
                } else if (serverMsg.startsWith("PREKEY")) {
                    processPreKeyBundle(serverMsg);
                } else if (serverMsg.startsWith("MSG")) {
                    receiveEncryptedData(serverMsg);
                } else {
                    showMsg(serverMsg);
                }
            } catch (Exception e) {
                System.out.println("Error handling msg from server");
                keepScanning = false;
            }
        }
    }

    private void showMsg(String serverMsg) {
        System.out.println("[recv] " + serverMsg);
    }

    public void shutdown() {
        try {
            in.close();
            out.close();
            if (!(socket.isClosed())) {
                socket.close();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public boolean isClosed() {
        return socket.isClosed();
    }

    public void send(String message) {
        out.println(message);
    }

    public void sendMessage(String recipient, String ordinaryMessage) {
        if (recipient.equals(username)) {
            showMsg(ordinaryMessage);
            return;
        }
        try {
            SessionCipher cipher = getOrCreateSessionCipher(recipient);

            CiphertextMessage ciphertextMessage = cipher.encrypt(ordinaryMessage.getBytes());
            String encryptedMessage = Base64.getEncoder().encodeToString(ciphertextMessage.serialize());
            String messageType = ciphertextMessage.getType() == CiphertextMessage.PREKEY_TYPE ? "PREKEY" : "WHISPER";
            out.println("MSG:" + recipient + ":" + messageType + ":" + encryptedMessage);
            System.out.println("[send] to " + recipient + ": " + ordinaryMessage);
        } catch (Exception e) {
            System.out.println("Error when sending message");
        }
    }

    private SessionCipher getOrCreateSessionCipher(String remoteUser) {
        SignalProtocolAddress address = new SignalProtocolAddress(remoteUser, 1);
        return sessionCiphers.computeIfAbsent(remoteUser, s -> new SessionCipher(signalStore, address));
    }

    private void receiveEncryptedData(String encryptedReceivedData) {
        String[] receivedDataParts = encryptedReceivedData.split(":", 4);
        if (receivedDataParts.length != 4) {
            System.out.println("Wrong format");
            return;
        }
        String sender = receivedDataParts[1];
        String msgType = receivedDataParts[2];
        String encryptedData = receivedDataParts[3];

        byte[] data = Base64.getDecoder().decode(encryptedData);
        SessionCipher cipher = getOrCreateSessionCipher(sender);

        byte[] plaintext;
        try {
            if (msgType.equals("PREKEY")) {
                PreKeySignalMessage preKeySignalMessage = new PreKeySignalMessage(data);
                plaintext = cipher.decrypt(preKeySignalMessage);
            } else {
                SignalMessage signalMessage = new SignalMessage(data);
                plaintext = cipher.decrypt(signalMessage);
            }
            System.out.println("[recv] from " + sender + ": " + new String(plaintext));
        } catch (Exception e) {
            System.out.println("Error in decrypting message");
            e.printStackTrace();
        }

    }

    private void sendPreKeyBundle(String requestingMsg) {
        String[] parts = requestingMsg.split(":", 2);
        String requestingUser = parts[1];
        try {
            List<PreKeyRecord> preKeys = KeyHelper.generatePreKeys(1, 100);
            PreKeyRecord preKey = preKeys.get(0);
            signalStore.storePreKey(preKey.getId(), preKey);

            ECKeyPair signedPreKeyPair = Curve.generateKeyPair();
            byte[] signedPreKeySignature = Curve.calculateSignature(
                signalStore.getIdentityKeyPair().getPrivateKey(),
                signedPreKeyPair.getPublicKey().serialize()
            );
            SignedPreKeyRecord signedPreKey = new SignedPreKeyRecord(
                1,
                System.currentTimeMillis(),
                signedPreKeyPair,
                signedPreKeySignature
            );

            signalStore.storeSignedPreKey(1, signedPreKey);
            IdentityKey identityKey = signalStore.getIdentityKeyPair().getPublicKey();

            String bundleData = String.format("%d,%d,%s,%s,%s,%s",
                signalStore.getLocalRegistrationId(),
                preKey.getId(),
                Base64.getEncoder().encodeToString(preKey.getKeyPair().getPublicKey().serialize()),
                Base64.getEncoder().encodeToString(signedPreKey.getKeyPair().getPublicKey().serialize()),
                Base64.getEncoder().encodeToString(signedPreKey.getSignature()),
                Base64.getEncoder().encodeToString(identityKey.serialize())
            );
            out.println("PREKEY:" + requestingUser + ":" + bundleData);
        } catch (Exception e) {
            System.out.println("Error sending bundle");
        }
    }

    private void processPreKeyBundle(String preKeyBundleData) {
        try {
            // format: PREKEY:sender:bundleData
            String[] preKeyBundleParts = preKeyBundleData.split(":");
            if (preKeyBundleParts.length != 3) return;

            String sender = preKeyBundleParts[1];
            String[] bundleDataParts = preKeyBundleParts[2].split(",");
            int registrationId = Integer.parseInt(bundleDataParts[0]);
            int preKeyId = Integer.parseInt(bundleDataParts[1]);

            ECPublicKey preKeyPublic = Curve.decodePoint(Base64.getDecoder().decode(bundleDataParts[2]), 0);
            ECPublicKey signedPreKeyPublic = Curve.decodePoint(Base64.getDecoder().decode(bundleDataParts[3]), 0);
            byte[] signedPreKeySignature = Base64.getDecoder().decode(bundleDataParts[4]);
            byte[] identityInfo = Base64.getDecoder().decode(bundleDataParts[5]);
            IdentityKey identityKey = new IdentityKey(identityInfo, 0);

            SignalProtocolAddress senderAddress = new SignalProtocolAddress(sender, 1);
            signalStore.saveIdentity(senderAddress, identityKey);

            PreKeyBundle preKeyBundle = new PreKeyBundle(
                registrationId, 1, preKeyId, preKeyPublic, 1,
                signedPreKeyPublic, signedPreKeySignature, identityKey
            );

            SessionBuilder sessionBuilder = new SessionBuilder(signalStore, senderAddress);
            sessionBuilder.process(preKeyBundle);

            System.out.println("Session established with " + sender);
        } catch (Exception e) {
            System.out.println("Error processing PreKey bundles");
            e.printStackTrace();
        }
    }

    public void establishSession(String toUser) {
        if (signalStore.hasSessionWith(toUser)) {
            System.out.println("Session already established!");
            return;
        } else if (username.equals(toUser)) {
            System.out.println("No session with self");
            return;
        }
        out.println("PREKEYREQ:" + toUser);
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public static void main(String[] args) {
        Client client = new Client();
        client.run();
    }

}
