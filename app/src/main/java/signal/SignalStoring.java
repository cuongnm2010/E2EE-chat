package signal;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.whispersystems.libsignal.IdentityKey;
import org.whispersystems.libsignal.IdentityKeyPair;
import org.whispersystems.libsignal.InvalidKeyIdException;
import org.whispersystems.libsignal.SignalProtocolAddress;
import org.whispersystems.libsignal.state.PreKeyRecord;
import org.whispersystems.libsignal.state.SessionRecord;
import org.whispersystems.libsignal.state.SignalProtocolStore;
import org.whispersystems.libsignal.state.SignedPreKeyRecord;
import org.whispersystems.libsignal.util.KeyHelper;

public class SignalStoring implements SignalProtocolStore {
    private IdentityKeyPair identityKeyPair;
    private int registrationId;
    private Map<Integer, PreKeyRecord> preKeys = new HashMap<>();
    private Map<Integer, SignedPreKeyRecord> signedPreKeys = new HashMap<>();
    private Map<SignalProtocolAddress, SessionRecord> sessions = new HashMap<>();
    private Map<SignalProtocolAddress, IdentityKey> trustedKeys = new HashMap<>();

    public SignalStoring() {
        identityKeyPair = KeyHelper.generateIdentityKeyPair();
        registrationId = KeyHelper.generateRegistrationId(false);
    }

    public SignalStoring(IdentityKeyPair identityKeyPair, int registrationId) {
        this.identityKeyPair = identityKeyPair;
        this.registrationId = registrationId;
    }

    @Override
    public SessionRecord loadSession(SignalProtocolAddress address) {
        SessionRecord sessionRecord = sessions.get(address);
        if (sessionRecord != null) {
            return sessionRecord;
        } else {
            return new SessionRecord();
        }
    }

    @Override
    public List<Integer> getSubDeviceSessions(String name) {
        return sessions.keySet().stream()
            .filter(a -> a.getName().equals(name) && a.getDeviceId() != 1)
            .map(SignalProtocolAddress::getDeviceId)
            .collect(Collectors.toList());
    }

    @Override
    public void storeSession(SignalProtocolAddress address, SessionRecord record) {
        sessions.put(address, record);
    }

    @Override
    public boolean containsSession(SignalProtocolAddress address) {
        return sessions.containsKey(address);
    }

    @Override
    public void deleteSession(SignalProtocolAddress address) {
        sessions.remove(address);
    }

    @Override
    public void deleteAllSessions(String name) {
        sessions.entrySet().removeIf(s -> s.getKey().getName().equals(name));
    }

    @Override
    public SignedPreKeyRecord loadSignedPreKey(int signedPreKeyId) throws InvalidKeyIdException {
        SignedPreKeyRecord signedPreKeyRecord = signedPreKeys.get(signedPreKeyId);
        if (signedPreKeyRecord != null) {
            return signedPreKeyRecord;
        } else {
            throw new InvalidKeyIdException("No such signed prekey with id: " + signedPreKeyId);
        }
    }

    @Override
    public List<SignedPreKeyRecord> loadSignedPreKeys() {
        return signedPreKeys.values().stream().collect(Collectors.toList());
    }

    @Override
    public void storeSignedPreKey(int signedPreKeyId, SignedPreKeyRecord record) {
        signedPreKeys.put(signedPreKeyId, record);
    }

    @Override
    public boolean containsSignedPreKey(int signedPreKeyId) {
        return signedPreKeys.containsKey(signedPreKeyId);
    }

    @Override
    public void removeSignedPreKey(int signedPreKeyId) {
        signedPreKeys.remove(signedPreKeyId);
    }

    @Override
    public PreKeyRecord loadPreKey(int preKeyId) throws InvalidKeyIdException {
        PreKeyRecord preKeyRecord = preKeys.get(preKeyId);
        if (preKeyRecord != null) {
            return preKeyRecord;
        }

        throw new InvalidKeyIdException("No such PreKey with id: " + preKeyId);
    }

    @Override
    public void storePreKey(int preKeyId, PreKeyRecord record) {
        preKeys.put(preKeyId, record);
    }

    @Override
    public boolean containsPreKey(int preKeyId) {
        return preKeys.containsKey(preKeyId);
    }

    @Override
    public void removePreKey(int preKeyId) {
        preKeys.remove(preKeyId);
    }

    @Override
    public IdentityKeyPair getIdentityKeyPair() {
        return identityKeyPair;
    }

    @Override
    public int getLocalRegistrationId() {
        return registrationId;
    }

    @Override
    public boolean saveIdentity(SignalProtocolAddress address, IdentityKey identityKey) {
        IdentityKey check = trustedKeys.get(address);
        if (check != null) {
            return check.equals(identityKey);
        } else {
            trustedKeys.put(address, check);
            return true;
        }
    }

    @Override
    public boolean isTrustedIdentity(SignalProtocolAddress address, IdentityKey identityKey, Direction direction) {
        IdentityKey identityKey2 = trustedKeys.get(address);
        return identityKey2 == null || identityKey2.equals(identityKey);

    }

    @Override
    public IdentityKey getIdentity(SignalProtocolAddress address) {
        return trustedKeys.get(address);
    }

    public boolean hasSessionWith(String toUser) {
        SignalProtocolAddress address = new SignalProtocolAddress(toUser, 1);
        return containsSession(address);
    }

}
