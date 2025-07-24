package server;

import java.io.IOException;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.stream.Collectors;

public class Server implements Runnable {
    private List<ConnectionHandler> connections = new ArrayList<>();
    private ServerSocket server;
    private ExecutorService pool;
    private Map<String, String> users = new HashMap<>();
    private Map<String, String> nicknames = new HashMap<>();

    @Override
    public void run() {
        try {
            server = new ServerSocket(3200);
            System.out.println("Server is running at " + getServerAddress());
            pool = Executors.newCachedThreadPool();

            while (!server.isClosed()) {
                Socket client = server.accept();
                ConnectionHandler handler = new ConnectionHandler(client, this);
                pool.execute(handler);
            }

            shutdown();
        } catch (IOException e) {
            shutdown();
        }
    }

    public void addConnection(ConnectionHandler connectionHandler) {
        connections.add(connectionHandler);
    }

    public void shutdown() {
        for (ConnectionHandler cH : connections) {
            cH.shutdown();
        }

        try {
            if (!server.isClosed()) {
                server.close();
            }
        } catch (Exception e) {
            System.err.println("Error during server shutdown");
        }
    }

    public String getServerAddress() {
        return "Server is running at port " + server.getLocalPort();
    }

    protected boolean lookupUser(String username, String password) {
        String passHash = getSHA256HexString(password);
        if (!users.containsKey(username) || !users.get(username).equals(passHash)) {
            return false;
        }

        return true;
    }

    public void registerUser(String user, String password) throws InvalidUsernameException, InvalidPasswordException {
        if (users.containsKey(user)) {
            throw new InvalidUsernameException("Username exists");
        } else if (!isPasswordValid(password)) {
            throw new InvalidPasswordException("Password needs to be at least 12 characters length, contain at least "
                        + "1 number, 1 uppercase and 1 lowercase letter");
        }
        users.put(user, getSHA256HexString(password));
    }

    private boolean isPasswordValid(String password) {
        if (password.length() < 12) return false;

        // contains only uppercase or lowercase
        if (!password.matches(".*[A-Z].*") || !password.matches(".*[a-z].*")) return false;

        // contains number
        if (!password.matches(".*[0-9].*")) return false;

        return true;
    }

    private String getSHA256HexString(String str) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            BigInteger number = new BigInteger(1, digest.digest(str.getBytes(StandardCharsets.UTF_8)));
            StringBuilder sb = new StringBuilder(number.toString(16));
            while (sb.length() < 64) {
                sb.insert(0, '0');
            }

            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static void main(String[] args) {
        Server server = new Server();
        server.run();
    }

    public void register(String username, String password) {
        if (users.keySet().contains(username)) {
            throw new IllegalArgumentException("The username existed!");
        }
        users.put(username, getSHA256HexString(password));
    }

    public void addNickName(String username, String nickname) {
        nicknames.put(username, nickname);
    }

    public String findNickname(String username) {
        return nicknames.get(username);
    }

    public void login(String username, String password) throws Exception {
        if (!lookupUser(username, password)) {
            throw new Exception("Username or password is invalid");
        }
    }

    public void sendPreKeyReq(String fromUser, String targetUser) {
        ConnectionHandler target = findConnectionHandler(targetUser);
        ConnectionHandler source = findConnectionHandler(fromUser);

        if (target == null) {
            source.sendMessage("Target user is not online. Use command /listUsers to check");
            return;
        }

        String msg = "PREKEYREQ:" + fromUser;
        target.sendMessage(msg);
    }

    public void sendPreKeyBundle(String fromUser, String targetUser, String preKeyBundle) {
        ConnectionHandler cH = findConnectionHandler(targetUser);
        if (cH == null) return;

        String msg = "PREKEY:" + fromUser + ":" + preKeyBundle;
        cH.sendMessage(msg);
    }

    public ConnectionHandler findConnectionHandler(String username) {
        for (ConnectionHandler cH : connections) {
            if (cH.getUsername().equals(username)) {
                return cH;
            }
        }

        return null;
    }

    public List<String> getUsers() {
        return connections.stream().map(ConnectionHandler::getUsername).collect(Collectors.toList());
    }

    public void sendMessage(String fromUser, String targetUser, String encryptedMsg) {
        ConnectionHandler cH = findConnectionHandler(targetUser);
        if (cH == null) return;

        String msg = "MSG:" + fromUser + ":" + encryptedMsg;
        cH.sendMessage(msg);
    }

    public void removeConnection(ConnectionHandler connectionHandler) {
        connections.remove(connectionHandler);
    }
}
