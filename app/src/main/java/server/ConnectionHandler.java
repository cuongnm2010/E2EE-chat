package server;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.List;

public class ConnectionHandler implements Runnable {
    private Server server;
    private Socket client;
    private BufferedReader in;
    private PrintWriter out;
    private String username;

    public ConnectionHandler(Socket client, Server server) {
        this.client = client;
        this.server = server;
        server.addConnection(this);
    }

    @Override
    public void run() {
        try {
            out = new PrintWriter(client.getOutputStream(), true);
            in = new BufferedReader(new InputStreamReader(client.getInputStream()));
            authentication();
            String message;
            boolean keepScanning = true;
            while ((message = in.readLine()) != null && keepScanning) {
                System.out.println("[recv] from " + username + ": " + message);

                if (message.startsWith("/quit")) {
                    System.out.println(username + " quit the chat!");
                    shutdown();
                    keepScanning = false;
                } else if (message.startsWith("/listUsers")) {
                    System.out.println("Listing users");
                    List<String> usersInServer = server.getUsers();
                    StringBuilder sb = new StringBuilder();
                    sb.append("USERS:");
                    usersInServer.forEach(uIS -> {
                        sb.append(uIS + ",");
                    });
                    sb.setLength(sb.length() - 1);
                    out.println(sb.toString());
                } else if (message.startsWith("PREKEYREQ")) {
                    String[] msgParts = message.split(":");
                    System.out.println("Establishing session between " + username + " and " + msgParts[1]);

                    server.sendPreKeyReq(username, msgParts[1]);
                } else if (message.startsWith("PREKEY")) {
                    String[] msgParts = message.split(":", 3);
                    server.sendPreKeyBundle(username, msgParts[1], msgParts[2]);
                } else if (message.startsWith("MSG")) {
                    // format
                    String[] msgParts = message.split(":", 3);

                    String recipient = msgParts[1];
                    String encryptedMsg = msgParts[2];
                    server.sendMessage(username, recipient, encryptedMsg);
                } else {
                    out.println("unknown command");
                }
            }
        } catch (Exception e) {
            shutdown();
            e.printStackTrace();
        }
    }

    private void authentication() {
        boolean authenticated = false;
        while (!authenticated) {
            try {
                String consoleLine = in.readLine().strip();
                String[] authenParts = consoleLine.split(" ");

                if (authenParts.length != 3) {
                    out.println("Usage: /login <username> <password> or /register <username> <password>");
                    continue;
                }

                String username = authenParts[1];
                String password = authenParts[2];
                if (authenParts[0].equals("/login")) {
                    server.login(username, password);
                    out.println("Login successful");
                    this.username = username;
                    authenticated = true;
                } else if (authenParts[0].equals("/register")) {
                    server.registerUser(username, password);
                    this.username = username;
                    authenticated = true;
                    out.println("Register successful");
                } else {
                    out.println("Unregconized command!");
                }
            } catch (Exception e) {
                out.println(e.getMessage());
            }

        }
    }

    public void sendMessage(String message) {
        System.out.println("[send] to " + username + ": " + message);
        out.println(message);
    }

    public void shutdown() {
        try {
            if (!client.isClosed()) {
                client.close();
            }
            in.close();
            out.close();
        } catch (IOException e) {
            // dont care
        }
        server.removeConnection(this);
    }

    public String getUsername() {
        return username;
    }
}
