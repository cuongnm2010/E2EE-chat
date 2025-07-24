package client;

import java.util.Scanner;

public class InputHandler implements Runnable {
    private Client client;

    public InputHandler(Client client) {
        this.client = client;
    }

    @Override
    public void run() {
        try {
            Scanner in = new Scanner(System.in);
            while (!client.isClosed()) {
                String message = in.nextLine();
                if (message.startsWith("/quit")) {
                    client.send(message);
                    in.close();
                    client.shutdown();
                } else if (message.startsWith("/msg")) {
                    String[] messageParts = message.split(" ", 3);
                    client.sendMessage(messageParts[1], messageParts[2]);
                } else if (message.startsWith("/session")) {
                    String[] messageParts = message.split(" ", 2);
                    client.establishSession(messageParts[1]);
                } else if (message.startsWith("/login") || message.startsWith("/register") || message.startsWith("/listUsers")) {
                    String[] parts = message.split(" ", 3);
                    if (parts.length == 3) {
                        client.setUsername(parts[1]);
                    }
                    client.send(message);
                } else {
                    System.out.println("Unknown command");
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
