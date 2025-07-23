package server;

import java.time.LocalDateTime;

public class MessageInfo {
    private LocalDateTime timestamp;
    private String sender;
    private String message;

    public MessageInfo(String sender, String message) {
        this.sender = sender;
        this.message = message;
        timestamp = LocalDateTime.now();
    }

    @Override
    public String toString() {
        return timestamp.toString() + " " + sender + ": " + message;
    }
}
