package pe.edu.vallegrande.cipher.demo.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Arrays;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class MessageResponse {
    private String originalMessage;
    private String encryptedMessage;
    private String decryptedMessage;
    private int messageLength;
    private String firstBytes;
    private String vulnerability;
    private String explanation;

    public MessageResponse(String originalMessage, byte[] encrypted) {
        this.originalMessage = originalMessage;
        this.encryptedMessage = Arrays.toString(encrypted);
        this.messageLength = encrypted.length;
        this.firstBytes = Arrays.toString(Arrays.copyOf(encrypted, Math.min(8, encrypted.length)));
    }
}