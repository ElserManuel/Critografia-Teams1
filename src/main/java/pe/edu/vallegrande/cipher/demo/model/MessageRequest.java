package pe.edu.vallegrande.cipher.demo.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class MessageRequest {
    private String message;
    private String iv; // Opcional para demostrar reutilización de IV
    private boolean simulateError; // Para demostrar propagación de errores

    public MessageRequest(String message) {
        this.message = message;
    }
}