package chat.CFB.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Setter
@Getter
@AllArgsConstructor
@NoArgsConstructor
public class CrytoResponder {
    private String mensaje;
    private String originalText;
    private String encryptedText;
    private String decryptedText;
    private String key;
    private String iv;
}
