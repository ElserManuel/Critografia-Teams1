package chat.CFB.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class CrytoPregunta {
    private String text;
    private String encryptedText;
    private String key;
    private String iv;
}
