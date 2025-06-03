package chat.CFB.service;

import chat.CFB.dto.CrytoResponder;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

@Service
public class CFBCrytoService {

    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/CFB/NoPadding";
    private static final int IV_LENGTH = 16; // 128 bits para AES

    public CrytoResponder encrypt(String plainText) throws Exception {
        // Generar clave secreta
        KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM);
        keyGenerator.init(256);
        SecretKey secretKey = keyGenerator.generateKey();

        // Generar IV aleatorio
        byte[] iv = new byte[IV_LENGTH];
        new SecureRandom().nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        // Configurar cifrador
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);

        // Cifrar el texto
        byte[] encryptedBytes = cipher.doFinal(plainText.getBytes("UTF-8"));

        // Convertir a Base64
        String encryptedText = Base64.getEncoder().encodeToString(encryptedBytes);
        String keyBase64 = Base64.getEncoder().encodeToString(secretKey.getEncoded());
        String ivBase64 = Base64.getEncoder().encodeToString(iv);

        // Construir respuesta
        CrytoResponder responder = new CrytoResponder();
        responder.setOriginalText(plainText);
        responder.setEncryptedText(encryptedText);
        responder.setKey(keyBase64);
        responder.setIv(ivBase64);
        responder.setMensaje("Texto cifrado exitosamente con CFB");

        return responder;
    }

    public String decrypt(String encryptedText, String keyBase64, String ivBase64) throws Exception {
        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedText);
        byte[] keyBytes = Base64.getDecoder().decode(keyBase64);
        byte[] iv = Base64.getDecoder().decode(ivBase64);

        SecretKey secretKey = new SecretKeySpec(keyBytes, ALGORITHM);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);

        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
        return new String(decryptedBytes, "UTF-8");
    }

    // Método para mostrar el proceso paso a paso
    public String explainCFBProcess(String text) {
        StringBuilder explanation = new StringBuilder();
        explanation.append("=== PROCESO CFB (Cipher Feedback) ===\n");
        explanation.append("1. Texto original: ").append(text).append("\n");
        explanation.append("2. Se genera una clave AES de 256 bits\n");
        explanation.append("3. Se genera un IV (Vector de Inicialización) aleatorio de 128 bits\n");
        explanation.append("4. CFB usa el cifrado de bloque (AES) como generador de flujo\n");
        explanation.append("5. El IV se cifra con AES para generar el primer bloque de clave\n");
        explanation.append("6. Se hace XOR entre el texto plano y la clave generada\n");
        explanation.append("7. El resultado cifrado se usa como entrada para el siguiente bloque\n");
        explanation.append("8. El proceso se repite hasta cifrar todo el texto\n");

        return explanation.toString();
    }
}
