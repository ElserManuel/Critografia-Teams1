package pe.edu.vallegrande.cipher.demo.service;

import org.springframework.stereotype.Service;
import pe.edu.vallegrande.cipher.demo.model.MessageRequest;
import pe.edu.vallegrande.cipher.demo.model.MessageResponse;
import pe.edu.vallegrande.cipher.demo.model.VulnerabilityDemo;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.*;

@Service
public class CryptoService {

    private static final String ALGORITHM = "AES/CFB/PKCS5Padding";
    private static final String KEY_ALGORITHM = "AES";
    private static final byte[] DEFAULT_KEY = "1234567890123456".getBytes();
    private static final byte[] REUSED_IV = "1234567890123456".getBytes();

    // 1. Demostrar reutilización de IV
    public VulnerabilityDemo demonstrateIVReuse() {
        VulnerabilityDemo demo = new VulnerabilityDemo(
                "Reutilización de Vector de Inicialización (IV)",
                "Cuando se reutiliza el mismo IV para cifrar múltiples mensajes, los atacantes pueden detectar patrones comunes en los mensajes cifrados."
        );

        List<MessageResponse> examples = new ArrayList<>();

        try {
            String[] messages = {
                    "Hola Juan, ¿cómo estás?",
                    "Hola Juan, nos vemos mañana",
                    "Hola María, ¿cómo estás?"
            };

            for (String message : messages) {
                Cipher cipher = Cipher.getInstance(ALGORITHM);
                SecretKeySpec secretKey = new SecretKeySpec(DEFAULT_KEY, KEY_ALGORITHM);
                IvParameterSpec ivParams = new IvParameterSpec(REUSED_IV);

                cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParams);
                byte[] encrypted = cipher.doFinal(message.getBytes());

                MessageResponse response = new MessageResponse(message, encrypted);
                response.setVulnerability("IV Reutilizado");
                response.setExplanation("Mismo IV usado para todos los mensajes - los que empiezan igual tendrán bytes cifrados idénticos");

                examples.add(response);
            }

        } catch (Exception e) {
            e.printStackTrace();
        }

        demo.setExamples(examples);
        demo.setConclusion("Los mensajes que empiezan con 'Hola Juan' tienen los mismos primeros bytes cifrados, revelando el patrón común.");

        return demo;
    }

    // 2. Demostrar propagación de errores
    public VulnerabilityDemo demonstrateErrorPropagation() {
        VulnerabilityDemo demo = new VulnerabilityDemo(
                "Propagación de Errores",
                "En CFB, un error en un byte cifrado corrompe todo el mensaje desde ese punto en adelante."
        );

        List<MessageResponse> examples = new ArrayList<>();

        try {
            String originalMessage = "Reunión importante mañana a las 10:00 AM en sala de conferencias principal";
            byte[] iv = "abcdefghijklmnop".getBytes();

            // Cifrar mensaje original
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            SecretKeySpec secretKey = new SecretKeySpec(DEFAULT_KEY, KEY_ALGORITHM);
            IvParameterSpec ivParams = new IvParameterSpec(iv);

            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParams);
            byte[] encrypted = cipher.doFinal(originalMessage.getBytes());

            // Mensaje sin error
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParams);
            byte[] decrypted = cipher.doFinal(encrypted);
            MessageResponse correctResponse = new MessageResponse(originalMessage, encrypted);
            correctResponse.setDecryptedMessage(new String(decrypted));
            correctResponse.setVulnerability("Sin Error");
            correctResponse.setExplanation("Mensaje descifrado correctamente");
            examples.add(correctResponse);

            // Simular error de transmisión
            byte[] corruptedMessage = encrypted.clone();
            corruptedMessage[10] ^= 0xFF; // Corromper un byte

            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParams);
            byte[] corruptedDecrypted = cipher.doFinal(corruptedMessage);
            MessageResponse errorResponse = new MessageResponse(originalMessage, corruptedMessage);
            errorResponse.setDecryptedMessage(new String(corruptedDecrypted));
            errorResponse.setVulnerability("Error en Byte 10");
            errorResponse.setExplanation("Un byte corrupto causa que todo el mensaje desde ese punto se vuelva ilegible");
            examples.add(errorResponse);

        } catch (Exception e) {
            e.printStackTrace();
        }

        demo.setExamples(examples);
        demo.setConclusion("Un solo byte corrupto hace que todo el resto del mensaje sea ilegible - problemático para mensajes largos.");

        return demo;
    }

    // 3. Demostrar ataques de repetición
    public VulnerabilityDemo demonstrateReplayAttack() {
        VulnerabilityDemo demo = new VulnerabilityDemo(
                "Ataques de Repetición (Replay Attack)",
                "Un atacante puede interceptar y reenviar mensajes cifrados para ejecutar acciones duplicadas."
        );

        List<MessageResponse> examples = new ArrayList<>();

        try {
            String[] sensitiveMessages = {
                    "TRANSFERIR $5000 A CUENTA 123456789",
                    "AUTORIZAR ACCESO SALA SEGURA",
                    "CONFIRMAR COMPRA $2500"
            };

            byte[] iv = "replayattacktest".getBytes();

            for (String message : sensitiveMessages) {
                Cipher cipher = Cipher.getInstance(ALGORITHM);
                SecretKeySpec secretKey = new SecretKeySpec(DEFAULT_KEY, KEY_ALGORITHM);
                IvParameterSpec ivParams = new IvParameterSpec(iv);

                cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParams);
                byte[] encrypted = cipher.doFinal(message.getBytes());

                MessageResponse response = new MessageResponse(message, encrypted);
                response.setVulnerability("Vulnerable a Replay");
                response.setExplanation("Este mensaje cifrado puede ser interceptado y reenviado por un atacante");

                examples.add(response);
            }

        } catch (Exception e) {
            e.printStackTrace();
        }

        demo.setExamples(examples);
        demo.setConclusion("Sin timestamps o tokens únicos, estos mensajes pueden ser reenviados para ejecutar acciones duplicadas.");

        return demo;
    }

    // 4. Demostrar análisis de longitud
    public VulnerabilityDemo demonstrateLengthAnalysis() {
        VulnerabilityDemo demo = new VulnerabilityDemo(
                "Análisis de Longitud de Mensajes",
                "La longitud del mensaje cifrado revela información sobre el tipo de contenido, permitiendo clasificar mensajes sin descifrarlos."
        );

        List<MessageResponse> examples = new ArrayList<>();

        try {
            Map<String, String[]> messageTypes = new HashMap<>();
            messageTypes.put("Respuestas Cortas", new String[]{"Sí", "No", "OK"});
            messageTypes.put("Confirmaciones", new String[]{"Reunión confirmada", "Pedido recibido"});
            messageTypes.put("Mensajes Largos", new String[]{"La reunión de mañana queda confirmada para las 15:00 horas en la sala de juntas del piso 5"});

            for (String category : messageTypes.keySet()) {
                for (String message : messageTypes.get(category)) {
                    byte[] iv = new byte[16];
                    new Random().nextBytes(iv);

                    Cipher cipher = Cipher.getInstance(ALGORITHM);
                    SecretKeySpec secretKey = new SecretKeySpec(DEFAULT_KEY, KEY_ALGORITHM);
                    IvParameterSpec ivParams = new IvParameterSpec(iv);

                    cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParams);
                    byte[] encrypted = cipher.doFinal(message.getBytes());

                    MessageResponse response = new MessageResponse(message, encrypted);
                    response.setVulnerability("Análisis de Longitud");

                    String classification;
                    if (encrypted.length < 20) {
                        classification = "Clasificado como: Respuesta Corta";
                    } else if (encrypted.length < 35) {
                        classification = "Clasificado como: Confirmación Simple";
                    } else {
                        classification = "Clasificado como: Mensaje Detallado";
                    }

                    response.setExplanation(classification + " (Longitud: " + encrypted.length + " bytes)");
                    examples.add(response);
                }
            }

        } catch (Exception e) {
            e.printStackTrace();
        }

        demo.setExamples(examples);
        demo.setConclusion("Los atacantes pueden clasificar tipos de mensaje basándose únicamente en la longitud del texto cifrado.");

        return demo;
    }

    // Método para cifrar mensaje personalizado
    public MessageResponse encryptMessage(MessageRequest request) {
        try {
            byte[] iv;
            if (request.getIv() != null && !request.getIv().isEmpty()) {
                iv = request.getIv().getBytes();
                if (iv.length != 16) {
                    iv = Arrays.copyOf(iv, 16); // Ajustar a 16 bytes
                }
            } else {
                iv = new byte[16];
                new Random().nextBytes(iv);
            }

            Cipher cipher = Cipher.getInstance(ALGORITHM);
            SecretKeySpec secretKey = new SecretKeySpec(DEFAULT_KEY, KEY_ALGORITHM);
            IvParameterSpec ivParams = new IvParameterSpec(iv);

            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParams);
            byte[] encrypted = cipher.doFinal(request.getMessage().getBytes());

            MessageResponse response = new MessageResponse(request.getMessage(), encrypted);

            // Simular error si se solicita
            if (request.isSimulateError()) {
                byte[] corruptedMessage = encrypted.clone();
                corruptedMessage[encrypted.length / 2] ^= 0xFF;

                try {
                    cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParams);
                    byte[] decrypted = cipher.doFinal(corruptedMessage);
                    response.setDecryptedMessage(new String(decrypted));
                    response.setVulnerability("Error Simulado - Descifrado Exitoso");
                    response.setExplanation("Sorprendentemente, el mensaje corrupto se descifró sin error aparente");
                } catch (Exception decryptionError) {
                    // Manejar el error de descifrado
                    response.setDecryptedMessage("ERROR: No se pudo descifrar - " + decryptionError.getMessage());
                    response.setVulnerability("Error de Padding/Descifrado");
                    response.setExplanation("El byte corrupto en posición " + (encrypted.length / 2) +
                            " causó un error de padding al intentar descifrar: " + decryptionError.getClass().getSimpleName());
                }
            } else {
                cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParams);
                byte[] decrypted = cipher.doFinal(encrypted);
                response.setDecryptedMessage(new String(decrypted));
                response.setVulnerability("Ninguna");
                response.setExplanation("Mensaje cifrado y descifrado correctamente");
            }

            return response;

        } catch (Exception e) {
            e.printStackTrace();

            // Retornar una respuesta de error en lugar de null
            MessageResponse errorResponse = new MessageResponse(request.getMessage(), null);
            errorResponse.setDecryptedMessage("ERROR GENERAL: " + e.getMessage());
            errorResponse.setVulnerability("Error de Cifrado");
            errorResponse.setExplanation("Error durante el proceso de cifrado: " + e.getClass().getSimpleName());
            return errorResponse;
        }
    }
    
}
