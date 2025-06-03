package chat.CFB.Controller;

import chat.CFB.dto.CrytoPregunta;
import chat.CFB.dto.CrytoResponder;
import chat.CFB.service.CFBCrytoService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@CrossOrigin(origins = "*")
@RequestMapping("/api/cryto")
public class CryptoController {

    @Autowired
    private CFBCrytoService cfbCryptoService;

    @PostMapping("/encrypt")
    public ResponseEntity<CrytoResponder> encrypt(@RequestBody CrytoPregunta request) {
        try {
            CrytoResponder response = cfbCryptoService.encrypt(request.getText());
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(new CrytoResponder(
                    "Error: " + e.getMessage(), "", "", "", "", ""
            ));
        }
    }

    @PostMapping("/decrypt")
    public ResponseEntity<CrytoResponder> decrypt(@RequestBody CrytoPregunta request) {
        try {
            String decrypted = cfbCryptoService.decrypt(
                    request.getEncryptedText(),
                    request.getKey(),
                    request.getIv()
            );
            CrytoResponder response = new CrytoResponder();
            response.setDecryptedText(decrypted);
            response.setMensaje("Texto descifrado exitosamente");
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(new CrytoResponder(
                    "Error al descifrar: " + e.getMessage(), "", "", "", "", ""
            ));
        }
    }

    @GetMapping("/demo")
    public ResponseEntity<CrytoResponder> demo() {
        try {
            String demoText = "Hola mundo, esto es una prueba de CFB";
            CrytoResponder response = cfbCryptoService.encrypt(demoText);

            // Agregar descifrado al demo
            String decrypted = cfbCryptoService.decrypt(
                    response.getEncryptedText(),
                    response.getKey(),
                    response.getIv()
            );
            response.setDecryptedText(decrypted);
            response.setMensaje("Demo completa: cifrado y descifrado exitoso");

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(new CrytoResponder(
                    "Error en demo: " + e.getMessage(), "", "", "", "", ""
            ));
        }
    }

}
