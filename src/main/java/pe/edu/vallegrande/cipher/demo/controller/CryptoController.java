package pe.edu.vallegrande.cipher.demo.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import pe.edu.vallegrande.cipher.demo.model.MessageRequest;
import pe.edu.vallegrande.cipher.demo.model.MessageResponse;
import pe.edu.vallegrande.cipher.demo.model.VulnerabilityDemo;
import pe.edu.vallegrande.cipher.demo.service.CryptoService;

@RestController
@RequestMapping("/api/crypto")
@CrossOrigin(origins = "*")
public class CryptoController {

    @Autowired
    private CryptoService cryptoService;

    @GetMapping("/")
    public String welcome() {
        return "CFB Vulnerabilities Demo API - Endpoints disponibles: /iv-reuse, /error-propagation, /replay-attack, /length-analysis, /encrypt";
    }

    @GetMapping("/iv-reuse")
    public VulnerabilityDemo demonstrateIVReuse() {
        return cryptoService.demonstrateIVReuse();
    }

    @GetMapping("/error-propagation")
    public VulnerabilityDemo demonstrateErrorPropagation() {
        return cryptoService.demonstrateErrorPropagation();
    }

    @GetMapping("/replay-attack")
    public VulnerabilityDemo demonstrateReplayAttack() {
        return cryptoService.demonstrateReplayAttack();
    }

    @GetMapping("/length-analysis")
    public VulnerabilityDemo demonstrateLengthAnalysis() {
        return cryptoService.demonstrateLengthAnalysis();
    }

    @PostMapping("/encrypt")
    public MessageResponse encryptMessage(@RequestBody MessageRequest request) {
        return cryptoService.encryptMessage(request);
    }
}