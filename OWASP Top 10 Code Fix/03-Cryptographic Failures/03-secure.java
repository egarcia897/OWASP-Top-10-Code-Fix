"""03 Cryptographic Failures
- Secure Code Java"""

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

public class PasswordService {
    private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(12);
    
    public String hashPassword(String password) {
        return encoder.encode(password);
    }

    public boolean  verifyPassword(String rawPassword, String hashPassword) {
        return encoder.matches(rawPassword, hashedPassword);
    }
}