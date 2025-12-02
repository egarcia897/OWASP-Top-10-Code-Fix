///#10 Identification and Authentication Failures
/// Secure code java

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

private BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(12);

public boolean authentication(String username, String inputPassword) {
    User user = userRepository.findByUsername(username);

    if (user == null) {
        return false; 
    }
    return encoder.matches(inputPassword, user.getPasswordHash());
}