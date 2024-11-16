package flcordis.spring_security_jwt.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import flcordis.spring_security_jwt.model.User;
import flcordis.spring_security_jwt.repository.UserRepository;

@Service
public class UserService {
    @Autowired
    private UserRepository repository;
    @Autowired
    private PasswordEncoder encoder;

    public void createUser(User user) {
        String pass = user.getPassword();
        // Criptografando primeiro
        user.setPassword((encoder.encode(pass)));
        repository.save(user);
    }
}
