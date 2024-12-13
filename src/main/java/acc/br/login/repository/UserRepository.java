package acc.br.login.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import acc.br.login.model.User;

public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);
}
