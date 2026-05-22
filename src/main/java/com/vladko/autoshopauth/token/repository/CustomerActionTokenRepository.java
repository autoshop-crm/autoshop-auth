package com.vladko.autoshopauth.token.repository;

import com.vladko.autoshopauth.token.entity.CustomerActionToken;
import com.vladko.autoshopauth.token.entity.CustomerActionTokenType;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface CustomerActionTokenRepository extends JpaRepository<CustomerActionToken, Long> {

    Optional<CustomerActionToken> findByTokenAndType(String token, CustomerActionTokenType type);

    List<CustomerActionToken> findAllByUserIdAndTypeAndUsedFalse(Long userId, CustomerActionTokenType type);

    Optional<CustomerActionToken> findTopByUserIdAndTypeOrderByCreatedAtDesc(Long userId, CustomerActionTokenType type);
}
