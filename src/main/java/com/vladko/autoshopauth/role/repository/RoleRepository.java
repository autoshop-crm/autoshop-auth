package com.vladko.autoshopauth.role.repository;

import com.vladko.autoshopauth.role.entity.Role;
import com.vladko.autoshopauth.role.entity.RoleName;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RoleRepository extends JpaRepository<Role, Long> {

    Optional<Role> findByName(RoleName name);
}
