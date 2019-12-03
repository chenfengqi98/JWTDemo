package com.jwt.security.system.repository;

import com.jwt.security.system.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;


public interface UserRepository extends JpaRepository<User, Integer> {

    @Query(value = " SELECT * FROM `user` WHERE username = ?1 LIMIT 1 ",nativeQuery = true)
    Optional<User> findUserByName(String name);

    @Transactional
    @Modifying
    @Query(value = "DELETE FROM `user` WHERE username = ?1 ", nativeQuery = true)
    void deleteByUserName(String name);

}
